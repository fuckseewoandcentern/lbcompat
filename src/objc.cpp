#include "host.hpp"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <list>
#include <mutex>
#include <string>
#include <sys/mman.h>
#include <unistd.h>
#include <unordered_map>
#include <vector>

#include <X11/Xlib.h>
#include <X11/Xutil.h>

namespace lb {
namespace {

struct RO {
    uint32_t flags = 0;
    uint32_t inst_start = 0;
    uint32_t inst_size = 0;
    uint32_t pad = 0;
    uint64_t ivar = 0;
    const char* name = nullptr;
    uint64_t methods = 0;
};

struct ClassObj {
    uint64_t isa = 0;
    uint64_t super = 0;
    uint64_t cache = 0;
    uint64_t vtable = 0;
    uint64_t bits = 0;
};

struct Info {
    std::string name;
    bool meta = false;
    uint32_t size = 64;
    ClassObj* obj = nullptr;
    Info* meta_info = nullptr;
    Info* super_info = nullptr;
    RO ro {};
    std::unordered_map<std::string, ShimFn> methods;
};

std::unordered_map<std::string, Info*> g_by_name;
std::unordered_map<uint64_t, Info*> g_by_addr;
std::unordered_map<uint64_t, Payload> g_payload;
std::unordered_map<std::string, uint64_t> g_guest_imp;
std::list<std::string> g_sel_pool;
std::unordered_map<std::string, const char*> g_sels;
std::vector<std::string> g_misses;
std::mutex g_miss_mu;

std::string imp_key(uint64_t cls, const char* sel) {
    return std::to_string(cls) + "\n" + (sel ? sel : "");
}

Info* info_at(uint64_t addr) {
    auto it = g_by_addr.find(addr);
    return it == g_by_addr.end() ? nullptr : it->second;
}

bool page_mapped(uint64_t addr) {
    addr = tbi(addr);
    if (addr < 0x10000) return false;
    unsigned char vec = 0;
    void* page = reinterpret_cast<void*>(addr & ~0xfffull);
    return ::mincore(page, 4096, reinterpret_cast<unsigned char*>(&vec)) == 0;
}

const char* text_of(uint64_t obj) {
    auto it = g_payload.find(obj);
    if (it != g_payload.end() && !it->second.str.empty()) return it->second.str.c_str();
    if (!obj || !page_mapped(obj) || !page_mapped(obj + 16)) return "";
    uint64_t p = read_u64(obj + 16);
    p = tbi(p);
    if (p > 0x10000 && page_mapped(p)) {
        const char* s = reinterpret_cast<const char*>(p);
        if (static_cast<unsigned char>(s[0]) >= 32 && static_cast<unsigned char>(s[0]) < 127) {
            size_t n = 0;
            while (n < 4096) {
                if ((n & 0xfff) == 0 && !page_mapped(p + n)) break;
                if (!s[n]) break;
                ++n;
            }
            if (n && n < 4096 && s[n] == 0) {
                payload(obj).str.assign(s, n);
                return payload(obj).str.c_str();
            }
        }
    }
    return "";
}

void remember_miss(const char* sel) {
    if (!sel) return;
    std::lock_guard<std::mutex> lock(g_miss_mu);
    if (g_misses.size() >= 40) return;
    for (const auto& s : g_misses)
        if (s == sel) return;
    g_misses.emplace_back(sel);
}

bool is_setter(const std::string& s, std::string& key) {
    if (s.size() < 5 || s.rfind("set", 0) != 0 || s.back() != ':') return false;
    if (s.find(':') != s.size() - 1) return false;
    key = s.substr(3, s.size() - 4);
    if (!key.empty() && key[0] >= 'A' && key[0] <= 'Z') key[0] = static_cast<char>(key[0] - 'A' + 'a');
    return !key.empty();
}

void write_rect(Guest& g, double x, double y, double w, double h) {
    // macOS arm64 returns a CGRect/NSRect as a four-double aggregate in v0-v3.
    double r[4] = {x, y, w, h};
    for (int i = 0; i < 4; ++i) {
        std::memset(g.v[i], 0, 16);
        std::memcpy(g.v[i], &r[i], 8);
    }
}

void read_arg_rect(const Guest& g, double r[4]) {
    // A CGRect/NSRect argument arrives in v0-v3, the same way it is returned.
    for (int i = 0; i < 4; ++i) std::memcpy(&r[i], g.v[i], 8);
    if (!(r[2] > 1 && r[2] < 100000 && r[3] > 1 && r[3] < 100000)) {
        r[0] = r[1] = 0;
        r[2] = 1280;
        r[3] = 720;
    }
}

Display* g_dpy = nullptr;
Window g_win = 0;
GC g_gc = 0;
int g_win_w = 1280;
int g_win_h = 720;

void ensure_window(int w, int h) {
    if (!std::getenv("DISPLAY")) return;
    if (!g_dpy) {
        XInitThreads();
        g_dpy = XOpenDisplay(nullptr);
        if (!g_dpy) return;
    }
    if (w < 16) w = 1280;
    if (h < 16) h = 720;
    if (g_win && w == g_win_w && h == g_win_h) return;
    int screen = DefaultScreen(g_dpy);
    if (g_win) XDestroyWindow(g_dpy, g_win);
    g_win = XCreateSimpleWindow(g_dpy, RootWindow(g_dpy, screen), 0, 0, w, h, 0, 0, 0x101014);
    XStoreName(g_dpy, g_win, "LyricsBlossom");
    XSelectInput(g_dpy, g_win, ExposureMask | KeyPressMask | StructureNotifyMask);
    XMapWindow(g_dpy, g_win);
    g_gc = XCreateGC(g_dpy, g_win, 0, nullptr);
    g_win_w = w;
    g_win_h = h;
    XFlush(g_dpy);
}

void m_alloc(Guest& g) {
    uint64_t cls = g.x[0];
    uint32_t sz = 64;
    if (g_image && g_image->contains(cls)) {
        uint64_t bits = read_u64(cls + 32);
        uint64_t ro = bits & 0x00007ffffffffff8ull;
        if (ro) std::memcpy(&sz, reinterpret_cast<void*>(ro + 8), 4);
    } else if (Info* info = info_at(cls)) {
        sz = info->size;
    }
    if (sz < 16) sz = 64;
    void* p = std::calloc(1, sz);
    if (p) write_u64(reinterpret_cast<uint64_t>(p), cls);
    g.x[0] = reinterpret_cast<uint64_t>(p);
}
void m_new(Guest& g) { m_alloc(g); }
void m_init(Guest& g) {}
void m_retain(Guest& g) {}
void m_release(Guest& g) { (void)g; }
void m_self(Guest& g) {}
void m_class(Guest& g) { g.x[0] = g.x[0] ? read_u64(g.x[0]) : 0; }
void m_hash(Guest& g) {}
void m_yes(Guest& g) { g.x[0] = 1; }
void m_no(Guest& g) { g.x[0] = 0; }
void m_copy(Guest& g) {}

void m_description(Guest& g) {
    uint64_t isa = g.x[0] ? read_u64(g.x[0]) : 0;
    const char* name = "Object";
    if (Info* info = info_at(isa)) name = info->name.c_str();
    else if (g_image && g_image->contains(isa)) {
        uint64_t ro = read_u64(isa + 32) & 0x00007ffffffffff8ull;
        if (ro && g_image->contains(ro)) {
            uint64_t np = read_u64(ro + 24);
            if (page_mapped(np)) name = guest_cstr(np);
        }
    }
    g.x[0] = make_string(name ? name : "Object");
}

void m_is_kind(Guest& g) {
    uint64_t want = g.x[2];
    uint64_t cls = g.x[0] ? read_u64(g.x[0]) : 0;
    for (int i = 0; cls && i < 32; ++i) {
        if (cls == want) {
            g.x[0] = 1;
            return;
        }
        if (g_image && g_image->contains(cls)) cls = read_u64(cls + 8);
        else if (Info* info = info_at(cls)) cls = info->obj ? info->obj->super : 0;
        else break;
    }
    g.x[0] = 0;
}

void m_responds(Guest& g) { g.x[0] = 1; }

void m_perform(Guest& g) {
    g.x[1] = g.x[2];
    objc_msg_send(g);
}

void m_utf8(Guest& g) { g.x[0] = reinterpret_cast<uint64_t>(text_of(g.x[0])); }
void m_length(Guest& g) {
    if (has_payload(g.x[0])) {
        Payload& p = payload(g.x[0]);
        if (p.kind == 2) g.x[0] = p.items.size();
        else if (p.kind == 3) g.x[0] = p.pairs.size();
        else if (p.kind == 5) g.x[0] = p.bytes.size();
        else g.x[0] = p.str.size();
        return;
    }
    g.x[0] = std::strlen(text_of(g.x[0]));
}
void m_eq_string(Guest& g) {
    g.x[0] = std::strcmp(text_of(g.x[0]), text_of(g.x[2])) == 0;
}
void m_string_utf8(Guest& g) {
    const char* s = guest_cstr(g.x[2]);
    g.x[0] = make_string(s ? s : "");
}
void m_string_init_utf8(Guest& g) {
    const char* s = guest_cstr(g.x[2]);
    payload(g.x[0]).kind = 1;
    payload(g.x[0]).str = s ? s : "";
}
void m_append(Guest& g) {
    std::string a = text_of(g.x[0]);
    a += text_of(g.x[2]);
    g.x[0] = make_string(a);
}

void m_array(Guest& g) {
    uint64_t o = make_object("NSArray");
    payload(o).kind = 2;
    g.x[0] = o;
}
void m_array_one(Guest& g) {
    uint64_t o = make_object("NSArray");
    payload(o).kind = 2;
    payload(o).items.push_back(g.x[2]);
    g.x[0] = o;
}
void m_array_count(Guest& g) {
    uint64_t o = make_object("NSArray");
    payload(o).kind = 2;
    uint64_t n = g.x[3];
    for (uint64_t i = 0; i < n && i < 256; ++i) payload(o).items.push_back(read_u64(g.x[2] + i * 8));
    g.x[0] = o;
}
void m_count(Guest& g) { m_length(g); }
void m_at(Guest& g) {
    Payload& p = payload(g.x[0]);
    uint64_t i = g.x[2];
    g.x[0] = i < p.items.size() ? p.items[i] : 0;
}
void m_first(Guest& g) {
    Payload& p = payload(g.x[0]);
    g.x[0] = p.items.empty() ? 0 : p.items[0];
}
void m_add(Guest& g) {
    payload(g.x[0]).kind = 2;
    payload(g.x[0]).items.push_back(g.x[2]);
}

void m_dict(Guest& g) {
    uint64_t o = make_object("NSDictionary");
    payload(o).kind = 3;
    g.x[0] = o;
}
void m_dict_one(Guest& g) {
    uint64_t o = make_object("NSMutableDictionary");
    payload(o).kind = 3;
    payload(o).pairs.push_back({g.x[3], g.x[2]});
    g.x[0] = o;
}
void m_set_obj(Guest& g) {
    payload(g.x[0]).kind = 3;
    payload(g.x[0]).pairs.push_back({g.x[3], g.x[2]});
}
void m_for_key(Guest& g) {
    Payload& p = payload(g.x[0]);
    for (auto it = p.pairs.rbegin(); it != p.pairs.rend(); ++it) {
        if (it->first == g.x[2] || (text_of(it->first)[0] && std::strcmp(text_of(it->first), text_of(g.x[2])) == 0)) {
            g.x[0] = it->second;
            return;
        }
    }
    auto prop = p.props.find(text_of(g.x[2]));
    if (prop != p.props.end()) {
        g.x[0] = prop->second;
        return;
    }
    g.x[0] = 0;
}

void m_num_int(Guest& g) {
    uint64_t o = make_object("NSNumber");
    payload(o).kind = 4;
    payload(o).number = static_cast<double>(static_cast<int64_t>(g.x[2]));
    payload(o).flag = g.x[2] != 0;
    g.x[0] = o;
}
void m_num_double(Guest& g) {
    double d = 0;
    std::memcpy(&d, g.v[0], 8);
    uint64_t o = make_object("NSNumber");
    payload(o).kind = 4;
    payload(o).number = d;
    payload(o).flag = d != 0;
    g.x[0] = o;
}
void m_int_value(Guest& g) { g.x[0] = static_cast<uint64_t>(static_cast<int64_t>(payload(g.x[0]).number)); }
void m_bool_value(Guest& g) { g.x[0] = payload(g.x[0]).flag || payload(g.x[0]).number != 0; }
void m_double_value(Guest& g) {
    double d = payload(g.x[0]).number;
    std::memcpy(g.v[0], &d, 8);
}

void m_data(Guest& g) {
    uint64_t o = make_object("NSData");
    payload(o).kind = 5;
    size_t n = g.x[3];
    if (g.x[2] && n && n < (8u << 20)) {
        payload(o).bytes.resize(n);
        std::memcpy(payload(o).bytes.data(), reinterpret_cast<void*>(tbi(g.x[2])), n);
    }
    g.x[0] = o;
}
void m_bytes(Guest& g) {
    Payload& p = payload(g.x[0]);
    if (p.bytes.empty()) {
        g.x[0] = 0;
        return;
    }
    g.x[0] = reinterpret_cast<uint64_t>(p.bytes.data());
}

uint64_t g_bundle_obj = 0;
uint64_t g_defaults = 0;
uint64_t g_process = 0;
uint64_t g_fileman = 0;
uint64_t g_center = 0;
uint64_t g_screen = 0;

void m_main_bundle(Guest& g) {
    if (!g_bundle_obj) {
        g_bundle_obj = make_object("NSBundle");
        payload(g_bundle_obj).str = g_bundle;
    }
    g.x[0] = g_bundle_obj;
}
void m_bundle_path(Guest& g) { g.x[0] = make_string(g_bundle); }
void m_resource_path(Guest& g) { g.x[0] = make_string(g_bundle + "/Contents/Resources"); }
void m_exe_path(Guest& g) { g.x[0] = make_string(g_exe); }
void m_bundle_id(Guest& g) { g.x[0] = make_string("com.oscar.lyricsblossom"); }
void m_info_dict(Guest& g) { m_dict(g); }

void m_process(Guest& g) {
    if (!g_process) g_process = make_object("NSProcessInfo");
    g.x[0] = g_process;
}
void m_cpus(Guest& g) { g.x[0] = static_cast<uint64_t>(sysconf(_SC_NPROCESSORS_ONLN)); }
void m_mem(Guest& g) {
    long pages = sysconf(_SC_PHYS_PAGES);
    long psz = sysconf(_SC_PAGESIZE);
    g.x[0] = (pages > 0 && psz > 0) ? static_cast<uint64_t>(pages) * static_cast<uint64_t>(psz) : (8ull << 30);
}
void m_osver(Guest& g) { g.x[0] = make_string("Version 14.0 (Build 23A344)"); }
void m_pname(Guest& g) { g.x[0] = make_string("LyricsBlossom"); }

void m_defaults(Guest& g) {
    if (!g_defaults) {
        g_defaults = make_object("NSUserDefaults");
        payload(g_defaults).kind = 3;
    }
    g.x[0] = g_defaults;
}
void m_defaults_set(Guest& g) { m_set_obj(g); }
void m_bool_key(Guest& g) {
    m_for_key(g);
    if (g.x[0] && has_payload(g.x[0])) g.x[0] = payload(g.x[0]).flag || payload(g.x[0]).number != 0;
}

void m_files(Guest& g) {
    if (!g_fileman) g_fileman = make_object("NSFileManager");
    g.x[0] = g_fileman;
}
void m_exists(Guest& g) {
    const char* path = text_of(g.x[2]);
    g.x[0] = path && path[0] && ::access(path, F_OK) == 0;
}

void m_date(Guest& g) {
    uint64_t o = make_object("NSDate");
    payload(o).number = static_cast<double>(std::time(nullptr));
    g.x[0] = o;
}
void m_interval(Guest& g) {
    double d = payload(g.x[0]).number;
    std::memcpy(g.v[0], &d, 8);
}

void m_runloop(Guest& g) { g.x[0] = make_object("NSRunLoop"); }
void m_run_return(Guest& g) { (void)g; }
void m_thread(Guest& g) { g.x[0] = make_object("NSThread"); }
void m_center(Guest& g) {
    if (!g_center) g_center = make_object("NSNotificationCenter");
    g.x[0] = g_center;
}

void m_shared_app(Guest& g) {
    if (!g_nsapp) g_nsapp = make_object("NSApplication");
    data_store_u64("_NSApp", g_nsapp);
    g.x[0] = g_nsapp;
}
void m_set_delegate(Guest& g) { payload(g.x[0]).props["delegate"] = g.x[2]; }
void m_delegate(Guest& g) { g.x[0] = payload(g.x[0]).props["delegate"]; }
void m_app_run(Guest& g) {
    uint64_t app = g.x[0];
    uint64_t del = payload(app).props["delegate"];
    if (del) {
        Guest call;
        call.x[0] = del;
        call.x[1] = reinterpret_cast<uint64_t>(sel("applicationDidFinishLaunching:"));
        call.x[2] = 0;
        objc_msg_send(call);
        if (call.redirect) call_guest(call.pc, call.x[0], call.x[1], call.x[2], call.x[3], &g);
        else if (call.stop) {
            g.stop = call.stop;
            g.stop_why = call.stop_why;
            g.stop_pc = call.stop_pc;
        }
    }
    g.x[0] = app;
}

void store_rect(uint64_t obj, const double r[4]) {
    Payload& p = payload(obj);
    p.bytes.resize(32);
    std::memcpy(p.bytes.data(), r, 32);
    p.props["w"] = static_cast<uint64_t>(r[2]);
    p.props["h"] = static_cast<uint64_t>(r[3]);
}
void load_rect(uint64_t obj, double r[4]) {
    r[0] = r[1] = 0;
    r[2] = 1280;
    r[3] = 720;
    Payload& p = payload(obj);
    if (p.bytes.size() >= 32) std::memcpy(r, p.bytes.data(), 32);
}

void m_init_frame(Guest& g) {
    double r[4];
    read_arg_rect(g, r);
    store_rect(g.x[0], r);
}
void m_frame(Guest& g) {
    double r[4];
    load_rect(g.x[0], r);
    write_rect(g, r[0], r[1], r[2], r[3]);
}
void m_set_title(Guest& g) { payload(g.x[0]).str = text_of(g.x[2]); }
void m_content(Guest& g) {
    uint64_t v = payload(g.x[0]).props["content"];
    if (!v) {
        v = make_object("NSView");
        payload(g.x[0]).props["content"] = v;
        payload(v).props["window"] = g.x[0];
        double r[4];
        load_rect(g.x[0], r);
        store_rect(v, r);
    }
    g.x[0] = v;
}
void m_set_content(Guest& g) {
    payload(g.x[0]).props["content"] = g.x[2];
    if (g.x[2]) payload(g.x[2]).props["window"] = g.x[0];
}
void m_order_front(Guest& g) {
    double r[4];
    load_rect(g.x[0], r);
    int w = static_cast<int>(r[2]);
    int h = static_cast<int>(r[3]);
    ensure_window(w > 0 ? w : 1280, h > 0 ? h : 720);
    payload(g.x[0]).flag = true;
}
void m_scale(Guest& g) {
    double s = 2;
    std::memcpy(g.v[0], &s, 8);
}
void m_superview(Guest& g) { g.x[0] = payload(g.x[0]).props["superview"]; }
void m_window(Guest& g) {
    uint64_t w = payload(g.x[0]).props["window"];
    if (!w) {
        uint64_t parent = payload(g.x[0]).props["superview"];
        if (parent) w = payload(parent).props["window"];
    }
    if (!w) {
        w = make_object("NSWindow");
        payload(g.x[0]).props["window"] = w;
        payload(w).props["content"] = g.x[0];
        double r[4];
        load_rect(g.x[0], r);
        store_rect(w, r);
    }
    g.x[0] = w;
}
void m_layer(Guest& g) {
    uint64_t layer = payload(g.x[0]).props["layer"];
    if (!layer) {
        layer = make_object("CAMetalLayer");
        payload(g.x[0]).props["layer"] = layer;
        double r[4];
        load_rect(g.x[0], r);
        store_rect(layer, r);
    }
    g.x[0] = layer;
}
void m_subview(Guest& g) {
    payload(g.x[0]).items.push_back(g.x[2]);
    if (g.x[2]) payload(g.x[2]).props["superview"] = g.x[0];
}
void m_screen(Guest& g) {
    if (!g_screen) {
        g_screen = make_object("NSScreen");
        double r[4] = {0, 0, 1280, 720};
        store_rect(g_screen, r);
    }
    g.x[0] = g_screen;
}
void m_screens(Guest& g) {
    m_screen(g);
    uint64_t s = g.x[0];
    uint64_t a = make_object("NSArray");
    payload(a).kind = 2;
    payload(a).items.push_back(s);
    g.x[0] = a;
}
void m_color(Guest& g) {
    uint64_t o = make_object("NSColor");
    double d[4] {};
    std::memcpy(&d[0], g.v[0], 8);
    std::memcpy(&d[1], g.v[1], 8);
    std::memcpy(&d[2], g.v[2], 8);
    std::memcpy(&d[3], g.v[3], 8);
    payload(o).bytes.resize(32);
    std::memcpy(payload(o).bytes.data(), d, 32);
    g.x[0] = o;
}
void m_font(Guest& g) {
    uint64_t o = make_object("NSFont");
    double sz = 0;
    std::memcpy(&sz, g.v[0], 8);
    payload(o).number = sz > 0 ? sz : 14;
    payload(o).str = "System";
    g.x[0] = o;
}
void m_font_named(Guest& g) {
    uint64_t o = make_object("NSFont");
    payload(o).str = text_of(g.x[2]);
    double sz = 0;
    std::memcpy(&sz, g.v[0], 8);
    payload(o).number = sz > 0 ? sz : 14;
    g.x[0] = o;
}

bool dispatch_host(Guest& g, Info* info, const char* sel) {
    while (info) {
        auto it = info->methods.find(sel);
        if (it != info->methods.end()) {
            it->second(g);
            return true;
        }
        info = info->super_info;
    }
    return false;
}

uint64_t guest_imp(uint64_t cls, const char* sel) {
    auto it = g_guest_imp.find(imp_key(cls, sel));
    return it == g_guest_imp.end() ? 0 : it->second;
}

bool generic_message(Guest& g, const char* sname) {
    std::string s = sname ? sname : "";
    if (s == "alloc" || s == "allocWithZone:") {
        m_alloc(g);
        return true;
    }
    if (s == "new") {
        m_new(g);
        return true;
    }
    if (s == "init" || s.rfind("init", 0) == 0) {
        if (s == "initWithContentRect:styleMask:backing:defer:" || s == "initWithFrame:") m_init_frame(g);
        return true;
    }
    if (s == "retain" || s == "autorelease" || s == "self" || s == "copy" || s == "mutableCopy") return true;
    if (s == "release" || s == "dealloc" || s == "drain") return true;
    if (s == "class") {
        m_class(g);
        return true;
    }
    if (s == "description" || s == "debugDescription") {
        m_description(g);
        return true;
    }
    if (s == "hash") return true;
    if (s == "isEqual:" || s == "isEqualTo:") {
        g.x[0] = g.x[0] == g.x[2];
        return true;
    }
    if (s == "isKindOfClass:" || s == "isMemberOfClass:") {
        m_is_kind(g);
        return true;
    }
    if (s == "respondsToSelector:" || s == "instancesRespondToSelector:") {
        g.x[0] = 1;
        return true;
    }
    if (s == "performSelector:" || s == "performSelector:withObject:") {
        m_perform(g);
        return true;
    }
    if (s == "UTF8String" || s == "cString" || s == "UTF8String") {
        m_utf8(g);
        return true;
    }
    if (s == "length" || s == "count") {
        m_length(g);
        return true;
    }
    std::string key;
    if (is_setter(s, key)) {
        if (key == "frame" || key == "bounds" || key.find("Rect") != std::string::npos) {
            double r[4];
            read_arg_rect(g, r);
            store_rect(g.x[0], r);
        } else payload(g.x[0]).props[key] = g.x[2];
        return true;
    }
    if (!s.empty() && s.find(':') == std::string::npos) {
        auto it = payload(g.x[0]).props.find(s);
        if (it != payload(g.x[0]).props.end()) {
            g.x[0] = it->second;
            return true;
        }
    }
    if (s.find("Rect") != std::string::npos || s == "bounds" || s == "frame" || s == "visibleFrame") {
        double r[4];
        load_rect(g.x[0], r);
        write_rect(g, r[0], r[1], r[2], r[3]);
        return true;
    }
    return false;
}

void index_methods(uint64_t cls) {
    if (!cls || !g_image || !g_image->contains(cls)) return;
    uint64_t bits = read_u64(cls + 32);
    uint64_t ro = bits & 0x00007ffffffffff8ull;
    if (!ro) return;
    uint64_t list = read_u64(ro + 32);
    if (!list || !g_image->contains(list)) return;
    uint32_t header = 0, count = 0;
    std::memcpy(&header, reinterpret_cast<void*>(list), 4);
    std::memcpy(&count, reinterpret_cast<void*>(list + 4), 4);
    bool relative = header & 0x80000000u;
    uint32_t stride = header & 0x7ffffffcu;
    if (stride == 0) stride = relative ? 12 : 24;
    if (count > 4096) count = 4096;
    for (uint32_t i = 0; i < count; ++i) {
        uint64_t ent = list + 8 + static_cast<uint64_t>(i) * stride;
        const char* name = nullptr;
        uint64_t imp = 0;
        if (relative && stride >= 12) {
            int32_t nrel = 0, irel = 0;
            std::memcpy(&nrel, reinterpret_cast<void*>(ent), 4);
            std::memcpy(&irel, reinterpret_cast<void*>(ent + 8), 4);
            uint64_t ntarget = ent + static_cast<int64_t>(nrel);
            imp = (ent + 8) + static_cast<int64_t>(irel);
            uint64_t selp = read_u64(ntarget);
            const char* via = guest_cstr(selp);
            if (via && via[0] >= 32 && via[0] < 127) name = via;
            else name = guest_cstr(ntarget);
        } else {
            name = guest_cstr(read_u64(ent));
            imp = read_u64(ent + 16);
        }
        if (name && name[0] && imp) g_guest_imp[imp_key(cls, name)] = imp;
    }
}

}  // namespace

const char* sel(const char* name) {
    if (!name) name = "";
    auto it = g_sels.find(name);
    if (it != g_sels.end()) return it->second;
    g_sel_pool.emplace_back(name);
    const char* p = g_sel_pool.back().c_str();
    g_sels.emplace(name, p);
    return p;
}

uint64_t ensure_class(const std::string& name, const std::string& super, uint32_t size) {
    auto found = g_by_name.find(name);
    if (found != g_by_name.end()) return reinterpret_cast<uint64_t>(found->second->obj);
    Info* sinfo = nullptr;
    if (!super.empty() && super != name) {
        ensure_class(super, super == "NSObject" ? "" : "NSObject", 64);
        sinfo = g_by_name[super];
    }
    auto* info = new Info;
    auto* meta = new Info;
    auto* cls = new ClassObj;
    auto* mcls = new ClassObj;
    info->name = name;
    info->size = size < 16 ? 64 : size;
    info->obj = cls;
    info->meta_info = meta;
    info->super_info = sinfo;
    info->ro.inst_size = info->size;
    info->ro.name = info->name.c_str();
    meta->name = name;
    meta->meta = true;
    meta->obj = mcls;
    meta->super_info = sinfo ? sinfo->meta_info : info;
    meta->ro.inst_size = 64;
    meta->ro.name = info->name.c_str();
    cls->isa = reinterpret_cast<uint64_t>(mcls);
    cls->super = sinfo ? reinterpret_cast<uint64_t>(sinfo->obj) : 0;
    cls->bits = reinterpret_cast<uint64_t>(&info->ro);
    mcls->isa = sinfo ? reinterpret_cast<uint64_t>(sinfo->meta_info->obj) : reinterpret_cast<uint64_t>(mcls);
    mcls->super = sinfo ? reinterpret_cast<uint64_t>(sinfo->meta_info->obj) : reinterpret_cast<uint64_t>(cls);
    mcls->bits = reinterpret_cast<uint64_t>(&meta->ro);
    g_by_name.emplace(name, info);
    g_by_addr.emplace(reinterpret_cast<uint64_t>(cls), info);
    g_by_addr.emplace(reinterpret_cast<uint64_t>(mcls), meta);
    return reinterpret_cast<uint64_t>(cls);
}

uint64_t class_ptr(const std::string& name) {
    auto it = g_by_name.find(name);
    if (it == g_by_name.end()) return 0;
    return reinterpret_cast<uint64_t>(it->second->obj);
}

void add_method(const std::string& cls, const char* s, ShimFn fn, bool class_method) {
    Info* info = g_by_name[cls];
    if (!info) return;
    Info* target = class_method ? info->meta_info : info;
    target->methods[s] = fn;
}

uint64_t make_object(const std::string& cls) {
    if (!class_ptr(cls)) ensure_class(cls, "NSObject", 64);
    Info* info = g_by_name[cls];
    uint32_t sz = info ? info->size : 64;
    void* p = std::calloc(1, sz);
    write_u64(reinterpret_cast<uint64_t>(p), reinterpret_cast<uint64_t>(info->obj));
    return reinterpret_cast<uint64_t>(p);
}

uint64_t make_string(const std::string& text) {
    uint64_t o = make_object("NSString");
    payload(o).kind = 1;
    payload(o).str = text;
    return o;
}

Payload& payload(uint64_t obj) { return g_payload[obj]; }
bool has_payload(uint64_t obj) { return g_payload.find(obj) != g_payload.end(); }
std::vector<std::string> missed_selectors() {
    std::lock_guard<std::mutex> lock(g_miss_mu);
    return g_misses;
}

void objc_msg_send(Guest& g) {
    uint64_t obj = g.x[0];
    if (!obj) {
        g.x[0] = 0;
        return;
    }
    const char* s = guest_cstr(g.x[1]);
    if (!s) s = "";
    uint64_t cls = read_u64(obj);
    while (cls && g_image && g_image->contains(cls)) {
        if (uint64_t imp = guest_imp(cls, s)) {
            g.pc = imp;
            g.redirect = true;
            return;
        }
        cls = read_u64(cls + 8);
    }
    if (Info* info = info_at(cls)) {
        if (dispatch_host(g, info, s)) return;
    }
    if (generic_message(g, s)) return;
    if (tracing()) std::fprintf(stderr, "sel %s\n", s);
    remember_miss(s);
    g.x[0] = 0;
}

void objc_msg_send_super2(Guest& g) {
    uint64_t rec = read_u64(g.x[0]);
    uint64_t cls = read_u64(g.x[0] + 8);
    uint64_t super = 0;
    if (g_image && g_image->contains(cls)) super = read_u64(cls + 8);
    else if (Info* info = info_at(cls)) super = info->obj ? info->obj->super : 0;
    g.x[0] = rec;
    if (!rec) return;
    uint64_t saved = read_u64(rec);
    write_u64(rec, super ? super : saved);
    objc_msg_send(g);
    write_u64(rec, saved);
}

void objc_init() {
    ensure_class("NSObject", "", 64);
    add_method("NSObject", "alloc", m_alloc, true);
    add_method("NSObject", "allocWithZone:", m_alloc, true);
    add_method("NSObject", "new", m_new, true);
    add_method("NSObject", "init", m_init, false);
    add_method("NSObject", "retain", m_retain, false);
    add_method("NSObject", "release", m_release, false);
    add_method("NSObject", "autorelease", m_retain, false);
    add_method("NSObject", "self", m_self, false);
    add_method("NSObject", "class", m_class, false);
    add_method("NSObject", "hash", m_hash, false);
    add_method("NSObject", "description", m_description, false);
    add_method("NSObject", "copy", m_copy, false);
    add_method("NSObject", "isKindOfClass:", m_is_kind, false);
    add_method("NSObject", "respondsToSelector:", m_responds, false);
    add_method("NSObject", "isEqual:", m_eq_string, false);

    auto foundation = [](const char* name, const char* super = "NSObject") { ensure_class(name, super, 1024); };
    foundation("NSString");
    foundation("__NSCFString", "NSString");
    foundation("NSMutableString", "NSString");
    foundation("NSArray");
    foundation("NSMutableArray", "NSArray");
    foundation("NSDictionary");
    foundation("NSMutableDictionary", "NSDictionary");
    foundation("NSNumber");
    foundation("NSData");
    foundation("NSMutableData", "NSData");
    foundation("NSBundle");
    foundation("NSProcessInfo");
    foundation("NSUserDefaults");
    foundation("NSFileManager");
    foundation("NSDate");
    foundation("NSRunLoop");
    foundation("NSThread");
    foundation("NSNotificationCenter");
    foundation("NSNotification");
    foundation("NSAutoreleasePool");
    foundation("NSValue");
    foundation("NSURL", "NSObject");
    foundation("NSError");
    foundation("NSApplication");
    foundation("NSWindow");
    foundation("NSView");
    foundation("NSScreen");
    foundation("NSColor");
    foundation("NSFont");
    foundation("NSImage");
    foundation("NSMenu");
    foundation("NSMenuItem");
    foundation("CALayer");
    foundation("CAMetalLayer", "CALayer");
    foundation("NSResponder", "NSObject");

    add_method("NSString", "stringWithUTF8String:", m_string_utf8, true);
    add_method("NSString", "stringWithCString:encoding:", m_string_utf8, true);
    add_method("NSString", "initWithUTF8String:", m_string_init_utf8, false);
    add_method("NSString", "UTF8String", m_utf8, false);
    add_method("NSString", "cStringUsingEncoding:", m_utf8, false);
    add_method("NSString", "length", m_length, false);
    add_method("NSString", "isEqualToString:", m_eq_string, false);
    add_method("NSString", "stringByAppendingString:", m_append, false);
    add_method("NSArray", "array", m_array, true);
    add_method("NSArray", "arrayWithObject:", m_array_one, true);
    add_method("NSArray", "arrayWithObjects:count:", m_array_count, true);
    add_method("NSArray", "count", m_count, false);
    add_method("NSArray", "objectAtIndex:", m_at, false);
    add_method("NSArray", "objectAtIndexedSubscript:", m_at, false);
    add_method("NSArray", "firstObject", m_first, false);
    add_method("NSMutableArray", "array", m_array, true);
    add_method("NSMutableArray", "addObject:", m_add, false);
    add_method("NSDictionary", "dictionary", m_dict, true);
    add_method("NSDictionary", "dictionaryWithObject:forKey:", m_dict_one, true);
    add_method("NSDictionary", "objectForKey:", m_for_key, false);
    add_method("NSDictionary", "objectForKeyedSubscript:", m_for_key, false);
    add_method("NSDictionary", "count", m_count, false);
    add_method("NSMutableDictionary", "dictionary", m_dict, true);
    add_method("NSMutableDictionary", "setObject:forKey:", m_set_obj, false);
    add_method("NSMutableDictionary", "setObject:forKeyedSubscript:", m_set_obj, false);
    add_method("NSNumber", "numberWithInt:", m_num_int, true);
    add_method("NSNumber", "numberWithInteger:", m_num_int, true);
    add_method("NSNumber", "numberWithUnsignedInteger:", m_num_int, true);
    add_method("NSNumber", "numberWithBool:", m_num_int, true);
    add_method("NSNumber", "numberWithLongLong:", m_num_int, true);
    add_method("NSNumber", "numberWithDouble:", m_num_double, true);
    add_method("NSNumber", "numberWithFloat:", m_num_double, true);
    add_method("NSNumber", "integerValue", m_int_value, false);
    add_method("NSNumber", "intValue", m_int_value, false);
    add_method("NSNumber", "longLongValue", m_int_value, false);
    add_method("NSNumber", "boolValue", m_bool_value, false);
    add_method("NSNumber", "doubleValue", m_double_value, false);
    add_method("NSNumber", "floatValue", m_double_value, false);
    add_method("NSData", "dataWithBytes:length:", m_data, true);
    add_method("NSData", "dataWithBytesNoCopy:length:", m_data, true);
    add_method("NSData", "bytes", m_bytes, false);
    add_method("NSData", "length", m_length, false);
    add_method("NSBundle", "mainBundle", m_main_bundle, true);
    add_method("NSBundle", "bundlePath", m_bundle_path, false);
    add_method("NSBundle", "resourcePath", m_resource_path, false);
    add_method("NSBundle", "executablePath", m_exe_path, false);
    add_method("NSBundle", "bundleIdentifier", m_bundle_id, false);
    add_method("NSBundle", "infoDictionary", m_info_dict, false);
    add_method("NSProcessInfo", "processInfo", m_process, true);
    add_method("NSProcessInfo", "processorCount", m_cpus, false);
    add_method("NSProcessInfo", "activeProcessorCount", m_cpus, false);
    add_method("NSProcessInfo", "physicalMemory", m_mem, false);
    add_method("NSProcessInfo", "operatingSystemVersionString", m_osver, false);
    add_method("NSProcessInfo", "processName", m_pname, false);
    add_method("NSUserDefaults", "standardUserDefaults", m_defaults, true);
    add_method("NSUserDefaults", "objectForKey:", m_for_key, false);
    add_method("NSUserDefaults", "stringForKey:", m_for_key, false);
    add_method("NSUserDefaults", "boolForKey:", m_bool_key, false);
    add_method("NSUserDefaults", "integerForKey:", m_for_key, false);
    add_method("NSUserDefaults", "setObject:forKey:", m_defaults_set, false);
    add_method("NSUserDefaults", "setBool:forKey:", m_defaults_set, false);
    add_method("NSFileManager", "defaultManager", m_files, true);
    add_method("NSFileManager", "fileExistsAtPath:", m_exists, false);
    add_method("NSDate", "date", m_date, true);
    add_method("NSDate", "timeIntervalSince1970", m_interval, false);
    add_method("NSRunLoop", "currentRunLoop", m_runloop, true);
    add_method("NSRunLoop", "mainRunLoop", m_runloop, true);
    add_method("NSRunLoop", "run", m_run_return, false);
    add_method("NSRunLoop", "runUntilDate:", m_run_return, false);
    add_method("NSThread", "isMainThread", m_yes, true);
    add_method("NSThread", "currentThread", m_thread, true);
    add_method("NSNotificationCenter", "defaultCenter", m_center, true);
    add_method("NSNotificationCenter", "addObserver:selector:name:object:", m_release, false);
    add_method("NSNotificationCenter", "postNotificationName:object:", m_release, false);
    add_method("NSApplication", "sharedApplication", m_shared_app, true);
    add_method("NSApplication", "setActivationPolicy:", m_release, false);
    add_method("NSApplication", "setDelegate:", m_set_delegate, false);
    add_method("NSApplication", "delegate", m_delegate, false);
    add_method("NSApplication", "finishLaunching", m_release, false);
    add_method("NSApplication", "run", m_app_run, false);
    add_method("NSApplication", "activateIgnoringOtherApps:", m_release, false);
    add_method("NSApplication", "windows", m_screens, false);
    add_method("NSWindow", "initWithContentRect:styleMask:backing:defer:", m_init_frame, false);
    add_method("NSWindow", "setTitle:", m_set_title, false);
    add_method("NSWindow", "contentView", m_content, false);
    add_method("NSWindow", "setContentView:", m_set_content, false);
    add_method("NSWindow", "makeKeyAndOrderFront:", m_order_front, false);
    add_method("NSWindow", "orderFront:", m_order_front, false);
    add_method("NSWindow", "frame", m_frame, false);
    add_method("NSWindow", "isVisible", m_yes, false);
    add_method("NSWindow", "screen", m_screen, false);
    add_method("NSWindow", "backingScaleFactor", m_scale, false);
    add_method("NSWindow", "setDelegate:", m_set_delegate, false);
    add_method("NSView", "initWithFrame:", m_init_frame, false);
    add_method("NSView", "setWantsLayer:", m_release, false);
    add_method("NSView", "layer", m_layer, false);
    add_method("NSView", "setLayer:", m_set_content, false);
    add_method("NSView", "addSubview:", m_subview, false);
    add_method("NSView", "bounds", m_frame, false);
    add_method("NSView", "frame", m_frame, false);
    add_method("NSView", "window", m_window, false);
    add_method("NSView", "superview", m_superview, false);
    add_method("NSScreen", "mainScreen", m_screen, true);
    add_method("NSScreen", "screens", m_screens, true);
    add_method("NSScreen", "frame", m_frame, false);
    add_method("NSScreen", "visibleFrame", m_frame, false);
    add_method("NSScreen", "backingScaleFactor", m_scale, false);
    add_method("NSColor", "colorWithRed:green:blue:alpha:", m_color, true);
    add_method("NSColor", "whiteColor", m_color, true);
    add_method("NSColor", "clearColor", m_color, true);
    add_method("NSColor", "blackColor", m_color, true);
    add_method("NSFont", "systemFontOfSize:", m_font, true);
    add_method("NSFont", "fontWithName:size:", m_font_named, true);
    add_method("CALayer", "layer", m_layer, true);
    add_method("CALayer", "setDelegate:", m_set_delegate, false);
    add_method("CALayer", "setContentsScale:", m_release, false);
    add_method("CAMetalLayer", "layer", m_layer, true);
}

void objc_load_guest(const MachImage& image) {
    const MachSection* cl = image.find_section("__DATA_CONST", "__objc_classlist");
    if (!cl) cl = image.find_section("__DATA", "__objc_classlist");
    if (!cl) return;
    for (uint64_t i = 0; i + 8 <= cl->size; i += 8) {
        uint64_t cls = read_u64(cl->addr + i);
        if (!cls) continue;
        index_methods(cls);
        uint64_t meta = read_u64(cls);
        if (image.contains(meta)) index_methods(meta);
    }
}

void objc_finish_data() {
    if (!g_nsapp) g_nsapp = make_object("NSApplication");
    data_store_u64("_NSApp", g_nsapp);
    uint64_t yes = make_object("NSNumber");
    payload(yes).kind = 4;
    payload(yes).flag = true;
    payload(yes).number = 1;
    uint64_t no = make_object("NSNumber");
    payload(no).kind = 4;
    data_store_u64("___kCFBooleanTrue", yes);
    data_store_u64("_kCFBooleanTrue", yes);
    data_store_u64("___kCFBooleanFalse", no);
    data_store_u64("_kCFBooleanFalse", no);
    uint64_t empty = data_symbol("___NSArray0__struct", 64);
    write_u64(empty, class_ptr("NSArray"));
    payload(empty).kind = 2;
    uint64_t emptyd = data_symbol("___NSDictionary0__struct", 64);
    write_u64(emptyd, class_ptr("NSDictionary"));
    payload(emptyd).kind = 3;
}

void host_present(const uint8_t* rgba, int w, int h) {
    if (!rgba || w <= 0 || h <= 0) return;
    if (const char* path = std::getenv("LB_FRAME_OUT")) {
        FILE* f = std::fopen(path, "wb");
        if (f) {
            std::fprintf(f, "P6\n%d %d\n255\n", w, h);
            for (int i = 0; i < w * h; ++i) std::fwrite(rgba + i * 4, 1, 3, f);
            std::fclose(f);
        }
    }
    ensure_window(w, h);
    if (!g_dpy || !g_win) return;
    std::vector<uint8_t> bgra(static_cast<size_t>(w) * h * 4);
    for (int i = 0; i < w * h; ++i) {
        bgra[i * 4 + 0] = rgba[i * 4 + 2];
        bgra[i * 4 + 1] = rgba[i * 4 + 1];
        bgra[i * 4 + 2] = rgba[i * 4 + 0];
        bgra[i * 4 + 3] = 255;
    }
    XImage* image = XCreateImage(g_dpy, DefaultVisual(g_dpy, DefaultScreen(g_dpy)), 24, ZPixmap, 0,
                                 reinterpret_cast<char*>(bgra.data()), w, h, 32, w * 4);
    if (!image) return;
    image->byte_order = LSBFirst;
    XPutImage(g_dpy, g_win, g_gc, image, 0, 0, 0, 0, w, h);
    image->data = nullptr;
    XDestroyImage(image);
    XFlush(g_dpy);
}

}  // namespace lb

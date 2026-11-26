#include "lb/runtime.hpp"
#include "host.hpp"

#include <execinfo.h>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <cerrno>
#include <cmath>
#include <csignal>
#include <poll.h>
#include <csetjmp>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <dirent.h>
#include <fcntl.h>
#include <netdb.h>
#include <pthread.h>
#include <spawn.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>
#include <arpa/inet.h>

#include <initializer_list>
#include <map>
#include <mutex>
#include <string>
#include <unordered_set>
#include <vector>

extern char** environ;

namespace lb {
namespace {

struct Shim {
    std::string name;
    ShimFn fn = nullptr;
    uint64_t addr = 0;
};

struct DataSym {
    std::string name;
    uint64_t addr = 0;
    size_t size = 0;
};

uint64_t g_shim_base = 0;
size_t g_shim_span = 0;
std::vector<Shim> g_shims;
std::unordered_map<std::string, size_t> g_shim_by_name;
std::unordered_map<std::string, DataSym> g_data;
std::vector<std::string> g_unknown;
std::mutex g_mu;

thread_local int g_dar_errno = 0;
thread_local sigjmp_buf g_jmp;
thread_local Guest* g_cur = nullptr;
thread_local volatile sig_atomic_t g_armed = 0;
uint64_t g_fault_addr = 0;
uint64_t g_fault_pc = 0;

uint64_t g_guest_stack = 0;
uint64_t g_exit_shim = 0;

int to_darwin_errno(int e) {
    switch (e) {
    case 0: return 0;
    case EDEADLK: return 11;
    case EAGAIN: return 35;
    case EINPROGRESS: return 36;
    case EALREADY: return 37;
    case ENOTSOCK: return 38;
    case EDESTADDRREQ: return 39;
    case EMSGSIZE: return 40;
    case EPROTOTYPE: return 41;
    case ENOPROTOOPT: return 42;
    case EPROTONOSUPPORT: return 43;
    case ESOCKTNOSUPPORT: return 44;
    case EOPNOTSUPP: return 45;
    case EPFNOSUPPORT: return 46;
    case EAFNOSUPPORT: return 47;
    case EADDRINUSE: return 48;
    case EADDRNOTAVAIL: return 49;
    case ENETDOWN: return 50;
    case ENETUNREACH: return 51;
    case ENETRESET: return 52;
    case ECONNABORTED: return 53;
    case ECONNRESET: return 54;
    case ENOBUFS: return 55;
    case EISCONN: return 56;
    case ENOTCONN: return 57;
    case ETIMEDOUT: return 60;
    case ECONNREFUSED: return 61;
    case ELOOP: return 62;
    case ENAMETOOLONG: return 63;
    case EHOSTDOWN: return 64;
    case EHOSTUNREACH: return 65;
    case ENOTEMPTY: return 66;
    case EDQUOT: return 69;
    case ESTALE: return 70;
    case ENOLCK: return 77;
    case ENOSYS: return 78;
    case EOVERFLOW: return 84;
    case ECANCELED: return 89;
    case EIDRM: return 90;
    case ENOMSG: return 91;
    case EILSEQ: return 92;
    case EBADMSG: return 94;
    case EMULTIHOP: return 95;
    case ENODATA: return 96;
    case ENOLINK: return 97;
    case ENOSR: return 98;
    case ENOSTR: return 99;
    case EPROTO: return 100;
    case ETIME: return 101;
    default: return (e > 0 && e <= 34) ? e : e;
    }
}

void set_guest_errno() { g_dar_errno = to_darwin_errno(errno); }

bool boot_test() {
    static int v = -1;
    if (v < 0) v = std::getenv("LB_BOOT_TEST") ? 1 : 0;
    return v;
}

uint64_t mono_ns() {
    timespec ts {};
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return static_cast<uint64_t>(ts.tv_sec) * 1000000000ull + static_cast<uint64_t>(ts.tv_nsec);
}

int map_open_flags(uint64_t f) {
    int o = static_cast<int>(f & 3);
    if (f & 0x100) o |= O_NOFOLLOW;
    if (f & 0x200) o |= O_CREAT;
    if (f & 0x400) o |= O_TRUNC;
    if (f & 0x800) o |= O_EXCL;
    if (f & 0x4) o |= O_NONBLOCK;
    if (f & 0x8) o |= O_APPEND;
    if (f & 0x100000) o |= O_DIRECTORY;
    if (f & 0x1000000) o |= O_CLOEXEC;
    return o;
}

int map_mmap_flags(uint64_t f) {
    int o = 0;
    if (f & 0x1) o |= MAP_SHARED;
    if (f & 0x2) o |= MAP_PRIVATE;
    if (f & 0x10) o |= MAP_FIXED;
    if (f & 0x1000) o |= MAP_ANONYMOUS;
    if ((o & (MAP_SHARED | MAP_PRIVATE)) == 0) o |= MAP_PRIVATE;
    return o;
}

void write_darwin_stat(void* dst, const struct stat& st) {
    uint8_t b[144] {};
    auto p32 = [&](int o, uint32_t v) { std::memcpy(b + o, &v, 4); };
    auto p16 = [&](int o, uint16_t v) { std::memcpy(b + o, &v, 2); };
    auto p64 = [&](int o, uint64_t v) { std::memcpy(b + o, &v, 8); };
    p32(0, static_cast<uint32_t>(st.st_dev));
    p16(4, static_cast<uint16_t>(st.st_mode));
    p16(6, static_cast<uint16_t>(st.st_nlink));
    p64(8, static_cast<uint64_t>(st.st_ino));
    p32(16, st.st_uid);
    p32(20, st.st_gid);
    p32(24, static_cast<uint32_t>(st.st_rdev));
    p64(32, static_cast<uint64_t>(st.st_atim.tv_sec));
    p64(40, static_cast<uint64_t>(st.st_atim.tv_nsec));
    p64(48, static_cast<uint64_t>(st.st_mtim.tv_sec));
    p64(56, static_cast<uint64_t>(st.st_mtim.tv_nsec));
    p64(64, static_cast<uint64_t>(st.st_ctim.tv_sec));
    p64(72, static_cast<uint64_t>(st.st_ctim.tv_nsec));
    p64(96, static_cast<uint64_t>(st.st_size));
    p64(104, static_cast<uint64_t>(st.st_blocks));
    p32(112, static_cast<uint32_t>(st.st_blksize));
    std::memcpy(dst, b, 144);
}

bool looks_like_linux_sockaddr(const uint8_t* p, uint64_t len) {
    if (len < 2) return false;
    uint16_t fam = 0;
    std::memcpy(&fam, p, 2);
    return fam == AF_INET || fam == AF_INET6 || fam == AF_UNIX;
}

bool to_host_sockaddr(uint64_t ptr, uint64_t len, sockaddr_storage& out, socklen_t& outlen) {
    if (!ptr || len < 2) return false;
    const auto* p = reinterpret_cast<const uint8_t*>(tbi(ptr));
    if (looks_like_linux_sockaddr(p, len)) {
        std::memset(&out, 0, sizeof(out));
        std::memcpy(&out, p, std::min<uint64_t>(len, sizeof(out)));
        outlen = static_cast<socklen_t>(std::min<uint64_t>(len, sizeof(out)));
        return true;
    }
    uint8_t family = p[1];
    std::memset(&out, 0, sizeof(out));
    if (family == AF_INET && len >= 8) {
        auto* s = reinterpret_cast<sockaddr_in*>(&out);
        s->sin_family = AF_INET;
        std::memcpy(&s->sin_port, p + 2, 2);
        if (len >= 8) std::memcpy(&s->sin_addr, p + 4, 4);
        outlen = sizeof(sockaddr_in);
        return true;
    }
    if (family == AF_UNIX) {
        auto* s = reinterpret_cast<sockaddr_un*>(&out);
        s->sun_family = AF_UNIX;
        size_t n = std::min<size_t>(len > 2 ? len - 2 : 0, sizeof(s->sun_path) - 1);
        std::memcpy(s->sun_path, p + 2, n);
        outlen = sizeof(sockaddr_un);
        return true;
    }
    return false;
}

std::vector<std::string> read_str_array(uint64_t p) {
    std::vector<std::string> out;
    if (!p) return out;
    for (int i = 0; i < 128; ++i) {
        uint64_t s = read_u64(p + static_cast<uint64_t>(i) * 8);
        if (!s) break;
        const char* c = guest_cstr(s);
        out.emplace_back(c ? c : "");
    }
    return out;
}

struct FileActs {
    uint32_t magic = 0x46414354;
    struct Dup {
        int from;
        int to;
    } dups[16] {};
    int ndup = 0;
    int closes[8] {};
    int nclose = 0;
};

FileActs* acts_from(uint64_t p) {
    if (p < 0x10000) return nullptr;
    auto* direct = reinterpret_cast<FileActs*>(tbi(p));
    if (direct->magic == 0x46414354) return direct;
    uint64_t inner = read_u64(p);
    if (inner < 0x10000) return nullptr;
    auto* nested = reinterpret_cast<FileActs*>(tbi(inner));
    if (nested->magic == 0x46414354) return nested;
    return nullptr;
}

struct JmpSave {
    Guest g;
    uint64_t resume = 0;
};
std::mutex g_jmp_mu;
std::map<uint64_t, JmpSave> g_jumps;

struct ThreadStart {
    uint64_t func = 0;
    uint64_t arg = 0;
    uint64_t stack = 0;
};

void install_handler();

struct GuestThread {
    pthread_t th{};
    Guest* guest = nullptr;
};

std::mutex g_thr_mu;
std::vector<GuestThread> g_guest_threads;

void note_guest_thread(pthread_t th, Guest* guest) {
    std::lock_guard<std::mutex> lock(g_thr_mu);
    g_guest_threads.push_back(GuestThread{th, guest});
}

void forget_guest_thread(pthread_t th) {
    std::lock_guard<std::mutex> lock(g_thr_mu);
    std::erase_if(g_guest_threads, [&](const GuestThread& t) { return pthread_equal(t.th, th); });
}

void stop_guest_threads() {
    dbt_request_shutdown();
    std::vector<GuestThread> copy;
    {
        std::lock_guard<std::mutex> lock(g_thr_mu);
        for (GuestThread& t : g_guest_threads)
            if (t.guest) t.guest->stop = 1;
        copy = g_guest_threads;
    }
    for (GuestThread& t : copy) {
        if (pthread_equal(t.th, pthread_self())) continue;
        pthread_join(t.th, nullptr);
    }
    std::lock_guard<std::mutex> lock(g_thr_mu);
    g_guest_threads.clear();
}

void* thread_tramp(void* raw) {
    auto* t = static_cast<ThreadStart*>(raw);
    Guest g;
    g.pc = t->func;
    g.x[0] = t->arg;
    g.x[30] = g_exit_shim;
    g.sp = t->stack;
    note_guest_thread(pthread_self(), &g);
    install_handler();
    g_cur = &g;
    if (sigsetjmp(g_jmp, 1) != 0) {
        g_armed = 0;
        std::fprintf(stderr, "guest thread fault pc=0x%llx\n", static_cast<unsigned long long>(g_fault_pc));
        forget_guest_thread(pthread_self());
        delete t;
        return nullptr;
    }
    g_armed = 1;
    dbt_run(g, 50000000);
    g_armed = 0;
    forget_guest_thread(pthread_self());
    delete t;
    return reinterpret_cast<void*>(g.x[0]);
}

struct GuestMutex {
    pthread_mutex_t mu = PTHREAD_MUTEX_INITIALIZER;
};
struct GuestOnce {
    std::atomic<int> state {0};
};

std::map<uint64_t, std::vector<uint8_t>> g_dirents;

void sh_unknown(Guest& g) {
    const char* name = shim_name_at(g.pc);
    if (!name) name = "?";
    note_unknown(name);
    if (name[0] == '_' && name[1] != '_' && (std::strstr(name, "Create") || std::strstr(name, "Copy"))) {
        if (std::strstr(name, "Name") || std::strstr(name, "String")) {
            g.x[0] = make_string(name);
            return;
        }
        g.x[0] = reinterpret_cast<uint64_t>(std::calloc(1, 64));
        return;
    }
    // Constructors and destructors return void. Leave the object pointer in x0.
    if (std::strstr(name, "C1E") || std::strstr(name, "C2E") || std::strstr(name, "C3E") ||
        std::strstr(name, "D0E") || std::strstr(name, "D1E") || std::strstr(name, "D2E"))
        return;
    g.x[0] = 0;
}

void sh_localeconv(Guest& g) {
    struct Lconv {
        uint64_t decimal_point;
        uint64_t thousands_sep;
        uint64_t grouping;
        uint64_t int_curr_symbol;
        uint64_t currency_symbol;
        uint64_t mon_decimal_point;
        uint64_t mon_thousands_sep;
        uint64_t mon_grouping;
        uint64_t positive_sign;
        uint64_t negative_sign;
        char flags[8];
    };
    static Lconv lc {};
    static const char dot[] = ".";
    static const char empty[] = "";
    if (!lc.decimal_point) {
        uint64_t d = reinterpret_cast<uint64_t>(dot);
        uint64_t e = reinterpret_cast<uint64_t>(empty);
        lc.decimal_point = d;
        lc.thousands_sep = e;
        lc.grouping = e;
        lc.int_curr_symbol = e;
        lc.currency_symbol = e;
        lc.mon_decimal_point = e;
        lc.mon_thousands_sep = e;
        lc.mon_grouping = e;
        lc.positive_sign = e;
        lc.negative_sign = e;
        std::memset(lc.flags, 127, sizeof lc.flags);
    }
    g.x[0] = reinterpret_cast<uint64_t>(&lc);
}

uint64_t make_vtable(const std::string& name);

// The inlined extractor loads the pointer at filebuf+24 and then reads a
// pointer pair at +24 of that object (current, end). The bytes live in the
// object; filebuf+24 points at the object.
struct GetArea {
    uint64_t vptr;
    uint64_t locale;
    uint64_t eback;
    uint64_t gptr;
    uint64_t egptr;
};

bool guest_mapped(uint64_t addr, size_t n);
std::map<uint64_t, FILE*> g_files;

uint64_t filebuf_vtable() {
    uint64_t vt = make_vtable("__ZTVNSt3__113basic_filebufIcNS_11char_traitsIcEEEE");
    auto* slots = reinterpret_cast<uint64_t*>(vt);
    slots[12] = resolve_symbol("___lb_streambuf_eof", 0);
    return vt;
}

uint64_t make_get_area(const char* bytes, size_t n) {
    auto* area = static_cast<GetArea*>(std::calloc(1, sizeof(GetArea)));
    char* buf = static_cast<char*>(std::malloc(n + 1));
    if (bytes && n) std::memcpy(buf, bytes, n);
    buf[n] = 0;
    area->vptr = filebuf_vtable() + 16;
    area->eback = reinterpret_cast<uint64_t>(buf);
    area->gptr = area->eback;
    area->egptr = area->eback + n;
    return reinterpret_cast<uint64_t>(area);
}

void arm_filebuf(uint64_t self) {
    write_u64(self + 0, filebuf_vtable() + 16);
    uint64_t area = make_get_area("", 0);
    write_u64(self + 16, area);
    write_u64(self + 24, area);
    write_u64(self + 32, area);
}

void sh_streambuf_eof(Guest& g) { g.x[0] = ~0ull; }

void sh_filebuf_ctor(Guest& g) { arm_filebuf(g.x[0]); }

void sh_next_prime(Guest& g) {
    uint64_t n = g.x[0] < 2 ? 2 : g.x[0];
    auto is_prime = [](uint64_t x) {
        if (x < 2) return false;
        if ((x & 1ull) == 0) return x == 2;
        for (uint64_t d = 3; d <= x / d; d += 2)
            if (x % d == 0) return false;
        return true;
    };
    while (n < (1ull << 32) && !is_prime(n)) ++n;
    g.x[0] = n;
}

struct ClassicCtype {
    uint64_t word0 = 1;
    uint64_t word8 = 0;
    uint32_t* table = nullptr;
    uint32_t masks[256]{};
};

void sh_facet_call(Guest& g) {
    uint64_t out = tbi(g.x[8]);
    uint64_t begin = tbi(g.x[1]);
    uint64_t end = tbi(g.x[2]);
    if (out < 0x10000 || begin < 0x10000 || end < begin || end - begin > 22) return;
    uint8_t buf[24]{};
    size_t n = static_cast<size_t>(end - begin);
    std::memcpy(buf, reinterpret_cast<void*>(begin), n);
    buf[23] = static_cast<uint8_t>(n);
    std::memcpy(reinterpret_cast<void*>(out), buf, 24);
}

ClassicCtype& classic_ctype() {
    static ClassicCtype* c = nullptr;
    if (!c) {
        c = new ClassicCtype();
        c->table = c->masks;
        auto* vt = new uint64_t[8]{};
        uint64_t fn = 0;
        auto it = g_shim_by_name.find("__lb_facet_call");
        if (it != g_shim_by_name.end()) fn = g_shims[it->second].addr;
        for (int i = 0; i < 8; ++i) vt[i] = fn;
        c->word0 = reinterpret_cast<uint64_t>(vt);
    }
    return *c;
}

void ensure_locale(uint64_t obj) {
    obj = tbi(obj);
    if (obj < 0x10000) return;
    uint64_t imp = reinterpret_cast<uint64_t>(&classic_ctype());
    uint64_t word = 0;
    std::memcpy(&word, reinterpret_cast<void*>(obj), 8);
    if (!word) std::memcpy(reinterpret_cast<void*>(obj), &imp, 8);
    std::memcpy(&word, reinterpret_cast<void*>(obj + 8), 8);
    if (!word) std::memcpy(reinterpret_cast<void*>(obj + 8), &imp, 8);
}

void sh_locale_ctor(Guest& g) { ensure_locale(g.x[0]); }

void sh_locale_copy(Guest& g) {
    uint64_t dst = tbi(g.x[0]);
    uint64_t src = tbi(g.x[1]);
    if (dst < 0x10000) return;
    uint64_t words[2]{};
    if (src > 0x10000) std::memcpy(words, reinterpret_cast<void*>(src), 16);
    if (words[0] || words[1]) std::memcpy(reinterpret_cast<void*>(dst), words, 16);
    ensure_locale(dst);
}

void sh_locale_dtor(Guest&) {}

void sh_use_facet(Guest& g) {
    ensure_locale(g.x[0]);
    g.x[0] = reinterpret_cast<uint64_t>(&classic_ctype());
}

void sh_locale_name(Guest& g) {
    uint64_t out = tbi(g.x[8]);
    if (out < 0x10000) return;
    uint8_t buf[24]{};
    buf[0] = 'C';
    buf[23] = 1;
    std::memcpy(reinterpret_cast<void*>(out), buf, 24);
}

void sh_ios_init(Guest& g) {
    // basic_ios keeps the streambuf pointer at +40 and rdstate at +32.
    write_u64(g.x[0] + 40, g.x[1]);
    write_u64(g.x[0] + 8, g.x[1]);
    uint32_t good = 0;
    std::memcpy(reinterpret_cast<void*>(tbi(g.x[0] + 32)), &good, 4);
}

void sh_ios_clear(Guest& g) {
    uint32_t st = static_cast<uint32_t>(g.x[1]);
    std::memcpy(reinterpret_cast<void*>(tbi(g.x[0] + 32)), &st, 4);
    g.x[0] = 0;
}

void sh_filebuf_open(Guest& g) {
    const char* path = guest_cstr(g.x[1]);
    unsigned mode = static_cast<unsigned>(g.x[2]);
    const char* how = "rb";
    bool in = mode & 0x08;
    bool out = mode & 0x10;
    bool app = mode & 0x01;
    bool trunc = mode & 0x20;
    if (in && out) how = "r+b";
    else if (out && app) how = "ab";
    else if (out || trunc) how = "wb";
    else if (in) how = "rb";
    std::string opened = path ? path : "";
    auto mkdir_parents = [](const std::string& file) {
        std::string cur;
        for (size_t i = 0; i < file.size(); ++i) {
            if (file[i] == '/' && cur.size() > 1) ::mkdir(cur.c_str(), 0755);
            cur.push_back(file[i]);
        }
    };
    if (!opened.empty()) mkdir_parents(opened);
    FILE* f = (!opened.empty()) ? std::fopen(opened.c_str(), how) : nullptr;
    if (!f && !opened.empty() && opened.size() >= 11 && opened.compare(opened.size() - 11, 11, "config.json") == 0) {
        // The app throws if its settings file is missing. A small JSON document
        // keeps startup on the path that reads lyrics instead of aborting.
        static const char kDefaultConfig[] =
            "{\n"
            "  \"lyricsRootPath\": \"/tmp/lyricsblossom-data/Lyrics\",\n"
            "  \"dbPath\": \"/tmp/lyricsblossom-data/lyrics_index.db\",\n"
            "  \"useSqlite\": false,\n"
            "  \"windowX\": 80,\n"
            "  \"windowY\": 80,\n"
            "  \"windowWidth\": 1280,\n"
            "  \"windowHeight\": 720,\n"
            "  \"miniMode\": false,\n"
            "  \"miniWindowWidth\": 480,\n"
            "  \"miniWindowHeight\": 160,\n"
            "  \"miniAlwaysOnTop\": false\n"
            "}\n";
        ::mkdir("/tmp/lyricsblossom-data", 0755);
        ::mkdir("/tmp/lyricsblossom-data/Lyrics", 0755);
        std::string dest = opened;
        if (opened.find('/') == std::string::npos) dest = "/tmp/lyricsblossom-data/config.json";
        if (FILE* out = std::fopen(dest.c_str(), "wb")) {
            std::fwrite(kDefaultConfig, 1, sizeof(kDefaultConfig) - 1, out);
            std::fclose(out);
        }
        f = std::fopen(dest.c_str(), how);
        if (f) opened = dest;
    }
    if (!f) {
        g.x[0] = 0;
        return;
    }
    std::fseek(f, 0, SEEK_END);
    long n = std::ftell(f);
    std::fseek(f, 0, SEEK_SET);
    if (n < 0) n = 0;
    auto* buf = static_cast<char*>(std::malloc(static_cast<size_t>(n) + 1));
    if (!buf) {
        std::fclose(f);
        g.x[0] = 0;
        return;
    }
    size_t got = n ? std::fread(buf, 1, static_cast<size_t>(n), f) : 0;
    std::fclose(f);
    buf[got] = 0;
    uint64_t area = make_get_area(buf, got);
    std::free(buf);
    write_u64(g.x[0] + 0, filebuf_vtable() + 16);
    write_u64(g.x[0] + 16, area);
    write_u64(g.x[0] + 24, area);
    write_u64(g.x[0] + 32, area);
}

void sh_filebuf_xsputn(Guest& g) {
    auto it = g_files.find(g.x[0]);
    FILE* f = it == g_files.end() ? nullptr : it->second;
    uint64_t n = g.x[2];
    if (f && g.x[1] > 0x10000 && n > 0 && n < (1u << 20) && guest_mapped(g.x[1], static_cast<size_t>(n))) {
        g.x[0] = std::fwrite(reinterpret_cast<void*>(tbi(g.x[1])), 1, static_cast<size_t>(n), f);
        std::fflush(f);
        return;
    }
    if (f && g.x[1] < 0x10000) {
        unsigned char c = static_cast<unsigned char>(g.x[1]);
        std::fputc(c, f);
        std::fflush(f);
        g.x[0] = c;
        return;
    }
    g.x[0] = n ? n : 1;
}

void sh_nop(Guest&) {}

bool guest_string_long(const uint8_t raw[24]) { return (raw[23] & 0x80) != 0; }

bool guest_mapped(uint64_t addr, size_t n) {
    addr = tbi(addr);
    if (addr < 0x10000 || n == 0) return false;
    uintptr_t page = addr & ~uintptr_t{0xfff};
    uintptr_t last = (addr + n - 1) & ~uintptr_t{0xfff};
    for (uintptr_t p = page; p <= last; p += 4096) {
        unsigned char vec = 0;
        if (mincore(reinterpret_cast<void*>(p), 4096, &vec) != 0 || (vec & 1) == 0) return false;
    }
    return true;
}

std::string read_guest_string(uint64_t obj) {
    obj = tbi(obj);
    if (!guest_mapped(obj, 24)) return {};
    uint8_t raw[24]{};
    std::memcpy(raw, reinterpret_cast<void*>(obj), 24);
    if (!guest_string_long(raw)) {
        size_t n = raw[23];
        if (n > 22) return {};
        return std::string(reinterpret_cast<char*>(raw), n);
    }
    uint64_t ptr = 0, sz = 0;
    std::memcpy(&ptr, raw, 8);
    std::memcpy(&sz, raw + 8, 8);
    ptr = tbi(ptr);
    if (!guest_mapped(ptr, static_cast<size_t>(sz > (1u << 20) ? 0 : sz == 0 ? 1 : sz)) || sz > (1u << 20)) return {};
    return std::string(reinterpret_cast<char*>(ptr), static_cast<size_t>(sz));
}

void write_guest_string(uint64_t obj, const std::string& s) {
    obj = tbi(obj);
    if (!guest_mapped(obj, 24)) return;
    uint8_t raw[24]{};
    if (s.size() <= 22) {
        if (!s.empty()) std::memcpy(raw, s.data(), s.size());
        raw[23] = static_cast<uint8_t>(s.size());
    } else {
        auto* buf = static_cast<char*>(std::malloc(s.size() + 1));
        std::memcpy(buf, s.data(), s.size());
        buf[s.size()] = 0;
        uint64_t ptr = reinterpret_cast<uint64_t>(buf);
        uint64_t sz = s.size();
        uint64_t cap = (sz + 1) | (1ull << 63);
        std::memcpy(raw, &ptr, 8);
        std::memcpy(raw + 8, &sz, 8);
        std::memcpy(raw + 16, &cap, 8);
    }
    std::memcpy(reinterpret_cast<void*>(obj), raw, 24);
}

void sh_to_string(Guest& g, bool hex_unsigned) {
    char buf[32];
    if (hex_unsigned) std::snprintf(buf, sizeof buf, "%llu", static_cast<unsigned long long>(g.x[0]));
    else std::snprintf(buf, sizeof buf, "%d", static_cast<int>(g.x[0]));
    if (guest_mapped(g.x[8], 24)) write_guest_string(g.x[8], buf);
}

void sh_runtime_error(Guest& g) {
    if (!guest_mapped(g.x[1], 1)) return;
    const char* msg = reinterpret_cast<const char*>(tbi(g.x[1]));
    if (msg[0] < 32 || msg[0] >= 127) return;
    std::fprintf(stderr, "runtime_error: %s\n", msg);
}

void sh_runtime_error_copy(Guest&) {}

void sh_to_string_int(Guest& g) { sh_to_string(g, false); }
void sh_to_string_ulong(Guest& g) { sh_to_string(g, true); }

void sh_string_push(Guest& g) {
    if (g.x[0] < 0x10000) return;
    std::string s = read_guest_string(g.x[0]);
    s.push_back(static_cast<char>(g.x[1]));
    write_guest_string(g.x[0], s);
}

void sh_steady_now(Guest& g) {
    timespec ts {};
    clock_gettime(CLOCK_MONOTONIC, &ts);
    g.x[0] = static_cast<uint64_t>(ts.tv_sec) * 1000000000ull + static_cast<uint64_t>(ts.tv_nsec);
}

void sh_fs_status(Guest& g) {
    std::string path = read_guest_string(g.x[0]);
    struct stat st {};
    int8_t type = -1;
    uint32_t perms = 0;
    if (!path.empty() && ::stat(path.c_str(), &st) == 0) {
        if (S_ISREG(st.st_mode)) type = 1;
        else if (S_ISDIR(st.st_mode)) type = 2;
        else if (S_ISLNK(st.st_mode)) type = 3;
        else type = 8;
        perms = static_cast<uint32_t>(st.st_mode) & 0777u;
    }
    uint64_t word = static_cast<uint32_t>(type);
    word |= static_cast<uint64_t>(perms) << 32;
    g.x[0] = word;
    if (g.x[8] > 0x10000) std::memcpy(reinterpret_cast<void*>(tbi(g.x[8])), &word, 8);
    if (g.x[1] > 0x10000) {
        int32_t zero = 0;
        std::memcpy(reinterpret_cast<void*>(tbi(g.x[1])), &zero, 4);
    }
}

void sh_fs_cwd(Guest& g) {
    char buf[4096];
    if (!::getcwd(buf, sizeof buf)) std::snprintf(buf, sizeof buf, "/tmp");
    if (g.x[8] > 0x10000) write_guest_string(g.x[8], buf);
    if (g.x[0] > 0x10000) {
        int32_t zero = 0;
        std::memcpy(reinterpret_cast<void*>(tbi(g.x[0])), &zero, 4);
    }
}

void sh_fs_root(Guest& g) {
    std::string path = read_guest_string(g.x[0]);
    if (g.x[8] > 0x10000) write_guest_string(g.x[8], (!path.empty() && path[0] == '/') ? "/" : "");
}

void sh_fs_parent(Guest& g) {
    std::string path = read_guest_string(g.x[0]);
    std::string parent;
    auto slash = path.find_last_of('/');
    if (slash != std::string::npos) parent = slash == 0 ? "/" : path.substr(0, slash);
    if (g.x[8] > 0x10000) write_guest_string(g.x[8], parent);
}

void sh_fs_mkdirs(Guest& g) {
    std::string path = read_guest_string(g.x[0]);
    std::string cur;
    for (size_t i = 0; i < path.size(); ++i) {
        cur.push_back(path[i]);
        if ((path[i] == '/' || i + 1 == path.size()) && cur.size() > 1) ::mkdir(cur.c_str(), 0755);
    }
    if (g.x[1] > 0x10000 && guest_mapped(g.x[1], 4)) {
        int32_t zero = 0;
        std::memcpy(reinterpret_cast<void*>(tbi(g.x[1])), &zero, 4);
    }
    g.x[0] = 1;
}

void sh_fs_rename(Guest& g) {
    std::string from = read_guest_string(g.x[0]);
    std::string to = read_guest_string(g.x[1]);
    if (!from.empty() && !to.empty()) {
        struct stat src {}, dst {};
        bool src_ok = ::stat(from.c_str(), &src) == 0;
        bool dst_ok = ::stat(to.c_str(), &dst) == 0;
        // An empty temporary must not replace a file that already has contents.
        if (!(src_ok && src.st_size == 0 && dst_ok && dst.st_size > 0)) ::rename(from.c_str(), to.c_str());
    }
    if (g.x[2] > 0x10000 && guest_mapped(g.x[2], 4)) {
        int32_t zero = 0;
        std::memcpy(reinterpret_cast<void*>(tbi(g.x[2])), &zero, 4);
    }
    g.x[0] = 0;
}

void sh_string_grow(Guest& g) {
    std::string old = read_guest_string(g.x[0]);
    size_t n_copy = static_cast<size_t>(g.x[4]);
    size_t n_del = static_cast<size_t>(g.x[5]);
    size_t n_add = static_cast<size_t>(g.x[6]);
    if (n_copy > old.size()) n_copy = old.size();
    if (n_add > (1u << 20)) n_add = 0;
    std::string neu = old.substr(0, n_copy);
    if (n_add && g.x[7] > 0x10000 && guest_mapped(g.x[7], n_add))
        neu.append(reinterpret_cast<char*>(tbi(g.x[7])), n_add);
    size_t tail = n_copy + n_del;
    if (tail < old.size()) neu.append(old, tail, std::string::npos);
    write_guest_string(g.x[0], neu);
}

void sh_system_category(Guest& g) {
    static uint64_t cat = 0;
    if (!cat) {
        uint64_t vt = make_vtable("__ZTVNSt3__114error_categoryE");
        uint64_t nop = resolve_symbol("__lb_nop", 0);
        auto* slots = reinterpret_cast<uint64_t*>(vt);
        for (int i = 2; i < 16; ++i) slots[i] = nop;
        cat = reinterpret_cast<uint64_t>(std::calloc(1, 32));
        write_u64(cat, vt + 16);
    }
    g.x[0] = cat;
}

void sh_sentry_ctor(Guest& g) {
    if (guest_mapped(g.x[0], 16)) {
        uint8_t ok = 1;
        std::memcpy(reinterpret_cast<void*>(tbi(g.x[0])), &ok, 1);
    }
}

std::map<uint64_t, int64_t> g_stream_pos;

struct HostArray;
HostArray* as_array(uint64_t p);
uint64_t host_array(std::initializer_list<uint64_t> items);

void sh_seekg(Guest& g) {
    int64_t off = static_cast<int64_t>(g.x[1]);
    int dir = static_cast<int>(g.x[2]);
    int64_t cur = g_stream_pos[g.x[0]];
    uint64_t area = 0;
    if (g.x[0] > 0x10000) {
        area = read_u64(g.x[0] + 24);
        if (area < 0x10000) area = read_u64(g.x[0] + 40);
    }
    int64_t len = 0;
    uint64_t base = 0;
    if (area > 0x10000) {
        base = read_u64(area + 16);
        uint64_t end = read_u64(area + 32);
        if (end >= base) len = static_cast<int64_t>(end - base);
    }
    int64_t pos = dir == 0 ? off : dir == 2 ? len + off : cur + off;
    if (pos < 0) pos = 0;
    if (len && pos > len) pos = len;
    g_stream_pos[g.x[0]] = pos;
    if (area > 0x10000 && base) write_u64(area + 24, base + static_cast<uint64_t>(pos));
}

void sh_tellg(Guest& g) {
    int64_t pos = g_stream_pos[g.x[0]];
    g.x[0] = static_cast<uint64_t>(pos);
    if (g.x[8] > 0x10000) {
        uint64_t buf[2] = {static_cast<uint64_t>(pos), 0};
        std::memcpy(reinterpret_cast<void*>(tbi(g.x[8])), buf, sizeof buf);
    }
}

uint64_t cf_dict() {
    uint64_t o = make_object("NSDictionary");
    payload(o).kind = 3;
    return o;
}

uint64_t cf_font() {
    uint64_t o = make_object("NSFont");
    payload(o).kind = 8;
    payload(o).str = "sans";
    return o;
}

std::string cf_text(uint64_t obj) {
    if (has_payload(obj)) return payload(obj).str;
    return {};
}

void sh_cf_get_type(Guest& g) {
    if (as_array(g.x[0])) {
        g.x[0] = 5;
        return;
    }
    if (!has_payload(g.x[0])) {
        g.x[0] = 0;
        return;
    }
    int k = payload(g.x[0]).kind;
    g.x[0] = k == 0 ? 1 : static_cast<uint64_t>(k);
}

void sh_cf_dict_type(Guest& g) { g.x[0] = 3; }

void sh_cf_dict_new(Guest& g) { g.x[0] = cf_dict(); }

void sh_cf_dict_add(Guest& g) {
    if (!has_payload(g.x[0])) return;
    payload(g.x[0]).props[cf_text(g.x[1])] = g.x[2];
}

void sh_cf_dict_get(Guest& g) {
    uint64_t dict = g.x[0];
    uint64_t key = g.x[1];
    uint64_t out = g.x[2];
    g.x[0] = 0;
    if (!has_payload(dict)) return;
    auto it = payload(dict).props.find(cf_text(key));
    if (it == payload(dict).props.end()) return;
    if (out > 0x10000) write_u64(out, it->second);
    g.x[0] = 1;
}

void sh_cf_number(Guest& g) {
    int64_t v = 0;
    if (g.x[2] > 0x10000) std::memcpy(&v, reinterpret_cast<void*>(tbi(g.x[2])), 8);
    uint64_t o = make_object("NSNumber");
    payload(o).kind = 4;
    payload(o).number = static_cast<double>(v);
    g.x[0] = o;
}

void sh_cf_data_create(Guest& g) {
    uint64_t n = g.x[2];
    if (n > (1u << 20)) n = 0;
    auto* buf = static_cast<uint8_t*>(std::malloc(n + 1));
    if (n && g.x[1] > 0x10000) std::memcpy(buf, reinterpret_cast<void*>(tbi(g.x[1])), n);
    buf[n] = 0;
    uint64_t o = make_object("NSData");
    payload(o).kind = 2;
    payload(o).props["ptr"] = reinterpret_cast<uint64_t>(buf);
    payload(o).props["len"] = n;
    g.x[0] = o;
}

void sh_cf_data_ptr(Guest& g) {
    g.x[0] = has_payload(g.x[0]) ? payload(g.x[0]).props["ptr"] : 0;
}

void sh_cf_set_create(Guest& g) {
    uint64_t o = make_object("NSSet");
    payload(o).kind = 6;
    g.x[0] = o;
}

void sh_cf_string_cmp(Guest& g) {
    std::string a = cf_text(g.x[0]);
    std::string b = cf_text(g.x[1]);
    g.x[0] = a < b ? ~0ull : a > b ? 1 : 0;
}

void sh_cf_url(Guest& g) {
    uint64_t o = make_string(cf_text(g.x[1]));
    payload(o).kind = 7;
    g.x[0] = o;
}

void sh_cf_url_path(Guest& g) {
    std::string path = cf_text(g.x[0]);
    if (path.empty()) path = "/tmp/lyricsblossom-data";
    if (g.x[2] > 0x10000 && g.x[3] > path.size()) {
        std::memcpy(reinterpret_cast<void*>(tbi(g.x[2])), path.c_str(), path.size() + 1);
        g.x[0] = 1;
    } else {
        g.x[0] = 0;
    }
}

void sh_cf_resources_url(Guest& g) {
    g.x[0] = make_string("/tmp/lyricsblossom-data");
    payload(g.x[0]).kind = 7;
}

void sh_cf_languages(Guest& g) { g.x[0] = host_array({make_string("zh-Hans"), make_string("en")}); }

void sh_ct_font(Guest& g) { g.x[0] = cf_font(); }

void sh_ct_families(Guest& g) {
    g.x[0] = host_array({make_string("sans"), make_string("PingFang SC"), make_string("Helvetica")});
}

void sh_ct_traits(Guest& g) { g.x[0] = 0; }

void sh_ct_register(Guest& g) { g.x[0] = 1; }

void sh_iopm(Guest& g) { g.x[0] = 0; }

void sh_display_service(Guest& g) { g.x[0] = 1; }

void sh_display_info(Guest& g) { g.x[0] = cf_dict(); }

void sh_thread_local_data(Guest& g) {
    static uint8_t* page = nullptr;
    if (!page) page = static_cast<uint8_t*>(std::calloc(1, 4096));
    g.x[0] = reinterpret_cast<uint64_t>(page);
}

void sh_ret0(Guest& g) { g.x[0] = 0; }
void sh_ret1(Guest& g) { g.x[0] = 1; }

void sh_malloc(Guest& g) {
    size_t n = g.x[0] ? g.x[0] : 1;
    g.x[0] = reinterpret_cast<uint64_t>(std::malloc(n));
}
void sh_calloc(Guest& g) {
    g.x[0] = reinterpret_cast<uint64_t>(std::calloc(g.x[0] ? g.x[0] : 1, g.x[1] ? g.x[1] : 1));
}
void sh_realloc(Guest& g) {
    g.x[0] = reinterpret_cast<uint64_t>(std::realloc(reinterpret_cast<void*>(tbi(g.x[0])), g.x[1]));
}
void sh_free(Guest& g) {
    if (g.x[0]) std::free(reinterpret_cast<void*>(tbi(g.x[0])));
}
void sh_malloc_size(Guest& g) { g.x[0] = g.x[0] ? 16 : 0; }
void sh_posix_memalign(Guest& g) {
    void* p = nullptr;
    size_t align = g.x[1] ? g.x[1] : 16;
    int rc = posix_memalign(&p, align, g.x[2] ? g.x[2] : 1);
    if (rc == 0 && g.x[0]) write_u64(g.x[0], reinterpret_cast<uint64_t>(p));
    g.x[0] = rc;
}

void sh_memcpy(Guest& g) {
    if (g.x[0] && g.x[1] && g.x[2]) std::memcpy(reinterpret_cast<void*>(tbi(g.x[0])), reinterpret_cast<void*>(tbi(g.x[1])), g.x[2]);
    g.x[0] = g.x[0];
}
void sh_memmove(Guest& g) {
    if (g.x[0] && g.x[2]) std::memmove(reinterpret_cast<void*>(tbi(g.x[0])), reinterpret_cast<void*>(tbi(g.x[1])), g.x[2]);
}
void sh_memset(Guest& g) {
    if (g.x[0] && g.x[2]) std::memset(reinterpret_cast<void*>(tbi(g.x[0])), static_cast<int>(g.x[1]), g.x[2]);
}
void sh_bzero(Guest& g) {
    if (g.x[0] && g.x[1]) std::memset(reinterpret_cast<void*>(tbi(g.x[0])), 0, g.x[1]);
}
void sh_memcmp(Guest& g) {
    g.x[0] = static_cast<uint64_t>(static_cast<int64_t>(
        std::memcmp(reinterpret_cast<void*>(tbi(g.x[0])), reinterpret_cast<void*>(tbi(g.x[1])), g.x[2])));
}
void sh_memchr(Guest& g) {
    void* p = g.x[0] ? std::memchr(reinterpret_cast<void*>(tbi(g.x[0])), static_cast<int>(g.x[1]), g.x[2]) : nullptr;
    g.x[0] = reinterpret_cast<uint64_t>(p);
}
void sh_strlen(Guest& g) { g.x[0] = g.x[0] ? std::strlen(guest_cstr(g.x[0])) : 0; }
void sh_strcmp(Guest& g) {
    const char* a = guest_cstr(g.x[0]);
    const char* b = guest_cstr(g.x[1]);
    g.x[0] = static_cast<uint64_t>(static_cast<int64_t>(std::strcmp(a ? a : "", b ? b : "")));
}
void sh_strncmp(Guest& g) {
    const char* a = guest_cstr(g.x[0]);
    const char* b = guest_cstr(g.x[1]);
    g.x[0] = static_cast<uint64_t>(static_cast<int64_t>(std::strncmp(a ? a : "", b ? b : "", g.x[2])));
}
void sh_strcpy(Guest& g) {
    if (g.x[0] && g.x[1]) std::strcpy(reinterpret_cast<char*>(tbi(g.x[0])), guest_cstr(g.x[1]));
}
void sh_strncpy(Guest& g) {
    if (g.x[0]) std::strncpy(reinterpret_cast<char*>(tbi(g.x[0])), guest_cstr(g.x[1]) ? guest_cstr(g.x[1]) : "", g.x[2]);
}
void sh_strcat(Guest& g) {
    if (g.x[0] && g.x[1]) std::strcat(reinterpret_cast<char*>(tbi(g.x[0])), guest_cstr(g.x[1]));
}
void sh_strdup(Guest& g) {
    const char* s = guest_cstr(g.x[0]);
    g.x[0] = reinterpret_cast<uint64_t>(::strdup(s ? s : ""));
}
void sh_strchr(Guest& g) {
    const char* s = guest_cstr(g.x[0]);
    char* p = s ? std::strchr(const_cast<char*>(s), static_cast<int>(g.x[1])) : nullptr;
    g.x[0] = reinterpret_cast<uint64_t>(p);
}
void sh_strrchr(Guest& g) {
    const char* s = guest_cstr(g.x[0]);
    char* p = s ? std::strrchr(const_cast<char*>(s), static_cast<int>(g.x[1])) : nullptr;
    g.x[0] = reinterpret_cast<uint64_t>(p);
}
void sh_strstr(Guest& g) {
    const char* a = guest_cstr(g.x[0]);
    const char* b = guest_cstr(g.x[1]);
    const char* p = (a && b) ? std::strstr(a, b) : nullptr;
    g.x[0] = reinterpret_cast<uint64_t>(p);
}
void sh_strnlen(Guest& g) {
    const char* s = guest_cstr(g.x[0]);
    g.x[0] = s ? ::strnlen(s, g.x[1]) : 0;
}
void sh_strerror(Guest& g) {
    g.x[0] = reinterpret_cast<uint64_t>(const_cast<char*>(std::strerror(static_cast<int>(g.x[0]))));
}
void sh_strtol(Guest& g) {
    const char* s = guest_cstr(g.x[0]);
    char* end = nullptr;
    long v = s ? std::strtol(s, &end, static_cast<int>(g.x[2])) : 0;
    if (g.x[1] && end) write_u64(g.x[1], reinterpret_cast<uint64_t>(end));
    g.x[0] = static_cast<uint64_t>(v);
}
void sh_strtoul(Guest& g) {
    const char* s = guest_cstr(g.x[0]);
    char* end = nullptr;
    unsigned long v = s ? std::strtoul(s, &end, static_cast<int>(g.x[2])) : 0;
    if (g.x[1] && end) write_u64(g.x[1], reinterpret_cast<uint64_t>(end));
    g.x[0] = v;
}
void sh_strtod(Guest& g) {
    const char* s = guest_cstr(g.x[0]);
    char* end = nullptr;
    double v = s ? std::strtod(s, &end) : 0;
    if (g.x[1] && end) write_u64(g.x[1], reinterpret_cast<uint64_t>(end));
    std::memcpy(g.v[0], &v, 8);
    g.x[0] = 0;
}
void sh_atoi(Guest& g) {
    const char* s = guest_cstr(g.x[0]);
    g.x[0] = static_cast<uint64_t>(static_cast<int64_t>(s ? std::atoi(s) : 0));
}
void sh_atof(Guest& g) {
    const char* s = guest_cstr(g.x[0]);
    double v = s ? std::atof(s) : 0;
    std::memcpy(g.v[0], &v, 8);
}

size_t em_strlcpy(char* d, const char* s, size_t n) {
    size_t len = std::strlen(s);
    if (n) {
        size_t c = std::min(len, n - 1);
        std::memcpy(d, s, c);
        d[c] = 0;
    }
    return len;
}
void sh_strlcpy(Guest& g) {
    char* d = reinterpret_cast<char*>(tbi(g.x[0]));
    const char* s = guest_cstr(g.x[1]);
    g.x[0] = (d && s) ? em_strlcpy(d, s, g.x[2]) : 0;
}
void sh_strlcat(Guest& g) {
    char* d = reinterpret_cast<char*>(tbi(g.x[0]));
    const char* s = guest_cstr(g.x[1]);
    if (!d || !s) {
        g.x[0] = 0;
        return;
    }
    size_t n = g.x[2];
    size_t dl = std::strlen(d);
    if (dl >= n) {
        g.x[0] = dl + std::strlen(s);
        return;
    }
    g.x[0] = dl + em_strlcpy(d + dl, s, n - dl);
}

void sh_chk_memcpy(Guest& g) { sh_memcpy(g); }
void sh_chk_memmove(Guest& g) { sh_memmove(g); }
void sh_chk_memset(Guest& g) { sh_memset(g); }
void sh_chk_strlcpy(Guest& g) { sh_strlcpy(g); }
void sh_chk_strlcat(Guest& g) { sh_strlcat(g); }

void sh_error(Guest& g) { g.x[0] = reinterpret_cast<uint64_t>(&g_dar_errno); }
void sh_chk_fail(Guest& g) {
    g.stop = 7;
    g.stop_why = "stack-chk";
    g.stop_pc = g.pc;
    g.redirect = true;
}
void sh_exit(Guest& g) {
    const char* who = shim_name_at(g.pc);
    std::fprintf(stderr, "guest %s(%lld) from %llx\n", who ? who : "exit",
                 static_cast<long long>(g.x[0]), static_cast<unsigned long long>(g.x[30]));
    g.stop = 1;
    g.stop_why = "exit";
    g.stop_insn = static_cast<uint32_t>(g.x[0]);
    g.redirect = true;
}
void sh_abort(Guest& g) {
    g.stop = 1;
    g.stop_why = "abort";
    g.redirect = true;
}

void sh_open(Guest& g) {
    const char* path = guest_cstr(g.x[0]);
    int fd = path ? ::open(path, map_open_flags(g.x[1]), static_cast<mode_t>(g.x[2])) : -1;
    if (fd < 0) set_guest_errno();
    g.x[0] = static_cast<uint64_t>(static_cast<int64_t>(fd));
}
void sh_close(Guest& g) {
    int rc = ::close(static_cast<int>(g.x[0]));
    if (rc < 0) set_guest_errno();
    g.x[0] = static_cast<uint64_t>(static_cast<int64_t>(rc));
}
void sh_read(Guest& g) {
    int fd = static_cast<int>(g.x[0]);
    if (boot_test()) {
        pollfd p {fd, POLLIN, 0};
        if (::poll(&p, 1, 0) <= 0) {
            errno = EAGAIN;
            set_guest_errno();
            g.x[0] = static_cast<uint64_t>(-1);
            return;
        }
    }
    ssize_t n = ::read(fd, reinterpret_cast<void*>(tbi(g.x[1])), g.x[2]);
    if (n < 0) set_guest_errno();
    g.x[0] = static_cast<uint64_t>(n);
}
void sh_write(Guest& g) {
    ssize_t n = ::write(static_cast<int>(g.x[0]), reinterpret_cast<void*>(tbi(g.x[1])), g.x[2]);
    if (n < 0) set_guest_errno();
    g.x[0] = static_cast<uint64_t>(n);
}
void sh_lseek(Guest& g) {
    off_t n = ::lseek(static_cast<int>(g.x[0]), static_cast<off_t>(g.x[1]), static_cast<int>(g.x[2]));
    if (n < 0) set_guest_errno();
    g.x[0] = static_cast<uint64_t>(n);
}
void sh_stat_common(Guest& g, int kind) {
    const char* path = guest_cstr(g.x[0]);
    struct stat st {};
    int rc = -1;
    if (kind == 0) rc = path ? ::stat(path, &st) : -1;
    if (kind == 1) rc = path ? ::lstat(path, &st) : -1;
    if (kind == 2) rc = ::fstat(static_cast<int>(g.x[0]), &st);
    if (rc == 0) {
        uint64_t dst = kind == 2 ? g.x[1] : g.x[1];
        if (dst) write_darwin_stat(reinterpret_cast<void*>(tbi(dst)), st);
    } else {
        set_guest_errno();
    }
    g.x[0] = static_cast<uint64_t>(static_cast<int64_t>(rc));
}
void sh_stat(Guest& g) { sh_stat_common(g, 0); }
void sh_lstat(Guest& g) { sh_stat_common(g, 1); }
void sh_fstat(Guest& g) { sh_stat_common(g, 2); }

void sh_access(Guest& g) {
    const char* path = guest_cstr(g.x[0]);
    int rc = path ? ::access(path, static_cast<int>(g.x[1])) : -1;
    if (rc < 0) set_guest_errno();
    g.x[0] = static_cast<uint64_t>(static_cast<int64_t>(rc));
}
void sh_mkdir(Guest& g) {
    const char* path = guest_cstr(g.x[0]);
    int rc = path ? ::mkdir(path, static_cast<mode_t>(g.x[1] ? g.x[1] : 0755)) : -1;
    if (rc < 0) set_guest_errno();
    g.x[0] = static_cast<uint64_t>(static_cast<int64_t>(rc));
}
void sh_unlink(Guest& g) {
    const char* path = guest_cstr(g.x[0]);
    int rc = path ? ::unlink(path) : -1;
    if (rc < 0) set_guest_errno();
    g.x[0] = static_cast<uint64_t>(static_cast<int64_t>(rc));
}
void sh_rename(Guest& g) {
    const char* a = guest_cstr(g.x[0]);
    const char* b = guest_cstr(g.x[1]);
    int rc = (a && b) ? ::rename(a, b) : -1;
    if (rc < 0) set_guest_errno();
    g.x[0] = static_cast<uint64_t>(static_cast<int64_t>(rc));
}
void sh_getcwd(Guest& g) {
    char* p = ::getcwd(reinterpret_cast<char*>(tbi(g.x[0])), g.x[1]);
    if (!p) set_guest_errno();
    g.x[0] = reinterpret_cast<uint64_t>(p);
}
void sh_chdir(Guest& g) {
    const char* path = guest_cstr(g.x[0]);
    int rc = path ? ::chdir(path) : -1;
    if (rc < 0) set_guest_errno();
    g.x[0] = static_cast<uint64_t>(static_cast<int64_t>(rc));
}
void sh_readlink(Guest& g) {
    const char* path = guest_cstr(g.x[0]);
    ssize_t n = path ? ::readlink(path, reinterpret_cast<char*>(tbi(g.x[1])), g.x[2]) : -1;
    if (n < 0) set_guest_errno();
    g.x[0] = static_cast<uint64_t>(n);
}
void sh_realpath(Guest& g) {
    const char* path = guest_cstr(g.x[0]);
    char* out = g.x[1] ? reinterpret_cast<char*>(tbi(g.x[1])) : nullptr;
    char* p = path ? ::realpath(path, out) : nullptr;
    if (!p) set_guest_errno();
    g.x[0] = reinterpret_cast<uint64_t>(p);
}

void sh_mmap(Guest& g) {
    int flags = map_mmap_flags(g.x[3]);
    int fd = (flags & MAP_ANONYMOUS) ? -1 : static_cast<int>(g.x[4]);
    void* want = g.x[0] ? reinterpret_cast<void*>(tbi(g.x[0])) : nullptr;
    void* p = ::mmap(want, g.x[1], static_cast<int>(g.x[2]), flags, fd, static_cast<off_t>(g.x[5]));
    if (p == MAP_FAILED && (flags & MAP_FIXED)) {
        flags &= ~MAP_FIXED;
        p = ::mmap(nullptr, g.x[1], static_cast<int>(g.x[2]), flags, fd, static_cast<off_t>(g.x[5]));
    }
    if (p == MAP_FAILED) {
        set_guest_errno();
        g.x[0] = static_cast<uint64_t>(-1);
        return;
    }
    g.x[0] = reinterpret_cast<uint64_t>(p);
}
void sh_munmap(Guest& g) {
    int rc = ::munmap(reinterpret_cast<void*>(tbi(g.x[0])), g.x[1]);
    if (rc < 0) set_guest_errno();
    g.x[0] = static_cast<uint64_t>(static_cast<int64_t>(rc));
}
void sh_mprotect(Guest& g) {
    int rc = ::mprotect(reinterpret_cast<void*>(tbi(g.x[0])), g.x[1], static_cast<int>(g.x[2]));
    if (rc < 0) set_guest_errno();
    g.x[0] = static_cast<uint64_t>(static_cast<int64_t>(rc));
}

void sh_getenv(Guest& g) {
    const char* n = guest_cstr(g.x[0]);
    const char* v = n ? std::getenv(n) : nullptr;
    g.x[0] = reinterpret_cast<uint64_t>(v);
}
void sh_setenv(Guest& g) {
    const char* n = guest_cstr(g.x[0]);
    const char* v = guest_cstr(g.x[1]);
    int rc = (n && v) ? ::setenv(n, v, static_cast<int>(g.x[2])) : -1;
    if (rc < 0) set_guest_errno();
    g.x[0] = static_cast<uint64_t>(static_cast<int64_t>(rc));
}
void sh_unsetenv(Guest& g) {
    const char* n = guest_cstr(g.x[0]);
    int rc = n ? ::unsetenv(n) : -1;
    g.x[0] = static_cast<uint64_t>(static_cast<int64_t>(rc));
}

void sh_printf(Guest& g) {
    char buf[2048];
    const char* fmt = guest_cstr(g.x[0]);
    int n = guest_format(buf, sizeof(buf), fmt ? fmt : "", g, 1, 0);
    if (n > 0) std::fputs(buf, stdout);
    g.x[0] = static_cast<uint64_t>(n);
}
void sh_fprintf(Guest& g) {
    char buf[2048];
    const char* fmt = guest_cstr(g.x[1]);
    int n = guest_format(buf, sizeof(buf), fmt ? fmt : "", g, 2, 0);
    FILE* fp = reinterpret_cast<FILE*>(tbi(g.x[0]));
    if (fp && n > 0) std::fputs(buf, fp);
    g.x[0] = static_cast<uint64_t>(n);
}
void sh_snprintf(Guest& g) {
    char tmp[4096];
    const char* fmt = guest_cstr(g.x[2]);
    int n = guest_format(tmp, sizeof(tmp), fmt ? fmt : "", g, 3, 0);
    if (g.x[0] && g.x[1]) {
        size_t cap = g.x[1];
        size_t c = std::min(static_cast<size_t>(n), cap ? cap - 1 : 0);
        std::memcpy(reinterpret_cast<void*>(tbi(g.x[0])), tmp, c);
        if (cap) reinterpret_cast<char*>(tbi(g.x[0]))[c] = 0;
    }
    g.x[0] = static_cast<uint64_t>(n);
}
void sh_puts(Guest& g) {
    const char* s = guest_cstr(g.x[0]);
    g.x[0] = static_cast<uint64_t>(std::puts(s ? s : ""));
}

void sh_fopen(Guest& g) {
    const char* path = guest_cstr(g.x[0]);
    const char* mode = guest_cstr(g.x[1]);
    FILE* fp = (path && mode) ? std::fopen(path, mode) : nullptr;
    if (!fp) set_guest_errno();
    g.x[0] = reinterpret_cast<uint64_t>(fp);
}
void sh_fclose(Guest& g) {
    FILE* fp = reinterpret_cast<FILE*>(tbi(g.x[0]));
    g.x[0] = static_cast<uint64_t>(fp ? std::fclose(fp) : -1);
}
void sh_fread(Guest& g) {
    FILE* fp = reinterpret_cast<FILE*>(tbi(g.x[3]));
    size_t n = fp ? std::fread(reinterpret_cast<void*>(tbi(g.x[0])), g.x[1] ? g.x[1] : 1, g.x[2], fp) : 0;
    g.x[0] = n;
}
void sh_fwrite(Guest& g) {
    FILE* fp = reinterpret_cast<FILE*>(tbi(g.x[3]));
    size_t n = fp ? std::fwrite(reinterpret_cast<void*>(tbi(g.x[0])), g.x[1] ? g.x[1] : 1, g.x[2], fp) : 0;
    g.x[0] = n;
}
void sh_fseek(Guest& g) {
    FILE* fp = reinterpret_cast<FILE*>(tbi(g.x[0]));
    g.x[0] = static_cast<uint64_t>(fp ? std::fseek(fp, static_cast<long>(g.x[1]), static_cast<int>(g.x[2])) : -1);
}
void sh_ftell(Guest& g) {
    FILE* fp = reinterpret_cast<FILE*>(tbi(g.x[0]));
    long n = fp ? std::ftell(fp) : -1;
    g.x[0] = static_cast<uint64_t>(n);
}
void sh_fflush(Guest& g) {
    FILE* fp = g.x[0] ? reinterpret_cast<FILE*>(tbi(g.x[0])) : nullptr;
    g.x[0] = static_cast<uint64_t>(std::fflush(fp));
}
void sh_feof(Guest& g) {
    FILE* fp = reinterpret_cast<FILE*>(tbi(g.x[0]));
    g.x[0] = fp && std::feof(fp) ? 1 : 0;
}
void sh_ferror(Guest& g) {
    FILE* fp = reinterpret_cast<FILE*>(tbi(g.x[0]));
    g.x[0] = fp && std::ferror(fp) ? 1 : 0;
}
void sh_fileno(Guest& g) {
    FILE* fp = reinterpret_cast<FILE*>(tbi(g.x[0]));
    g.x[0] = static_cast<uint64_t>(static_cast<int64_t>(fp ? fileno(fp) : -1));
}
void sh_fgets(Guest& g) {
    FILE* fp = reinterpret_cast<FILE*>(tbi(g.x[2]));
    char* p = (fp && g.x[0]) ? std::fgets(reinterpret_cast<char*>(tbi(g.x[0])), static_cast<int>(g.x[1]), fp) : nullptr;
    g.x[0] = reinterpret_cast<uint64_t>(p);
}

void sh_pipe(Guest& g) {
    int fds[2] {-1, -1};
    int rc = ::pipe(fds);
    if (rc == 0 && g.x[0]) {
        int32_t out[2] = {fds[0], fds[1]};
        std::memcpy(reinterpret_cast<void*>(tbi(g.x[0])), out, 8);
    } else if (rc < 0) {
        set_guest_errno();
    }
    g.x[0] = static_cast<uint64_t>(static_cast<int64_t>(rc));
}
void sh_dup2(Guest& g) {
    int rc = ::dup2(static_cast<int>(g.x[0]), static_cast<int>(g.x[1]));
    if (rc < 0) set_guest_errno();
    g.x[0] = static_cast<uint64_t>(static_cast<int64_t>(rc));
}
void sh_fcntl(Guest& g) {
    int fd = static_cast<int>(g.x[0]);
    int cmd = static_cast<int>(g.x[1]);
    int rc = ::fcntl(fd, cmd, g.x[2]);
    if (rc < 0) set_guest_errno();
    g.x[0] = static_cast<uint64_t>(static_cast<int64_t>(rc));
}

void sh_fa_init(Guest& g) {
    auto* a = new FileActs;
    if (g.x[0]) write_u64(g.x[0], reinterpret_cast<uint64_t>(a));
    g.x[0] = 0;
}
void sh_fa_dup2(Guest& g) {
    FileActs* a = acts_from(g.x[0]);
    if (a && a->ndup < 16) a->dups[a->ndup++] = {static_cast<int>(g.x[1]), static_cast<int>(g.x[2])};
    g.x[0] = 0;
}
void sh_fa_close(Guest& g) {
    FileActs* a = acts_from(g.x[0]);
    if (a && a->nclose < 8) a->closes[a->nclose++] = static_cast<int>(g.x[1]);
    g.x[0] = 0;
}
void sh_fa_destroy(Guest& g) {
    FileActs* a = acts_from(g.x[0]);
    delete a;
    g.x[0] = 0;
}
void sh_spawnattr_init(Guest& g) {
    if (g.x[0]) write_u64(g.x[0], 1);
    g.x[0] = 0;
}
void sh_spawnattr_destroy(Guest& g) { g.x[0] = 0; }

void do_spawn(Guest& g, bool search) {
    const char* path = guest_cstr(g.x[1]);
    FileActs* acts = acts_from(g.x[2]);
    std::vector<std::string> args = read_str_array(g.x[4]);
    SpawnPlan plan = plan_spawn(path ? path : "", args);
    std::string exe = plan.bridge ? bridge_executable() : (path ? path : "");
    const std::vector<std::string>& use = plan.bridge ? plan.argv : args;
    std::vector<std::string> store = use.empty() ? std::vector<std::string> {exe} : use;
    std::vector<char*> ptrs;
    ptrs.reserve(store.size() + 1);
    for (auto& s : store) ptrs.push_back(s.data());
    ptrs.push_back(nullptr);
    posix_spawn_file_actions_t fa;
    posix_spawn_file_actions_init(&fa);
    if (acts) {
        for (int i = 0; i < acts->ndup; ++i) posix_spawn_file_actions_adddup2(&fa, acts->dups[i].from, acts->dups[i].to);
        for (int i = 0; i < acts->nclose; ++i) posix_spawn_file_actions_addclose(&fa, acts->closes[i]);
    }
    pid_t pid = 0;
    int rc = search ? posix_spawnp(&pid, exe.c_str(), &fa, nullptr, ptrs.data(), environ)
                    : posix_spawn(&pid, exe.c_str(), &fa, nullptr, ptrs.data(), environ);
    posix_spawn_file_actions_destroy(&fa);
    if (rc != 0) {
        g_dar_errno = to_darwin_errno(rc);
        g.x[0] = static_cast<uint64_t>(rc);
        return;
    }
    if (g.x[0]) {
        int32_t p = pid;
        std::memcpy(reinterpret_cast<void*>(tbi(g.x[0])), &p, 4);
    }
    if (tracing() || plan.bridge) std::fprintf(stderr, "spawn %s pid %d\n", exe.c_str(), pid);
    g.x[0] = 0;
}
void sh_posix_spawn(Guest& g) { do_spawn(g, false); }
void sh_posix_spawnp(Guest& g) { do_spawn(g, true); }

void sh_fork(Guest& g) {
    pid_t p = ::fork();
    if (p < 0) set_guest_errno();
    g.x[0] = static_cast<uint64_t>(static_cast<int64_t>(p));
}
void sh_waitpid(Guest& g) {
    int st = 0;
    pid_t p = ::waitpid(static_cast<pid_t>(g.x[0]), &st, static_cast<int>(g.x[2]) | WNOHANG);
    if (p < 0) set_guest_errno();
    if (g.x[1] && p > 0) {
        int32_t s = st;
        std::memcpy(reinterpret_cast<void*>(tbi(g.x[1])), &s, 4);
    }
    g.x[0] = static_cast<uint64_t>(static_cast<int64_t>(p));
}

void sh_getpid(Guest& g) { g.x[0] = static_cast<uint64_t>(::getpid()); }
void sh_getuid(Guest& g) { g.x[0] = ::getuid(); }
void sh_geteuid(Guest& g) { g.x[0] = ::geteuid(); }
void sh_getgid(Guest& g) { g.x[0] = ::getgid(); }
void sh_getegid(Guest& g) { g.x[0] = ::getegid(); }
void sh_getpagesize(Guest& g) { g.x[0] = 16384; }
void sh_sysconf(Guest& g) {
    int name = static_cast<int>(g.x[0]);
    if (name == 29 || name == _SC_NPROCESSORS_ONLN) g.x[0] = static_cast<uint64_t>(sysconf(_SC_NPROCESSORS_ONLN));
    else if (name == _SC_PAGESIZE) g.x[0] = 16384;
    else g.x[0] = static_cast<uint64_t>(sysconf(name));
}

void sh_sysctlbyname(Guest& g) {
    const char* name = guest_cstr(g.x[0]);
    void* oldp = g.x[1] ? reinterpret_cast<void*>(tbi(g.x[1])) : nullptr;
    auto* oldlen = g.x[2] ? reinterpret_cast<uint64_t*>(tbi(g.x[2])) : nullptr;
    auto put = [&](const void* src, size_t n) {
        if (oldlen) {
            if (oldp && *oldlen >= n) std::memcpy(oldp, src, n);
            *oldlen = n;
        }
        g.x[0] = 0;
    };
    if (!name) {
        g.x[0] = static_cast<uint64_t>(-1);
        return;
    }
    if (std::strcmp(name, "hw.ncpu") == 0 || std::strcmp(name, "hw.physicalcpu") == 0 || std::strcmp(name, "hw.logicalcpu") == 0) {
        int32_t n = static_cast<int32_t>(sysconf(_SC_NPROCESSORS_ONLN));
        put(&n, 4);
        return;
    }
    if (std::strcmp(name, "hw.memsize") == 0) {
        long pages = sysconf(_SC_PHYS_PAGES);
        long psz = sysconf(_SC_PAGESIZE);
        uint64_t m = (pages > 0 && psz > 0) ? static_cast<uint64_t>(pages) * static_cast<uint64_t>(psz) : (8ull << 30);
        put(&m, 8);
        return;
    }
    if (std::strcmp(name, "hw.pagesize") == 0 || std::strcmp(name, "hw.pagesize64") == 0) {
        int32_t n = 16384;
        put(&n, 4);
        return;
    }
    if (std::strcmp(name, "kern.osrelease") == 0) {
        const char* s = "23.0.0";
        put(s, 7);
        return;
    }
    if (std::strcmp(name, "kern.osversion") == 0) {
        const char* s = "23A344";
        put(s, 7);
        return;
    }
    if (std::strcmp(name, "kern.hostname") == 0) {
        char host[256] = "localhost";
        gethostname(host, sizeof(host));
        put(host, std::strlen(host) + 1);
        return;
    }
    if (std::strncmp(name, "hw.optional.", 12) == 0 || std::strncmp(name, "hw.optional.arm.", 16) == 0) {
        int32_t n = 0;
        put(&n, 4);
        return;
    }
    g_dar_errno = 2;
    g.x[0] = static_cast<uint64_t>(-1);
}

void sh_mach_abs(Guest& g) { g.x[0] = mono_ns(); }
void sh_timebase(Guest& g) {
    if (g.x[0]) {
        uint32_t v[2] = {1, 1};
        std::memcpy(reinterpret_cast<void*>(tbi(g.x[0])), v, 8);
    }
    g.x[0] = 0;
}
void sh_ca_time(Guest& g) {
    double s = static_cast<double>(mono_ns()) / 1e9;
    std::memcpy(g.v[0], &s, 8);
}
void sh_gettimeofday(Guest& g) {
    timeval tv {};
    ::gettimeofday(&tv, nullptr);
    if (g.x[0]) {
        int64_t sec = tv.tv_sec;
        int32_t usec = static_cast<int32_t>(tv.tv_usec);
        std::memcpy(reinterpret_cast<void*>(tbi(g.x[0])), &sec, 8);
        std::memcpy(reinterpret_cast<uint8_t*>(tbi(g.x[0])) + 8, &usec, 4);
    }
    g.x[0] = 0;
}
void sh_clock_gettime(Guest& g) {
    int clk = static_cast<int>(g.x[0]);
    int host = (clk == 6 || clk == 1) ? CLOCK_MONOTONIC : CLOCK_REALTIME;
    timespec ts {};
    int rc = ::clock_gettime(host, &ts);
    if (rc == 0 && g.x[1]) std::memcpy(reinterpret_cast<void*>(tbi(g.x[1])), &ts, sizeof(ts));
    if (rc < 0) set_guest_errno();
    g.x[0] = static_cast<uint64_t>(static_cast<int64_t>(rc));
}
void sh_time(Guest& g) {
    time_t t = ::time(nullptr);
    if (g.x[0]) {
        int64_t v = t;
        std::memcpy(reinterpret_cast<void*>(tbi(g.x[0])), &v, 8);
    }
    g.x[0] = static_cast<uint64_t>(t);
}
void sh_nanosleep(Guest& g) {
    uint64_t ns = 10ull * 1000 * 1000;
    if (g.x[0]) {
        timespec ts {};
        std::memcpy(&ts, reinterpret_cast<void*>(tbi(g.x[0])), sizeof(ts));
        ns = std::min<uint64_t>(static_cast<uint64_t>(ts.tv_sec) * 1000000000ull + static_cast<uint64_t>(ts.tv_nsec), ns);
    }
    timespec req {0, static_cast<long>(ns)};
    ::nanosleep(&req, nullptr);
    g.x[0] = 0;
}
void sh_localtime_r(Guest& g) {
    int64_t sec = 0;
    if (g.x[0]) std::memcpy(&sec, reinterpret_cast<void*>(tbi(g.x[0])), 8);
    time_t t = static_cast<time_t>(sec);
    tm out {};
    tm* p = localtime_r(&t, &out);
    if (p && g.x[1]) std::memcpy(reinterpret_cast<void*>(tbi(g.x[1])), p, sizeof(tm));
    g.x[0] = p ? g.x[1] : 0;
}
void sh_gmtime_r(Guest& g) {
    int64_t sec = 0;
    if (g.x[0]) std::memcpy(&sec, reinterpret_cast<void*>(tbi(g.x[0])), 8);
    time_t t = static_cast<time_t>(sec);
    tm out {};
    tm* p = gmtime_r(&t, &out);
    if (p && g.x[1]) std::memcpy(reinterpret_cast<void*>(tbi(g.x[1])), p, sizeof(tm));
    g.x[0] = p ? g.x[1] : 0;
}

void sh_pthread_create(Guest& g) {
    auto* start = new ThreadStart;
    start->func = g.x[2];
    start->arg = g.x[3];
    void* mem = ::mmap(nullptr, 8 << 20, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    start->stack = mem ? reinterpret_cast<uint64_t>(mem) + (8 << 20) - 64 : g.sp;
    pthread_t th {};
    int rc = pthread_create(&th, nullptr, thread_tramp, start);
    if (rc == 0 && g.x[0]) std::memcpy(reinterpret_cast<void*>(tbi(g.x[0])), &th, sizeof(th));
    else delete start;
    g.x[0] = static_cast<uint64_t>(rc);
}
void sh_pthread_join(Guest& g) {
    pthread_t th {};
    std::memcpy(&th, &g.x[0], sizeof(th));
    void* ret = nullptr;
    int rc = pthread_join(th, &ret);
    if (g.x[1]) write_u64(g.x[1], reinterpret_cast<uint64_t>(ret));
    g.x[0] = static_cast<uint64_t>(rc);
}
void sh_pthread_detach(Guest& g) {
    pthread_t th {};
    std::memcpy(&th, &g.x[0], sizeof(th));
    g.x[0] = static_cast<uint64_t>(pthread_detach(th));
}
void sh_pthread_self(Guest& g) {
    pthread_t th = pthread_self();
    std::memcpy(&g.x[0], &th, sizeof(th));
}
GuestMutex* mutex_of(uint64_t p) {
    if (!p) return nullptr;
    uint64_t slot = read_u64(p);
    if (slot < 0x10000) {
        auto* m = new GuestMutex;
        write_u64(p, reinterpret_cast<uint64_t>(m));
        return m;
    }
    return reinterpret_cast<GuestMutex*>(tbi(slot));
}
void sh_mutex_init(Guest& g) {
    if (g.x[0]) {
        auto* m = new GuestMutex;
        write_u64(g.x[0], reinterpret_cast<uint64_t>(m));
    }
    g.x[0] = 0;
}
void sh_mutex_lock(Guest& g) {
    // Do not wait. A guest thread that stops while holding a Darwin mutex
    // would otherwise leave the process blocked on a host futex.
    (void)mutex_of(g.x[0]);
    g.x[0] = 0;
}
void sh_mutex_unlock(Guest& g) { g.x[0] = 0; }
void sh_mutex_trylock(Guest& g) {
    (void)mutex_of(g.x[0]);
    g.x[0] = 0;
}
void sh_mutex_destroy(Guest& g) { g.x[0] = 0; }
void sh_mutexattr(Guest& g) { g.x[0] = 0; }

void sh_cond_init(Guest& g) { g.x[0] = 0; }
void sh_cond_wait(Guest& g) { g.x[0] = 0; }
void sh_cond_signal(Guest& g) { g.x[0] = 0; }

thread_local std::map<uint64_t, uint64_t> g_tls;
std::vector<uint64_t> g_tls_dtors;
void sh_key_create(Guest& g) {
    uint64_t id = g_tls_dtors.size() + 1;
    g_tls_dtors.push_back(g.x[1]);
    if (g.x[0]) write_u64(g.x[0], id);
    g.x[0] = 0;
}
void sh_getspecific(Guest& g) { g.x[0] = g_tls[g.x[0]]; }
void sh_setspecific(Guest& g) {
    g_tls[g.x[0]] = g.x[1];
    g.x[0] = 0;
}
void sh_pthread_once(Guest& g) {
    auto* slot = reinterpret_cast<uint32_t*>(tbi(g.x[0]));
    if (slot && *slot == 0) {
        *slot = 1;
        call_guest(g.x[1], 0, 0, 0, 0, &g);
    }
    g.x[0] = 0;
}

void sh_call_once(Guest& g) {
    // libc++ __call_once(flag, arg, func). A finished flag is all-ones.
    uint64_t flag_at = tbi(g.x[0]);
    uint64_t func = g.x[2];
    g.x[0] = 0;
    if (flag_at < 0x10000 || !func) return;
    uint64_t flag = 0;
    std::memcpy(&flag, reinterpret_cast<void*>(flag_at), 8);
    if (flag == ~0ull) return;
    call_guest(func, g.x[1], 0, 0, 0, &g);
    flag = ~0ull;
    std::memcpy(reinterpret_cast<void*>(flag_at), &flag, 8);
    g.x[0] = 0;
}

void sh_setjmp(Guest& g) {
    JmpSave s;
    s.g = g;
    s.resume = g.x[30];
    std::lock_guard<std::mutex> lock(g_jmp_mu);
    g_jumps[g.x[0]] = s;
    g.x[0] = 0;
}
void sh_longjmp(Guest& g) {
    JmpSave s;
    {
        std::lock_guard<std::mutex> lock(g_jmp_mu);
        auto it = g_jumps.find(g.x[0]);
        if (it == g_jumps.end()) {
            g.stop = 1;
            g.stop_why = "longjmp";
            g.redirect = true;
            return;
        }
        s = it->second;
    }
    uint64_t val = g.x[1] ? g.x[1] : 1;
    uint64_t steps = g.steps;
    g = s.g;
    g.steps = steps;
    g.pc = s.resume;
    g.x[0] = val;
    g.stop = 0;
    g.redirect = true;
}

void invoke_block(Guest& g, uint64_t block) {
    if (!block) return;
    uint64_t imp = read_u64(block + 16);
    if (imp) call_guest(imp, block, 0, 0, 0, &g);
}
void sh_dispatch_async(Guest& g) { invoke_block(g, g.x[1]); }
void sh_dispatch_once(Guest& g) {
    auto* pred = reinterpret_cast<uint64_t*>(tbi(g.x[0]));
    if (pred && *pred == 0) {
        *pred = ~0ull;
        invoke_block(g, g.x[1]);
    }
}
void sh_dispatch_once_f(Guest& g) {
    auto* pred = reinterpret_cast<uint64_t*>(tbi(g.x[0]));
    if (pred && *pred == 0) {
        *pred = ~0ull;
        call_guest(g.x[2], g.x[1], 0, 0, 0, &g);
    }
}
void sh_queue(Guest& g) { g.x[0] = 0x710000000000ull; }
void sh_sem_create(Guest& g) { g.x[0] = 0x710000000100ull + (g.x[0] & 0xff); }
void sh_sem_signal(Guest& g) { g.x[0] = 0; }
void sh_sem_wait(Guest& g) { g.x[0] = 0; }
void sh_dispatch_release(Guest& g) { (void)g; }

void sh_dlopen(Guest& g) {
    const char* name = g.x[0] ? guest_cstr(g.x[0]) : "";
    auto* h = new std::string(name ? name : "");
    g.x[0] = reinterpret_cast<uint64_t>(h);
}
void sh_dlsym(Guest& g) {
    const char* name = guest_cstr(g.x[1]);
    if (!name) {
        g.x[0] = 0;
        return;
    }
    std::string n = name;
    if (n.empty() || n[0] != '_') n = "_" + n;
    g.x[0] = resolve_symbol(n, 0);
}
void sh_dlclose(Guest& g) { g.x[0] = 0; }
void sh_dlerror(Guest& g) { g.x[0] = 0; }
void sh_dladdr(Guest& g) { g.x[0] = 0; }

void sh_dyld_count(Guest& g) { g.x[0] = g_image ? 1 : 0; }
void sh_dyld_header(Guest& g) { g.x[0] = (g_image && g.x[0] == 0) ? g_image->base : 0; }
void sh_dyld_name(Guest& g) { g.x[0] = (g.x[0] == 0) ? reinterpret_cast<uint64_t>(g_exe.c_str()) : 0; }
void sh_getsectiondata(Guest& g) {
    const char* seg = guest_cstr(g.x[1]);
    const char* sect = guest_cstr(g.x[2]);
    const MachSection* s = (g_image && seg && sect) ? g_image->find_section(seg, sect) : nullptr;
    if (!s) {
        g.x[0] = 0;
        return;
    }
    if (g.x[3]) write_u64(g.x[3], s->size);
    g.x[0] = s->addr;
}

void sh_cxa_atexit(Guest& g) { g.x[0] = 0; }
void sh_guard_acq(Guest& g) {
    auto* p = reinterpret_cast<uint8_t*>(tbi(g.x[0]));
    if (p && *p == 0) {
        *p = 1;
        g.x[0] = 1;
    } else {
        g.x[0] = 0;
    }
}
void sh_guard_rel(Guest& g) {
    auto* p = reinterpret_cast<uint8_t*>(tbi(g.x[0]));
    if (p) *p = 1;
}
void sh_guard_abort(Guest& g) {
    auto* p = reinterpret_cast<uint8_t*>(tbi(g.x[0]));
    if (p) *p = 0;
}
void sh_throw(Guest& g) {
    g.stop = 6;
    g.stop_why = "cxx-throw";
    g.stop_pc = g.x[30];
    g.redirect = true;
}
void sh_pure(Guest& g) {
    g.stop = 6;
    g.stop_why = "pure-virtual";
    g.redirect = true;
}
void sh_new(Guest& g) {
    size_t n = g.x[0] ? g.x[0] : 1;
    g.x[0] = reinterpret_cast<uint64_t>(std::malloc(n));
}
void sh_delete(Guest& g) {
    if (g.x[0]) std::free(reinterpret_cast<void*>(tbi(g.x[0])));
}

void sh_objc_msg(Guest& g) { objc_msg_send(g); }
void sh_objc_msg_super(Guest& g) { objc_msg_send_super2(g); }
void sh_objc_alloc(Guest& g) {
    g.x[1] = reinterpret_cast<uint64_t>(sel("alloc"));
    objc_msg_send(g);
}
void sh_objc_alloc_init(Guest& g) {
    uint64_t cls = g.x[0];
    g.x[1] = reinterpret_cast<uint64_t>(sel("alloc"));
    objc_msg_send(g);
    if (g.redirect) return;
    g.x[0] = g.x[0] ? g.x[0] : cls;
    g.x[1] = reinterpret_cast<uint64_t>(sel("init"));
    objc_msg_send(g);
}
void sh_objc_opt_new(Guest& g) { sh_objc_alloc_init(g); }
void sh_retain(Guest& g) {}
void sh_release(Guest& g) { (void)g; }
void sh_autorelease(Guest& g) {}
void sh_pool_push(Guest& g) { g.x[0] = 1; }
void sh_pool_pop(Guest& g) { (void)g; }
void sh_store_strong(Guest& g) {
    if (g.x[0] > 0x10000) write_u64(g.x[0], g.x[1]);
    g.x[0] = g.x[1];
}
void sh_load_weak(Guest& g) {
    g.x[0] = g.x[0] > 0x10000 ? read_u64(g.x[0]) : 0;
}
void sh_destroy_weak(Guest& g) {
    if (g.x[0] > 0x10000) write_u64(g.x[0], 0);
}
void sh_copy_weak(Guest& g) {
    uint64_t v = g.x[1] > 0x10000 ? read_u64(g.x[1]) : 0;
    if (g.x[0] > 0x10000) write_u64(g.x[0], v);
}
void sh_get_class(Guest& g) {
    const char* n = guest_cstr(g.x[0]);
    g.x[0] = (n && *n) ? ensure_class(n, "NSObject", 64) : 0;
}
void sh_class_name(Guest& g) {
    uint64_t cls = g.x[0];
    if (g_image && g_image->contains(cls)) {
        uint64_t bits = read_u64(cls + 32);
        uint64_t ro = bits & 0x00007ffffffffff8ull;
        g.x[0] = ro ? read_u64(ro + 24) : 0;
        return;
    }
    g.x[0] = reinterpret_cast<uint64_t>("NSObject");
}
void sh_sel_reg(Guest& g) {
    const char* n = guest_cstr(g.x[0]);
    g.x[0] = reinterpret_cast<uint64_t>(sel(n ? n : ""));
}
void sh_sel_name(Guest& g) { g.x[0] = g.x[0]; }
void sh_sync_enter(Guest& g) { g.x[0] = 0; }
void sh_sync_exit(Guest& g) { g.x[0] = 0; }

void sh_nslog(Guest& g) {
    char buf[2048];
    const char* fmt = nullptr;
    if (has_payload(g.x[0]) && !payload(g.x[0]).str.empty()) fmt = payload(g.x[0]).str.c_str();
    else if (g.x[0]) fmt = guest_cstr(read_u64(g.x[0] + 16));
    guest_format(buf, sizeof(buf), fmt ? fmt : "", g, 1, 0);
    std::fprintf(stderr, "NSLog: %s\n", buf);
}
void sh_class_from_string(Guest& g) {
    const char* n = nullptr;
    if (has_payload(g.x[0]) && !payload(g.x[0]).str.empty()) n = payload(g.x[0]).str.c_str();
    else if (g.x[0]) n = guest_cstr(read_u64(g.x[0] + 16));
    g.x[0] = (n && *n) ? ensure_class(n, "NSObject", 64) : 0;
}
void sh_search_path(Guest& g) {
    const char* home = std::getenv("HOME");
    g.x[0] = make_string(home ? home : "/tmp");
    uint64_t s = g.x[0];
    uint64_t arr = make_object("NSArray");
    payload(arr).kind = 2;
    payload(arr).items.push_back(s);
    g.x[0] = arr;
}

void sh_opendir(Guest& g) {
    const char* path = guest_cstr(g.x[0]);
    DIR* d = path ? ::opendir(path) : nullptr;
    if (!d) set_guest_errno();
    g.x[0] = reinterpret_cast<uint64_t>(d);
}
void sh_readdir(Guest& g) {
    auto* d = reinterpret_cast<DIR*>(tbi(g.x[0]));
    if (!d) {
        g.x[0] = 0;
        return;
    }
    dirent* e = ::readdir(d);
    if (!e) {
        g.x[0] = 0;
        return;
    }
    auto& buf = g_dirents[g.x[0]];
    buf.assign(1100, 0);
    uint64_t ino = e->d_ino;
    std::memcpy(buf.data(), &ino, 8);
    uint16_t reclen = 1048;
    uint16_t namlen = static_cast<uint16_t>(std::strlen(e->d_name));
    std::memcpy(buf.data() + 16, &reclen, 2);
    std::memcpy(buf.data() + 18, &namlen, 2);
    buf[20] = e->d_type;
    std::memcpy(buf.data() + 21, e->d_name, namlen);
    g.x[0] = reinterpret_cast<uint64_t>(buf.data());
}
void sh_closedir(Guest& g) {
    auto* d = reinterpret_cast<DIR*>(tbi(g.x[0]));
    g.x[0] = static_cast<uint64_t>(d ? ::closedir(d) : -1);
}

void sh_socket(Guest& g) {
    int fd = ::socket(static_cast<int>(g.x[0]), static_cast<int>(g.x[1]), static_cast<int>(g.x[2]));
    if (fd < 0) set_guest_errno();
    g.x[0] = static_cast<uint64_t>(static_cast<int64_t>(fd));
}
void sh_connect(Guest& g) {
    sockaddr_storage ss {};
    socklen_t sl = 0;
    int rc = -1;
    if (to_host_sockaddr(g.x[1], g.x[2] ? g.x[2] : 16, ss, sl)) rc = ::connect(static_cast<int>(g.x[0]), reinterpret_cast<sockaddr*>(&ss), sl);
    if (rc < 0) set_guest_errno();
    g.x[0] = static_cast<uint64_t>(static_cast<int64_t>(rc));
}
void sh_bind(Guest& g) {
    sockaddr_storage ss {};
    socklen_t sl = 0;
    int rc = -1;
    if (to_host_sockaddr(g.x[1], g.x[2] ? g.x[2] : 16, ss, sl)) rc = ::bind(static_cast<int>(g.x[0]), reinterpret_cast<sockaddr*>(&ss), sl);
    if (rc < 0) set_guest_errno();
    g.x[0] = static_cast<uint64_t>(static_cast<int64_t>(rc));
}
void sh_listen(Guest& g) {
    int rc = ::listen(static_cast<int>(g.x[0]), static_cast<int>(g.x[1]));
    if (rc < 0) set_guest_errno();
    g.x[0] = static_cast<uint64_t>(static_cast<int64_t>(rc));
}
void sh_accept(Guest& g) {
    int fd = ::accept(static_cast<int>(g.x[0]), nullptr, nullptr);
    if (fd < 0) set_guest_errno();
    g.x[0] = static_cast<uint64_t>(static_cast<int64_t>(fd));
}
void sh_send(Guest& g) {
    ssize_t n = ::send(static_cast<int>(g.x[0]), reinterpret_cast<void*>(tbi(g.x[1])), g.x[2], static_cast<int>(g.x[3]));
    if (n < 0) set_guest_errno();
    g.x[0] = static_cast<uint64_t>(n);
}
void sh_recv(Guest& g) {
    ssize_t n = ::recv(static_cast<int>(g.x[0]), reinterpret_cast<void*>(tbi(g.x[1])), g.x[2], static_cast<int>(g.x[3]));
    if (n < 0) set_guest_errno();
    g.x[0] = static_cast<uint64_t>(n);
}
void sh_setsockopt(Guest& g) {
    int rc = ::setsockopt(static_cast<int>(g.x[0]), static_cast<int>(g.x[1]), static_cast<int>(g.x[2]),
                          reinterpret_cast<void*>(tbi(g.x[3])), static_cast<socklen_t>(g.x[4]));
    if (rc < 0) set_guest_errno();
    g.x[0] = static_cast<uint64_t>(static_cast<int64_t>(rc));
}
void sh_getaddrinfo(Guest& g) {
    const char* host = g.x[0] ? guest_cstr(g.x[0]) : nullptr;
    const char* serv = g.x[1] ? guest_cstr(g.x[1]) : nullptr;
    addrinfo* res = nullptr;
    int rc = ::getaddrinfo(host, serv, nullptr, &res);
    if (rc == 0 && g.x[3]) write_u64(g.x[3], reinterpret_cast<uint64_t>(res));
    g.x[0] = static_cast<uint64_t>(rc);
}
void sh_freeaddrinfo(Guest& g) {
    if (g.x[0]) ::freeaddrinfo(reinterpret_cast<addrinfo*>(tbi(g.x[0])));
}
void sh_poll(Guest& g) {
    int timeout = static_cast<int>(g.x[2]);
    if (timeout < 0 || timeout > 20) timeout = boot_test() ? 0 : 20;
    int rc = ::poll(reinterpret_cast<pollfd*>(tbi(g.x[0])), static_cast<nfds_t>(g.x[1]), timeout);
    if (rc < 0) set_guest_errno();
    g.x[0] = static_cast<uint64_t>(static_cast<int64_t>(rc));
}
void sh_gethostname(Guest& g) {
    int rc = ::gethostname(reinterpret_cast<char*>(tbi(g.x[0])), g.x[1]);
    if (rc < 0) set_guest_errno();
    g.x[0] = static_cast<uint64_t>(static_cast<int64_t>(rc));
}

void sh_qsort(Guest& g) {
    auto* base = reinterpret_cast<uint8_t*>(tbi(g.x[0]));
    size_t n = g.x[1];
    size_t w = g.x[2];
    uint64_t cmp = g.x[3];
    if (!base || !cmp || w == 0 || n < 2) return;
    std::vector<uint8_t> tmp(w);
    for (size_t i = 1; i < n; ++i) {
        std::memcpy(tmp.data(), base + i * w, w);
        size_t j = i;
        while (j > 0) {
            int c = static_cast<int>(call_guest(cmp, reinterpret_cast<uint64_t>(base + (j - 1) * w), reinterpret_cast<uint64_t>(tmp.data()), 0, 0, &g));
            if (c <= 0) break;
            std::memcpy(base + j * w, base + (j - 1) * w, w);
            --j;
        }
        std::memcpy(base + j * w, tmp.data(), w);
    }
}

void sh_arc4(Guest& g) {
    uint32_t v = 0;
    int fd = ::open("/dev/urandom", O_RDONLY);
    if (fd >= 0) {
        if (::read(fd, &v, 4) != 4) v = static_cast<uint32_t>(mono_ns());
        ::close(fd);
    }
    g.x[0] = v;
}
void sh_ccrandom(Guest& g) {
    int fd = ::open("/dev/urandom", O_RDONLY);
    if (fd >= 0 && g.x[0] && g.x[1]) {
        ssize_t n = ::read(fd, reinterpret_cast<void*>(tbi(g.x[0])), g.x[1]);
        (void)n;
        ::close(fd);
    }
    g.x[0] = 0;
}

#define LB_D1(name, fn)                                      \
    void sh_##name(Guest& g) {                               \
        double x = 0;                                        \
        std::memcpy(&x, g.v[0], 8);                          \
        double y = fn(x);                                    \
        std::memcpy(g.v[0], &y, 8);                          \
    }
#define LB_F1(name, fn)                                      \
    void sh_##name(Guest& g) {                               \
        float x = 0;                                         \
        std::memcpy(&x, g.v[0], 4);                          \
        float y = fn(x);                                     \
        std::memset(g.v[0], 0, 16);                          \
        std::memcpy(g.v[0], &y, 4);                          \
    }
#define LB_D2(name, fn)                                      \
    void sh_##name(Guest& g) {                               \
        double a = 0, b = 0;                                 \
        std::memcpy(&a, g.v[0], 8);                          \
        std::memcpy(&b, g.v[1], 8);                          \
        double y = fn(a, b);                                 \
        std::memcpy(g.v[0], &y, 8);                          \
    }
#define LB_F2(name, fn)                                      \
    void sh_##name(Guest& g) {                               \
        float a = 0, b = 0;                                  \
        std::memcpy(&a, g.v[0], 4);                          \
        std::memcpy(&b, g.v[1], 4);                          \
        float y = fn(a, b);                                  \
        std::memset(g.v[0], 0, 16);                          \
        std::memcpy(g.v[0], &y, 4);                          \
    }
LB_D1(cos, ::cos) LB_D1(sin, ::sin) LB_D1(tan, ::tan) LB_D1(acos, ::acos) LB_D1(asin, ::asin) LB_D1(atan, ::atan)
LB_D1(cosh, ::cosh) LB_D1(sinh, ::sinh) LB_D1(tanh, ::tanh) LB_D1(exp, ::exp) LB_D1(exp2, ::exp2) LB_D1(log, ::log)
LB_D1(log10, ::log10) LB_D1(log2, ::log2) LB_D1(cbrt, ::cbrt)
LB_F1(cosf, ::cosf) LB_F1(sinf, ::sinf) LB_F1(tanf, ::tanf) LB_F1(acosf, ::acosf) LB_F1(asinf, ::asinf) LB_F1(atanf, ::atanf)
LB_F1(expf, ::expf) LB_F1(exp2f, ::exp2f) LB_F1(logf, ::logf) LB_F1(log10f, ::log10f) LB_F1(log2f, ::log2f) LB_F1(cbrtf, ::cbrtf)
LB_D2(pow, ::pow) LB_D2(atan2, ::atan2) LB_D2(fmod, ::fmod) LB_D2(hypot, ::hypot)
LB_F2(powf, ::powf) LB_F2(atan2f, ::atan2f) LB_F2(fmodf, ::fmodf) LB_F2(hypotf, ::hypotf)

void sh_pixels_wide(Guest& g) { g.x[0] = 1280; }
void sh_pixels_high(Guest& g) { g.x[0] = 720; }
void sh_main_display(Guest& g) { g.x[0] = 1; }
void sh_display_bounds(Guest& g) {
    double r[4] = {0, 0, 1280, 720};
    for (int i = 0; i < 4; ++i) {
        std::memset(g.v[i], 0, 16);
        std::memcpy(g.v[i], &r[i], 8);
    }
}

struct HostArray {
    uint32_t magic = 0x41525221;
    uint32_t count = 0;
    uint64_t items[8]{};
};
std::unordered_set<uint64_t> g_host_arrays;
uint64_t g_display_mode = 0;

uint64_t host_array(std::initializer_list<uint64_t> items) {
    auto* a = new HostArray;
    a->count = static_cast<uint32_t>(std::min<size_t>(items.size(), 8));
    uint32_t i = 0;
    for (uint64_t v : items) {
        if (i >= 8) break;
        a->items[i++] = v;
    }
    uint64_t p = reinterpret_cast<uint64_t>(a);
    g_host_arrays.insert(p);
    return p;
}
HostArray* as_array(uint64_t p) {
    if (!g_host_arrays.count(p)) return nullptr;
    return reinterpret_cast<HostArray*>(tbi(p));
}
void ensure_display_mode() {
    if (!g_display_mode) g_display_mode = reinterpret_cast<uint64_t>(std::calloc(1, 32));
}

void sh_online_displays(Guest& g) {
    uint32_t max = static_cast<uint32_t>(g.x[0]);
    uint32_t n = 1;
    if (g.x[2]) std::memcpy(reinterpret_cast<void*>(tbi(g.x[2])), &n, 4);
    if (g.x[1] && max >= 1) {
        uint32_t id = 1;
        std::memcpy(reinterpret_cast<void*>(tbi(g.x[1])), &id, 4);
    }
    g.x[0] = 0;
}
void sh_copy_display_mode(Guest& g) {
    ensure_display_mode();
    g.x[0] = g_display_mode;
}
void sh_copy_all_modes(Guest& g) {
    ensure_display_mode();
    g.x[0] = host_array({g_display_mode});
}
void sh_mode_w(Guest& g) { g.x[0] = 1280; }
void sh_mode_h(Guest& g) { g.x[0] = 720; }
void sh_mode_usable(Guest& g) { g.x[0] = 1; }
void sh_mode_hz(Guest& g) {
    double hz = 60;
    std::memcpy(g.v[0], &hz, 8);
}
void sh_cfarray_count(Guest& g) {
    HostArray* a = as_array(g.x[0]);
    g.x[0] = a ? a->count : 0;
}
void sh_cfarray_at(Guest& g) {
    HostArray* a = as_array(g.x[0]);
    uint64_t i = g.x[1];
    g.x[0] = (a && i < a->count) ? a->items[i] : 0;
}
void sh_cf_array_append(Guest& g) {
    HostArray* a = as_array(g.x[0]);
    if (!a || a->count >= 8) return;
    a->items[a->count++] = g.x[1];
}
void sh_cfarray_create(Guest& g) {
    uint64_t values = g.x[1];
    uint64_t n = g.x[2];
    if (n > 8) n = 8;
    auto* a = new HostArray;
    a->count = static_cast<uint32_t>(n);
    for (uint64_t i = 0; i < n; ++i) {
        uint64_t v = 0;
        if (values) std::memcpy(&v, reinterpret_cast<void*>(tbi(values + i * 8)), 8);
        a->items[i] = v;
    }
    uint64_t p = reinterpret_cast<uint64_t>(a);
    g_host_arrays.insert(p);
    g.x[0] = p;
}
void sh_tis_source(Guest& g) {
    static uint64_t src = reinterpret_cast<uint64_t>(std::calloc(1, 16));
    g.x[0] = src;
}
void sh_tis_prop(Guest& g) {
    static uint64_t data = reinterpret_cast<uint64_t>(std::calloc(1, 64));
    g.x[0] = data;
}
uint64_t display_link() {
    static uint64_t link = reinterpret_cast<uint64_t>(std::calloc(1, 32));
    return link;
}
void sh_cv_create_active(Guest& g) {
    // CVDisplayLinkCreateWithActiveCGDisplays(CVDisplayLinkRef*)
    if (g.x[0] > 0x10000) write_u64(g.x[0], display_link());
    g.x[0] = 0;
}
void sh_cv_create_display(Guest& g) {
    // CVDisplayLinkCreateWithCGDisplay(CGDirectDisplayID, CVDisplayLinkRef*)
    if (g.x[1] > 0x10000) write_u64(g.x[1], display_link());
    g.x[0] = 0;
}
void sh_cv_period(Guest& g) {
    g.x[0] = 1;
    g.x[1] = 60;
}
void sh_font_metric(Guest& g) {
    double v = 12;
    std::memcpy(g.v[0], &v, 8);
}
void sh_audio_get(Guest& g) {
    auto* sz = g.x[4] ? reinterpret_cast<uint32_t*>(tbi(g.x[4])) : nullptr;
    void* out = g.x[5] ? reinterpret_cast<void*>(tbi(g.x[5])) : nullptr;
    if (sz && out && *sz > 0 && *sz < (1u << 20)) std::memset(out, 0, *sz);
    g.x[0] = 0;
}
void sh_audio_size(Guest& g) {
    if (g.x[4]) {
        uint32_t n = 4;
        std::memcpy(reinterpret_cast<void*>(tbi(g.x[4])), &n, 4);
    }
    g.x[0] = 0;
}
void sh_cf_runloop(Guest& g) { g.x[0] = 1; }
void sh_cf_release(Guest& g) { (void)g; }
void sh_cf_retain(Guest& g) {}
void sh_cf_string_ptr(Guest& g) {
    if (has_payload(g.x[0]) && !payload(g.x[0]).str.empty()) {
        g.x[0] = reinterpret_cast<uint64_t>(payload(g.x[0]).str.c_str());
        return;
    }
    g.x[0] = g.x[0] ? read_u64(g.x[0] + 16) : 0;
}
void sh_cf_string_len(Guest& g) {
    if (has_payload(g.x[0])) g.x[0] = payload(g.x[0]).str.size();
    else if (g.x[0]) {
        int32_t n = 0;
        std::memcpy(&n, reinterpret_cast<void*>(tbi(g.x[0] + 24)), 4);
        g.x[0] = static_cast<uint64_t>(n);
    } else g.x[0] = 0;
}
void sh_cf_string_create(Guest& g) {
    const char* s = guest_cstr(g.x[1]);
    g.x[0] = make_string(s ? s : "");
}
void sh_cf_bundle(Guest& g) { g.x[0] = make_object("NSBundle"); }
void sh_availability(Guest& g) { g.x[0] = 1; }
void sh_mach_msg(Guest& g) { g.x[0] = 0x10000003; }
void sh_host_self(Guest& g) { g.x[0] = 1; }
void sh_ns_environ(Guest& g) { g.x[0] = data_symbol("_environ", 8); }

void sh_block_assign(Guest& g) { g.x[0] = 0; }
void sh_block_dispose(Guest& g) { (void)g; }

void on_segv(int sig, siginfo_t* info, void*) {
    if (g_armed && g_cur) {
        g_fault_pc = g_cur->pc;
        g_fault_addr = info ? reinterpret_cast<uint64_t>(info->si_addr) : 0;
        g_cur->stop = 4;
        g_cur->stop_why = sig == SIGBUS ? "sigbus" : "sigsegv";
        g_cur->stop_pc = g_cur->pc;
        siglongjmp(g_jmp, 1);
    }
    const char msg[] = "unhandled guest signal\n";
    ssize_t unused = ::write(2, msg, sizeof msg - 1);
    (void)unused;
    void* frames[24];
    int n = backtrace(frames, 24);
    backtrace_symbols_fd(frames, n, 2);
    _exit(139);
}

void install_handler() {
    static int once = 0;
    if (once) return;
    once = 1;
    struct sigaction sa {};
    sa.sa_sigaction = on_segv;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGSEGV, &sa, nullptr);
    sigaction(SIGBUS, &sa, nullptr);
    sigaction(SIGILL, &sa, nullptr);
}

uint64_t run_guarded(Guest& g, uint64_t max_insns) {
    install_handler();
    g_cur = &g;
    if (sigsetjmp(g_jmp, 1) != 0) {
        g.stop = 4;
        g.stop_why = "sigsegv";
        g.stop_pc = g_fault_pc ? g_fault_pc : g.pc;
        g_armed = 0;
        const char* shim = shim_name_at(g.stop_pc);
        std::fprintf(stderr, "guest fault pc=0x%llx addr=0x%llx load=%llx shim=%s\n",
                     static_cast<unsigned long long>(g.stop_pc),
                     static_cast<unsigned long long>(g_fault_addr),
                     static_cast<unsigned long long>(g_debug_load_addr), shim ? shim : "");
        g_armed = 0;
        return g.steps;
    }
    g_armed = 1;
    uint64_t n = dbt_run(g, max_insns);
    g_armed = 0;
    return n;
}

void register_libc() {
    register_shim("_malloc", sh_malloc);
    register_shim("_calloc", sh_calloc);
    register_shim("_realloc", sh_realloc);
    register_shim("_free", sh_free);
    register_shim("_malloc_size", sh_malloc_size);
    register_shim("_malloc_zone_malloc", sh_malloc);
    register_shim("_malloc_zone_realloc", sh_realloc);
    register_shim("_malloc_zone_free", sh_free);
    register_shim("_malloc_default_zone", sh_ret1);
    register_shim("_malloc_create_zone", sh_ret1);
    register_shim("_malloc_set_zone_name", sh_ret0);
    register_shim("_posix_memalign", sh_posix_memalign);
    register_shim("_memcpy", sh_memcpy);
    register_shim("_memmove", sh_memmove);
    register_shim("_memset", sh_memset);
    register_shim("_bzero", sh_bzero);
    register_shim("_memcmp", sh_memcmp);
    register_shim("_memchr", sh_memchr);
    register_shim("___memcpy_chk", sh_chk_memcpy);
    register_shim("___memmove_chk", sh_chk_memmove);
    register_shim("___memset_chk", sh_chk_memset);
    register_shim("_strlen", sh_strlen);
    register_shim("_strnlen", sh_strnlen);
    register_shim("_strcmp", sh_strcmp);
    register_shim("_strncmp", sh_strncmp);
    register_shim("_strcpy", sh_strcpy);
    register_shim("_strncpy", sh_strncpy);
    register_shim("_strcat", sh_strcat);
    register_shim("_strdup", sh_strdup);
    register_shim("_strchr", sh_strchr);
    register_shim("_strrchr", sh_strrchr);
    register_shim("_strstr", sh_strstr);
    register_shim("_strerror", sh_strerror);
    register_shim("_strerror_r", sh_strerror);
    register_shim("_strtol", sh_strtol);
    register_shim("_strtoll", sh_strtol);
    register_shim("_strtoul", sh_strtoul);
    register_shim("_strtoull", sh_strtoul);
    register_shim("_strtod", sh_strtod);
    register_shim("_atoi", sh_atoi);
    register_shim("_atof", sh_atof);
    register_shim("_strlcpy", sh_strlcpy);
    register_shim("_strlcat", sh_strlcat);
    register_shim("___strlcpy_chk", sh_chk_strlcpy);
    register_shim("___strlcat_chk", sh_chk_strlcat);
    register_shim("___error", sh_error);
    register_shim("___stack_chk_fail", sh_chk_fail);
    register_shim("___chkstk_darwin", sh_ret0);
    register_shim("_exit", sh_exit);
    register_shim("__exit", sh_exit);
    register_shim("__Exit", sh_exit);
    register_shim("_abort", sh_abort);
    register_shim("_open", sh_open);
    register_shim("_close", sh_close);
    register_shim("_read", sh_read);
    register_shim("_write", sh_write);
    register_shim("_pread", sh_read);
    register_shim("_pwrite", sh_write);
    register_shim("_lseek", sh_lseek);
    register_shim("_stat", sh_stat);
    register_shim("_lstat", sh_lstat);
    register_shim("_fstat", sh_fstat);
    register_shim("_access", sh_access);
    register_shim("_mkdir", sh_mkdir);
    register_shim("_unlink", sh_unlink);
    register_shim("_remove", sh_unlink);
    register_shim("_rename", sh_rename);
    register_shim("_getcwd", sh_getcwd);
    register_shim("_chdir", sh_chdir);
    register_shim("_readlink", sh_readlink);
    register_shim("_realpath$DARWIN_EXTSN", sh_realpath);
    register_shim("_mmap", sh_mmap);
    register_shim("_munmap", sh_munmap);
    register_shim("_mprotect", sh_mprotect);
    register_shim("_mlock", sh_ret0);
    register_shim("_munlock", sh_ret0);
    register_shim("_getenv", sh_getenv);
    register_shim("_setenv", sh_setenv);
    register_shim("_unsetenv", sh_unsetenv);
    register_shim("_printf", sh_printf);
    register_shim("_fprintf", sh_fprintf);
    register_shim("_snprintf", sh_snprintf);
    register_shim("_vsnprintf", sh_snprintf);
    register_shim("_vfprintf", sh_fprintf);
    register_shim("_puts", sh_puts);
    register_shim("_fopen", sh_fopen);
    register_shim("_fopen$DARWIN_EXTSN", sh_fopen);
    register_shim("_fclose", sh_fclose);
    register_shim("_fread", sh_fread);
    register_shim("_fwrite", sh_fwrite);
    register_shim("_fseek", sh_fseek);
    register_shim("_fseeko", sh_fseek);
    register_shim("_ftell", sh_ftell);
    register_shim("_ftello", sh_ftell);
    register_shim("_fflush", sh_fflush);
    register_shim("_feof", sh_feof);
    register_shim("_ferror", sh_ferror);
    register_shim("_fileno", sh_fileno);
    register_shim("_fgets", sh_fgets);
    register_shim("_rewind", sh_ret0);
    register_shim("_setvbuf", sh_ret0);
    register_shim("_clearerr", sh_ret0);
    register_shim("_pipe", sh_pipe);
    register_shim("_dup2", sh_dup2);
    register_shim("_fcntl", sh_fcntl);
    register_shim("_flock", sh_ret0);
    register_shim("_fsync", sh_ret0);
    register_shim("_posix_spawn_file_actions_init", sh_fa_init);
    register_shim("_posix_spawn_file_actions_adddup2", sh_fa_dup2);
    register_shim("_posix_spawn_file_actions_addclose", sh_fa_close);
    register_shim("_posix_spawn_file_actions_addopen", sh_ret0);
    register_shim("_posix_spawn_file_actions_addchdir_np", sh_ret0);
    register_shim("_posix_spawn_file_actions_destroy", sh_fa_destroy);
    register_shim("_posix_spawnattr_init", sh_spawnattr_init);
    register_shim("_posix_spawnattr_destroy", sh_spawnattr_destroy);
    register_shim("_posix_spawn", sh_posix_spawn);
    register_shim("_posix_spawnp", sh_posix_spawnp);
    register_shim("_fork", sh_fork);
    register_shim("_waitpid", sh_waitpid);
    register_shim("_getpid", sh_getpid);
    register_shim("_getuid", sh_getuid);
    register_shim("_geteuid", sh_geteuid);
    register_shim("_getgid", sh_getgid);
    register_shim("_getegid", sh_getegid);
    register_shim("_getpagesize", sh_getpagesize);
    register_shim("_sysconf", sh_sysconf);
    register_shim("_sysctlbyname", sh_sysctlbyname);
    register_shim("_sysctl", sh_ret0);
    register_shim("_mach_absolute_time", sh_mach_abs);
    register_shim("_mach_timebase_info", sh_timebase);
    register_shim("_CACurrentMediaTime", sh_ca_time);
    register_shim("_gettimeofday", sh_gettimeofday);
    register_shim("_clock_gettime", sh_clock_gettime);
    register_shim("_time", sh_time);
    register_shim("_nanosleep", sh_nanosleep);
    register_shim("_localtime_r", sh_localtime_r);
    register_shim("_gmtime_r", sh_gmtime_r);
    register_shim("_localtime", sh_localtime_r);
    register_shim("_gmtime", sh_gmtime_r);
    register_shim("_pthread_create", sh_pthread_create);
    register_shim("_pthread_join", sh_pthread_join);
    register_shim("_pthread_detach", sh_pthread_detach);
    register_shim("_pthread_self", sh_pthread_self);
    register_shim("_pthread_equal", sh_ret1);
    register_shim("_pthread_mutex_init", sh_mutex_init);
    register_shim("_pthread_mutex_lock", sh_mutex_lock);
    register_shim("_pthread_mutex_unlock", sh_mutex_unlock);
    register_shim("_pthread_mutex_trylock", sh_mutex_trylock);
    register_shim("_pthread_mutex_destroy", sh_mutex_destroy);
    register_shim("_pthread_mutexattr_init", sh_mutexattr);
    register_shim("_pthread_mutexattr_destroy", sh_mutexattr);
    register_shim("_pthread_mutexattr_settype", sh_mutexattr);
    register_shim("_pthread_cond_init", sh_cond_init);
    register_shim("_pthread_cond_destroy", sh_cond_init);
    register_shim("_pthread_cond_wait", sh_cond_wait);
    register_shim("_pthread_cond_timedwait", sh_cond_wait);
    register_shim("_pthread_cond_signal", sh_cond_signal);
    register_shim("_pthread_cond_broadcast", sh_cond_signal);
    register_shim("_pthread_rwlock_init", sh_mutex_init);
    register_shim("_pthread_rwlock_destroy", sh_mutex_destroy);
    register_shim("_pthread_rwlock_rdlock", sh_mutex_lock);
    register_shim("_pthread_rwlock_wrlock", sh_mutex_lock);
    register_shim("_pthread_rwlock_tryrdlock", sh_mutex_trylock);
    register_shim("_pthread_rwlock_trywrlock", sh_mutex_trylock);
    register_shim("_pthread_rwlock_unlock", sh_mutex_unlock);
    register_shim("_pthread_key_create", sh_key_create);
    register_shim("_pthread_key_delete", sh_ret0);
    register_shim("_pthread_getspecific", sh_getspecific);
    register_shim("_pthread_setspecific", sh_setspecific);
    register_shim("_pthread_once", sh_pthread_once);
    register_shim("_pthread_attr_init", sh_ret0);
    register_shim("_pthread_attr_destroy", sh_ret0);
    register_shim("_pthread_attr_setdetachstate", sh_ret0);
    register_shim("_pthread_attr_setstacksize", sh_ret0);
    register_shim("_pthread_sigmask", sh_ret0);
    register_shim("_pthread_setcanceltype", sh_ret0);
    register_shim("_pthread_setschedparam", sh_ret0);
    register_shim("_pthread_getschedparam", sh_ret0);
    register_shim("_pthread_set_qos_class_self_np", sh_ret0);
    register_shim("_setjmp", sh_setjmp);
    register_shim("__setjmp", sh_setjmp);
    register_shim("_longjmp", sh_longjmp);
    register_shim("__longjmp", sh_longjmp);
    register_shim("_dispatch_async", sh_dispatch_async);
    register_shim("_dispatch_sync", sh_dispatch_async);
    register_shim("_dispatch_once", sh_dispatch_once);
    register_shim("_dispatch_once_f", sh_dispatch_once_f);
    register_shim("_dispatch_get_global_queue", sh_queue);
    register_shim("_dispatch_queue_create", sh_queue);
    register_shim("_dispatch_release", sh_dispatch_release);
    register_shim("_dispatch_semaphore_create", sh_sem_create);
    register_shim("_dispatch_semaphore_signal", sh_sem_signal);
    register_shim("_dispatch_semaphore_wait", sh_sem_wait);
    register_shim("_dispatch_data_create", sh_ret0);
    register_shim("_dlopen", sh_dlopen);
    register_shim("_dlsym", sh_dlsym);
    register_shim("_dlclose", sh_dlclose);
    register_shim("_dlerror", sh_dlerror);
    register_shim("_dladdr", sh_dladdr);
    register_shim("__dyld_image_count", sh_dyld_count);
    register_shim("__dyld_get_image_header", sh_dyld_header);
    register_shim("__dyld_get_image_name", sh_dyld_name);
    register_shim("_getsectiondata", sh_getsectiondata);
    register_shim("___cxa_atexit", sh_cxa_atexit);
    register_shim("_atexit", sh_ret0);
    register_shim("__ZNSt3__111__call_onceERVmPvPFvS2_E", sh_call_once);
    register_shim("___cxa_guard_acquire", sh_guard_acq);
    register_shim("___cxa_guard_release", sh_guard_rel);
    register_shim("___cxa_guard_abort", sh_guard_abort);
    register_shim("___cxa_throw", sh_throw);
    register_shim("___cxa_rethrow", sh_throw);
    register_shim("___cxa_allocate_exception", sh_new);
    register_shim("___cxa_free_exception", sh_delete);
    register_shim("___cxa_begin_catch", sh_ret0);
    register_shim("___cxa_end_catch", sh_ret0);
    register_shim("___cxa_pure_virtual", sh_pure);
    register_shim("__Unwind_Resume", sh_throw);
    register_shim("__ZSt9terminatev", sh_abort);
    register_shim("__Znwm", sh_new);
    register_shim("__Znam", sh_new);
    register_shim("__ZdlPv", sh_delete);
    register_shim("__ZdaPv", sh_delete);
    register_shim("_objc_msgSend", sh_objc_msg);
    register_shim("_objc_msgSendSuper2", sh_objc_msg_super);
    register_shim("_objc_alloc", sh_objc_alloc);
    register_shim("_objc_alloc_init", sh_objc_alloc_init);
    register_shim("_objc_opt_new", sh_objc_opt_new);
    register_shim("_objc_retain", sh_retain);
    register_shim("_objc_release", sh_release);
    register_shim("_objc_autorelease", sh_autorelease);
    register_shim("_objc_retainAutorelease", sh_retain);
    register_shim("_objc_retainAutoreleaseReturnValue", sh_retain);
    register_shim("_objc_autoreleaseReturnValue", sh_autorelease);
    register_shim("_objc_retainAutoreleasedReturnValue", sh_retain);
    register_shim("_objc_unsafeClaimAutoreleasedReturnValue", sh_retain);
    register_shim("_objc_claimAutoreleasedReturnValue", sh_retain);
    register_shim("_objc_autoreleasePoolPush", sh_pool_push);
    register_shim("_objc_autoreleasePoolPop", sh_pool_pop);
    register_shim("_objc_storeStrong", sh_store_strong);
    register_shim("_objc_storeWeak", sh_store_strong);
    register_shim("_objc_loadWeakRetained", sh_load_weak);
    register_shim("_objc_loadWeak", sh_load_weak);
    register_shim("_objc_destroyWeak", sh_destroy_weak);
    register_shim("_objc_copyWeak", sh_copy_weak);
    register_shim("_objc_setProperty_nonatomic_copy", sh_store_strong);
    register_shim("_objc_setAssociatedObject", sh_ret0);
    register_shim("_objc_getClass", sh_get_class);
    register_shim("_class_getName", sh_class_name);
    register_shim("_sel_registerName", sh_sel_reg);
    register_shim("_sel_getName", sh_sel_name);
    register_shim("_objc_sync_enter", sh_sync_enter);
    register_shim("_objc_sync_exit", sh_sync_exit);
    register_shim("_objc_begin_catch", sh_ret0);
    register_shim("_objc_end_catch", sh_ret0);
    register_shim("_objc_enumerationMutation", sh_ret0);
    register_shim("_NSLog", sh_nslog);
    register_shim("_NSClassFromString", sh_class_from_string);
    register_shim("_NSSearchPathForDirectoriesInDomains", sh_search_path);
    register_shim("_opendir", sh_opendir);
    register_shim("_readdir", sh_readdir);
    register_shim("_closedir", sh_closedir);
    register_shim("_socket", sh_socket);
    register_shim("_socketpair", sh_ret0);
    register_shim("_connect", sh_connect);
    register_shim("_connectx", sh_connect);
    register_shim("_bind", sh_bind);
    register_shim("_listen", sh_listen);
    register_shim("_accept", sh_accept);
    register_shim("_send", sh_send);
    register_shim("_sendto", sh_send);
    register_shim("_recv", sh_recv);
    register_shim("_recvfrom", sh_recv);
    register_shim("_setsockopt", sh_setsockopt);
    register_shim("_getsockopt", sh_ret0);
    register_shim("_getaddrinfo", sh_getaddrinfo);
    register_shim("_freeaddrinfo", sh_freeaddrinfo);
    register_shim("_poll", sh_poll);
    register_shim("_select", sh_ret0);
    register_shim("_gethostname", sh_gethostname);
    register_shim("_inet_ntop", sh_ret0);
    register_shim("_inet_pton", sh_ret0);
    register_shim("_ioctl", sh_ret0);
    register_shim("_qsort", sh_qsort);
    register_shim("_arc4random", sh_arc4);
    register_shim("_random", sh_arc4);
    register_shim("_rand", sh_arc4);
    register_shim("_srand", sh_ret0);
    register_shim("_srandomdev", sh_ret0);
    register_shim("_CCRandomGenerateBytes", sh_ccrandom);
    register_shim("_cos", sh_cos);
    register_shim("_sin", sh_sin);
    register_shim("_tan", sh_tan);
    register_shim("_acos", sh_acos);
    register_shim("_asin", sh_asin);
    register_shim("_atan", sh_atan);
    register_shim("_cosh", sh_cosh);
    register_shim("_sinh", sh_sinh);
    register_shim("_tanh", sh_tanh);
    register_shim("_exp", sh_exp);
    register_shim("_exp2", sh_exp2);
    register_shim("_log", sh_log);
    register_shim("_log10", sh_log10);
    register_shim("_log2", sh_log2);
    register_shim("_cbrt", sh_cbrt);
    register_shim("_cosf", sh_cosf);
    register_shim("_sinf", sh_sinf);
    register_shim("_tanf", sh_tanf);
    register_shim("_acosf", sh_acosf);
    register_shim("_asinf", sh_asinf);
    register_shim("_atanf", sh_atanf);
    register_shim("_expf", sh_expf);
    register_shim("_exp2f", sh_exp2f);
    register_shim("_logf", sh_logf);
    register_shim("_log10f", sh_log10f);
    register_shim("_log2f", sh_log2f);
    register_shim("_cbrtf", sh_cbrtf);
    register_shim("_pow", sh_pow);
    register_shim("_atan2", sh_atan2);
    register_shim("_fmod", sh_fmod);
    register_shim("_hypot", sh_hypot);
    register_shim("_powf", sh_powf);
    register_shim("_atan2f", sh_atan2f);
    register_shim("_fmodf", sh_fmodf);
    register_shim("_hypotf", sh_hypotf);
    register_shim("_CGDisplayPixelsWide", sh_pixels_wide);
    register_shim("_CGDisplayPixelsHigh", sh_pixels_high);
    register_shim("_CGMainDisplayID", sh_main_display);
    register_shim("_CGDisplayBounds", sh_display_bounds);
    register_shim("_CGDisplayIsMain", sh_ret1);
    register_shim("_CGGetOnlineDisplayList", sh_online_displays);
    register_shim("_CGGetActiveDisplayList", sh_online_displays);
    register_shim("_CGDisplayCopyDisplayMode", sh_copy_display_mode);
    register_shim("_CGDisplayCopyAllDisplayModes", sh_copy_all_modes);
    register_shim("_CGDisplayModeGetWidth", sh_mode_w);
    register_shim("_CGDisplayModeGetHeight", sh_mode_h);
    register_shim("_CGDisplayModeGetPixelWidth", sh_mode_w);
    register_shim("_CGDisplayModeGetPixelHeight", sh_mode_h);
    register_shim("_CGDisplayModeGetIOFlags", sh_ret0);
    register_shim("_CGDisplayModeGetRefreshRate", sh_mode_hz);
    register_shim("_CGDisplayModeIsUsableForDesktopGUI", sh_mode_usable);
    register_shim("_CGDisplayModeRelease", sh_ret0);
    register_shim("_CGDisplayModeCopyPixelEncoding", sh_ret0);
    register_shim("_CGDisplayRegisterReconfigurationCallback", sh_ret0);
    register_shim("_CGDisplayRemoveReconfigurationCallback", sh_ret0);
    register_shim("_CGDisplayMirrorsDisplay", sh_ret0);
    register_shim("_CGDisplayFade", sh_ret0);
    register_shim("_CGDisplaySetDisplayMode", sh_ret0);
    register_shim("_CFArrayGetCount", sh_cfarray_count);
    register_shim("_CFArrayGetValueAtIndex", sh_cfarray_at);
    register_shim("_CFArrayCreate", sh_cfarray_create);
    register_shim("_CFArrayCreateMutable", sh_cfarray_create);
    register_shim("_TISCopyCurrentKeyboardLayoutInputSource", sh_tis_source);
    register_shim("_TISGetInputSourceProperty", sh_tis_prop);
    register_shim("_CVDisplayLinkCreateWithActiveCGDisplays", sh_cv_create_active);
    register_shim("_CVDisplayLinkCreateWithCGDisplay", sh_cv_create_display);
    register_shim("_CVDisplayLinkGetNominalOutputVideoRefreshPeriod", sh_cv_period);
    register_shim("_CVDisplayLinkSetOutputCallback", sh_ret0);
    register_shim("_CVDisplayLinkStart", sh_ret0);
    register_shim("_CVDisplayLinkStop", sh_ret0);
    register_shim("_CVDisplayLinkRelease", sh_ret0);
    register_shim("_CVDisplayLinkSetCurrentCGDisplayFromOpenGLContext", sh_ret0);
    register_shim("_CTFontGetAscent", sh_font_metric);
    register_shim("_CTFontGetDescent", sh_font_metric);
    register_shim("_CTFontGetLeading", sh_font_metric);
    register_shim("_CTFontGetCapHeight", sh_font_metric);
    register_shim("_CTFontGetXHeight", sh_font_metric);
    register_shim("_CTFontGetSize", sh_font_metric);
    register_shim("_CTFontGetUnitsPerEm", sh_font_metric);
    register_shim("_AudioObjectGetPropertyData", sh_audio_get);
    register_shim("_AudioObjectGetPropertyDataSize", sh_audio_size);
    register_shim("_AudioObjectSetPropertyData", sh_ret0);
    register_shim("_AudioObjectAddPropertyListener", sh_ret0);
    register_shim("_AudioObjectRemovePropertyListener", sh_ret0);
    register_shim("_AudioDeviceCreateIOProcID", sh_ret0);
    register_shim("_AudioDeviceDestroyIOProcID", sh_ret0);
    register_shim("_AudioDeviceStart", sh_ret0);
    register_shim("_AudioDeviceStop", sh_ret0);
    register_shim("_AudioHardwareCreateAggregateDevice", sh_ret0);
    register_shim("_AudioHardwareDestroyAggregateDevice", sh_ret0);
    register_shim("_AudioHardwareCreateProcessTap", sh_ret0);
    register_shim("_AudioHardwareDestroyProcessTap", sh_ret0);
    register_shim("_AudioQueueNewInput", sh_ret0);
    register_shim("_AudioQueueNewOutput", sh_ret0);
    register_shim("_AudioQueueAllocateBuffer", sh_ret0);
    register_shim("_AudioQueueEnqueueBuffer", sh_ret0);
    register_shim("_AudioQueueStart", sh_ret0);
    register_shim("_AudioQueueStop", sh_ret0);
    register_shim("_AudioQueueFlush", sh_ret0);
    register_shim("_AudioQueueSetProperty", sh_ret0);
    register_shim("_AudioQueueDispose", sh_ret0);
    register_shim("_CFRunLoopRunInMode", sh_cf_runloop);
    register_shim("_CFRunLoopGetMain", sh_ret1);
    register_shim("_CFRunLoopGetCurrent", sh_ret1);
    register_shim("_CFRunLoopStop", sh_ret0);
    register_shim("_CFRunLoopWakeUp", sh_ret0);
    register_shim("_CFRelease", sh_cf_release);
    register_shim("_CFRetain", sh_cf_retain);
    register_shim("_CFStringGetCStringPtr", sh_cf_string_ptr);
    register_shim("_CFStringGetLength", sh_cf_string_len);
    register_shim("_CFStringGetCString", sh_ret0);
    register_shim("_CFStringCreateWithCString", sh_cf_string_create);
    register_shim("_CFStringCreateWithBytes", sh_cf_string_create);
    register_shim("_CFBundleGetMainBundle", sh_cf_bundle);
    register_shim("_CFAbsoluteTimeGetCurrent", sh_ca_time);
    register_shim("_CFEqual", sh_ret0);
    register_shim("__availability_version_check", sh_availability);
    register_shim("_mach_msg", sh_mach_msg);
    register_shim("_mach_host_self", sh_host_self);
    register_shim("_host_get_clock_service", sh_ret0);
    register_shim("_mach_port_deallocate", sh_ret0);
    register_shim("_mach_error_string", sh_ret0);
    register_shim("__NSGetEnviron", sh_ns_environ);
    register_shim("__Block_object_assign", sh_block_assign);
    register_shim("__Block_object_dispose", sh_block_dispose);
    register_shim("_signal", sh_ret0);
    register_shim("_sigaction", sh_ret0);
    register_shim("_setlocale", sh_ret0);
    register_shim("_localeconv", sh_localeconv);
    register_shim("___lb_streambuf_eof", sh_streambuf_eof);
    register_shim("___lb_filebuf_xsputn", sh_filebuf_xsputn);
    register_shim("__ZNSt3__112__next_primeEm", sh_next_prime);
    register_shim("__ZNSt3__16localeC1Ev", sh_locale_ctor);
    register_shim("__ZNSt3__16localeC2Ev", sh_locale_ctor);
    register_shim("__ZNSt3__16localeC1ERKS0_", sh_locale_copy);
    register_shim("__ZNSt3__16localeC2ERKS0_", sh_locale_copy);
    register_shim("__ZNSt3__16localeD1Ev", sh_locale_dtor);
    register_shim("__ZNKSt3__16locale9use_facetERNS0_2idE", sh_use_facet);
    register_shim("__ZNKSt3__16locale4nameEv", sh_locale_name);
    register_shim("__lb_facet_call", sh_facet_call);
    register_shim("__ZNSt3__16localeD2Ev", sh_locale_dtor);
    register_shim("__ZNSt3__18ios_base4initEPv", sh_ios_init);
    register_shim("__ZNSt3__18ios_base5clearEj", sh_ios_clear);
    register_shim("__ZNSt3__113basic_filebufIcNS_11char_traitsIcEEEC1Ev", sh_filebuf_ctor);
    register_shim("__ZNSt3__113basic_filebufIcNS_11char_traitsIcEEE4openEPKcj", sh_filebuf_open);
    register_shim("__ZNSt3__113basic_filebufIcNS_11char_traitsIcEEED1Ev", sh_nop);
    register_shim("__ZNSt3__113basic_istreamIcNS_11char_traitsIcEEED2Ev", sh_nop);
    register_shim("__ZNSt3__19basic_iosIcNS_11char_traitsIcEEED2Ev", sh_nop);
    register_shim("__ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE9push_backEc", sh_string_push);
    register_shim("__ZNSt13runtime_errorC1EPKc", sh_runtime_error);
    register_shim("__ZNSt13runtime_errorC1ERKS_", sh_runtime_error_copy);
    register_shim("__ZNSt3__19to_stringEi", sh_to_string_int);
    register_shim("__ZNSt3__19to_stringEm", sh_to_string_ulong);
    register_shim("__ZNSt3__113basic_istreamIcNS_11char_traitsIcEEE5seekgExNS_8ios_base7seekdirE", sh_seekg);
    register_shim("__ZNSt3__113basic_istreamIcNS_11char_traitsIcEEE5tellgEv", sh_tellg);
    register_shim("__ZNSt3__16chrono12steady_clock3nowEv", sh_steady_now);
    register_shim("__ZNSt3__15mutex4lockEv", sh_nop);
    register_shim("__ZNSt3__15mutex6unlockEv", sh_nop);
    register_shim("__ZNSt3__115recursive_mutexC1Ev", sh_nop);
    register_shim("__ZNSt3__115recursive_mutex4lockEv", sh_nop);
    register_shim("__ZNSt3__115recursive_mutex6unlockEv", sh_nop);
    register_shim("__ZNSt3__115__thread_structC1Ev", sh_nop);
    register_shim("__ZNSt3__16thread6detachEv", sh_nop);
    register_shim("__ZNSt3__16threadD1Ev", sh_nop);
    register_shim("__ZNSt3__14__fs10filesystem8__statusERKNS1_4pathEPNS_10error_codeE", sh_fs_status);
    register_shim("__ZNSt3__14__fs10filesystem14__current_pathEPNS_10error_codeE", sh_fs_cwd);
    register_shim("__ZNKSt3__14__fs10filesystem4path16__root_directoryEv", sh_fs_root);
    register_shim("__ZNKSt3__14__fs10filesystem4path13__parent_pathEv", sh_fs_parent);
    register_shim("__ZNSt3__14__fs10filesystem20__create_directoriesERKNS1_4pathEPNS_10error_codeE", sh_fs_mkdirs);
    register_shim("__ZNSt3__14__fs10filesystem8__renameERKNS1_4pathES4_PNS_10error_codeE", sh_fs_rename);
    register_shim("__ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE21__grow_by_and_replaceEmmmmmmPKc", sh_string_grow);
    register_shim("__ZNSt3__115system_categoryEv", sh_system_category);
    register_shim("__ZNSt3__119__shared_weak_count14__release_weakEv", sh_nop);
    register_shim("__ZNSt3__113basic_ostreamIcNS_11char_traitsIcEEE6sentryC1ERS3_", sh_sentry_ctor);
    register_shim("__ZNSt3__113basic_ostreamIcNS_11char_traitsIcEEE6sentryD1Ev", sh_nop);
    register_shim("__ZNSt3__113basic_ostreamIcNS_11char_traitsIcEEE5flushEv", sh_nop);
    register_shim("__ZNSt3__113basic_ostreamIcNS_11char_traitsIcEEED2Ev", sh_nop);
    register_shim("__lb_nop", sh_nop);
    register_shim("_CFStringCompare", sh_cf_string_cmp);
    register_shim("_CFArrayAppendValue", sh_cf_array_append);
    register_shim("_CFDataGetBytePtr", sh_cf_data_ptr);
    register_shim("_CFDataCreate", sh_cf_data_create);
    register_shim("_CFDictionaryCreateMutable", sh_cf_dict_new);
    register_shim("_CFDictionaryAddValue", sh_cf_dict_add);
    register_shim("_CFDictionaryGetValueIfPresent", sh_cf_dict_get);
    register_shim("_CFDictionaryGetTypeID", sh_cf_dict_type);
    register_shim("_CFGetTypeID", sh_cf_get_type);
    register_shim("_CFNumberCreate", sh_cf_number);
    register_shim("_CFSetCreate", sh_cf_set_create);
    register_shim("_CFURLCreateWithFileSystemPath", sh_cf_url);
    register_shim("_CFURLGetFileSystemRepresentation", sh_cf_url_path);
    register_shim("_CFBundleCopyResourcesDirectoryURL", sh_cf_resources_url);
    register_shim("_CFLocaleCopyPreferredLanguages", sh_cf_languages);
    register_shim("_CTFontDescriptorCreateWithAttributes", sh_ct_font);
    register_shim("_CTFontDescriptorCreateMatchingFontDescriptor", sh_ct_font);
    register_shim("_CTFontCreateWithFontDescriptor", sh_ct_font);
    register_shim("_CTFontCopyFontDescriptor", sh_ct_font);
    register_shim("_CTFontDescriptorCopyAttribute", sh_ct_font);
    register_shim("_CTFontManagerCreateFontDescriptorFromData", sh_ct_font);
    register_shim("_CTFontCollectionCreateFromAvailableFonts", sh_ct_font);
    register_shim("_CTFontManagerCopyAvailableFontFamilyNames", sh_ct_families);
    register_shim("_CTFontGetSymbolicTraits", sh_ct_traits);
    register_shim("_CTFontManagerRegisterFontsForURL", sh_ct_register);
    register_shim("_IOPMAssertionCreateWithDescription", sh_iopm);
    register_shim("_CGDisplayIOServicePort", sh_display_service);
    register_shim("_IODisplayCreateInfoDictionary", sh_display_info);
    register_shim("__ZNSt3__119__thread_local_dataEv", sh_thread_local_data);
    register_shim("_uselocale", sh_ret1);
    register_shim("_newlocale", sh_ret1);
    register_shim("_freelocale", sh_ret0);
    g_exit_shim = resolve_symbol("_exit", 0);
}

bool exact_data(const std::string& n) {
    static const char* k[] = {
        "___stack_chk_guard", "___CFConstantStringClassReference", "___stderrp", "___stdinp", "___stdoutp",
        "___NSArray0__struct", "___NSDictionary0__struct", "___kCFBooleanFalse", "___kCFBooleanTrue",
        "__DefaultRuneLocale", "__NSConcreteGlobalBlock", "__NSConcreteStackBlock", "__dispatch_main_q",
        "_NSApp", "_NSZeroPoint", "_NSZeroRect", "_NSAppKitVersionNumber", "_NSFontWeightRegular",
        "_environ", "__objc_empty_cache", "_mach_task_self_", nullptr};
    for (int i = 0; k[i]; ++i)
        if (n == k[i]) return true;
    return false;
}

uint64_t make_data_bytes(const std::string& name, size_t n) {
    auto it = g_data.find(name);
    if (it != g_data.end()) return it->second.addr;
    size_t bytes = std::max<size_t>(n, 64);
    void* p = std::calloc(1, bytes);
    DataSym d;
    d.name = name;
    d.addr = reinterpret_cast<uint64_t>(p);
    d.size = bytes;
    g_data.emplace(name, d);
    return d.addr;
}

uint64_t make_vtable(const std::string& name) {
    auto it = g_data.find(name);
    if (it != g_data.end()) return it->second.addr;
    // Eight words of prefix so a vptr (symbol+16) can read the virtual-base
    // offset at vptr-24, which lands at symbol-8.
    constexpr size_t kPrefix = 64;
    constexpr int kSlots = 64;
    void* mem = std::calloc(1, kPrefix + static_cast<size_t>(kSlots) * 8);
    uint64_t addr = reinterpret_cast<uint64_t>(mem) + kPrefix;
    DataSym d;
    d.name = name;
    d.addr = addr;
    d.size = static_cast<size_t>(kSlots) * 8;
    g_data.emplace(name, d);
    uint64_t fn = resolve_symbol("___lb_vtable_slot", 0);
    auto* slots = reinterpret_cast<uint64_t*>(addr);
    // basic_ofstream / basic_ifstream place the virtual basic_ios at +0x1a0.
    // A construction path also installs the vptr eight bytes higher, and
    // then reads this word via vptr-24.
    uint64_t vbase = 0;
    if (name.find("basic_ofstream") != std::string::npos || name.find("basic_ifstream") != std::string::npos)
        vbase = 0x1a0;
    slots[0] = 0;
    slots[1] = make_data_bytes(name + ".ti", 32);
    for (int i = 2; i < kSlots; ++i) slots[i] = fn;
    std::memcpy(reinterpret_cast<void*>(addr - 8), &vbase, 8);
    return addr;
}

uint64_t make_vtt(const std::string& name) {
    auto it = g_data.find(name);
    if (it != g_data.end()) return it->second.addr;
    std::string vtable = name;
    auto pos = vtable.find("ZTT");
    if (pos != std::string::npos) vtable.replace(pos, 3, "ZTV");
    uint64_t vt = make_vtable(vtable);
    uint64_t addr = make_data_bytes(name, 32 * 8);
    auto* entries = reinterpret_cast<uint64_t*>(addr);
    for (int i = 0; i < 32; ++i) entries[i] = vt + 16;
    return addr;
}

}  // namespace

MachImage* g_image = nullptr;
uint64_t g_debug_load_addr = 0;
std::string g_bundle;
std::string g_exe;
uint64_t g_nsapp = 0;

void shim_arena_init() {
    if (g_shim_base) return;
    size_t span = 16u << 20;
    void* p = ::mmap(reinterpret_cast<void*>(kPreferredShimBase), span, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
    if (p == MAP_FAILED) p = ::mmap(nullptr, span, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    g_shim_base = reinterpret_cast<uint64_t>(p);
    g_shim_span = span;
    register_shim("___lb_vtable_slot", sh_ret0);
}

void register_shim(const std::string& name, ShimFn fn) {
    auto it = g_shim_by_name.find(name);
    if (it != g_shim_by_name.end()) {
        g_shims[it->second].fn = fn;
        return;
    }
    Shim s;
    s.name = name;
    s.fn = fn;
    s.addr = g_shim_base + g_shims.size() * 16;
    g_shim_by_name.emplace(name, g_shims.size());
    g_shims.push_back(std::move(s));
}

bool is_data_symbol(const std::string& n) {
    if (g_shim_by_name.count(n)) return false;
    if (n.rfind("_OBJC_", 0) == 0) return true;
    if (n.find("ZTV") != std::string::npos || n.find("ZTI") != std::string::npos || n.find("ZTS") != std::string::npos ||
        n.find("ZTT") != std::string::npos)
        return true;
    if (exact_data(n)) return true;
    if (n.size() >= 3 && n[0] == '_' && n[1] == 'k' && std::isupper(static_cast<unsigned char>(n[2]))) return true;
    if (n.size() >= 4 && n[0] == '_' && n[1] == '_' && n[2] == 'k' && std::isupper(static_cast<unsigned char>(n[3]))) return true;
    if (n.find("Notification") != std::string::npos) return true;
    if (n.find("RunLoopMode") != std::string::npos) return true;
    if (n.find("ColorSpace") != std::string::npos) return true;
    if (n.find("AttributeName") != std::string::npos) return true;
    if (n.find("Pboard") != std::string::npos || n.find("Pasteboard") != std::string::npos) return true;
    if (n.find("AppearanceName") != std::string::npos) return true;
    if (n.size() > 4 && n.rfind("Key") == n.size() - 3 && n[0] == '_') return true;
    if (n.rfind("_AV", 0) == 0) return true;
    if (n.rfind("_UTType", 0) == 0 && n.find("Copy") == std::string::npos && n.find("Create") == std::string::npos) return true;
    return false;
}

uint64_t data_symbol(const std::string& name, size_t bytes) { return make_data_bytes(name, bytes); }

void data_store_u64(const std::string& name, uint64_t value) {
    uint64_t addr = make_data_bytes(name, 8);
    std::memcpy(reinterpret_cast<void*>(addr), &value, 8);
}

const char* shim_name_at(uint64_t pc) {
    if (!g_shim_base || pc < g_shim_base || pc >= g_shim_base + g_shim_span) return nullptr;
    size_t index = static_cast<size_t>((pc - g_shim_base) / 16);
    if (index >= g_shims.size()) return nullptr;
    return g_shims[index].name.c_str();
}

void note_unknown(const std::string& name) {
    std::lock_guard<std::mutex> lock(g_mu);
    if (g_unknown.size() >= 48) return;
    for (const auto& s : g_unknown)
        if (s == name) return;
    g_unknown.push_back(name);
}
std::vector<std::string> unknown_symbols() {
    std::lock_guard<std::mutex> lock(g_mu);
    return g_unknown;
}

uint64_t resolve_symbol(const std::string& name, int) {
    auto it = g_shim_by_name.find(name);
    if (it != g_shim_by_name.end()) return g_shims[it->second].addr;
    if (name.rfind("_OBJC_CLASS_$_", 0) == 0) return ensure_class(name.substr(14), "NSObject", 128);
    if (name.rfind("_OBJC_METACLASS_$_", 0) == 0) {
        ensure_class(name.substr(17), "NSObject", 128);
        return class_ptr(name.substr(17)) ? read_u64(class_ptr(name.substr(17))) : 0;
    }
    if (name == "___CFConstantStringClassReference") {
        ensure_class("__NSCFString", "NSString", 64);
        return class_ptr("__NSCFString");
    }
    if (name == "__NSConcreteGlobalBlock" || name == "__NSConcreteStackBlock") {
        ensure_class(name, "NSObject", 64);
        return class_ptr(name);
    }
    if (is_data_symbol(name)) {
        if (name.find("ZTT") != std::string::npos) return make_vtt(name);
        if (name.find("ZTV") != std::string::npos) return make_vtable(name);
        uint64_t addr = make_data_bytes(name, 256);
        if (name.find("Notification") != std::string::npos || name.find("Name") != std::string::npos ||
            name.find("Mode") != std::string::npos || name.find("Key") != std::string::npos ||
            name.find("ColorSpace") != std::string::npos || name.find("Pboard") != std::string::npos ||
            name.rfind("_AV", 0) == 0 || name.rfind("_UTType", 0) == 0) {
            uint64_t s = make_string(name.c_str() + 1);
            std::memcpy(reinterpret_cast<void*>(addr), &s, 8);
        }
        return addr;
    }
    register_shim(name, sh_unknown);
    return g_shims[g_shim_by_name[name]].addr;
}

uint64_t read_u64(uint64_t addr) {
    uint64_t v = 0;
    if (addr) std::memcpy(&v, reinterpret_cast<void*>(tbi(addr)), 8);
    return v;
}
void write_u64(uint64_t addr, uint64_t value) {
    if (addr) std::memcpy(reinterpret_cast<void*>(tbi(addr)), &value, 8);
}
const char* guest_cstr(uint64_t addr) {
    if (!addr) return nullptr;
    return reinterpret_cast<const char*>(tbi(addr));
}
bool tracing() {
    static int v = -1;
    if (v < 0) v = std::getenv("LB_TRACE") ? 1 : 0;
    return v;
}

int guest_format(char* out, size_t cap, const char* fmt, Guest& g, int first_gpr, int first_vec) {
    if (!out || cap == 0) return 0;
    out[0] = 0;
    if (!fmt) return 0;
    std::string o;
    int gi = first_gpr;
    int vi = first_vec;
    auto next_i = [&]() -> uint64_t {
        if (gi >= 0 && gi <= 7) return g.x[gi++];
        uint64_t addr = g.sp + static_cast<uint64_t>(gi - 8) * 8;
        ++gi;
        return read_u64(addr);
    };
    auto next_d = [&]() -> double {
        double d = 0;
        if (vi >= 0 && vi < 8) std::memcpy(&d, g.v[vi++], 8);
        return d;
    };
    for (const char* p = fmt; *p && o.size() + 1 < cap;) {
        if (*p != '%') {
            o.push_back(*p++);
            continue;
        }
        ++p;
        if (*p == '%') {
            o.push_back('%');
            ++p;
            continue;
        }
        while (*p && std::strchr("-+ 0#", *p)) ++p;
        while (*p && std::isdigit(static_cast<unsigned char>(*p))) ++p;
        if (*p == '*') {
            next_i();
            ++p;
        }
        if (*p == '.') {
            ++p;
            while (*p && std::isdigit(static_cast<unsigned char>(*p))) ++p;
        }
        int lng = 0;
        while (*p == 'l' || *p == 'z' || *p == 'h') {
            if (*p == 'l') ++lng;
            ++p;
        }
        char spec = *p ? *p++ : 0;
        char tmp[128];
        if (spec == 's') {
            const char* s = guest_cstr(next_i());
            o += s ? s : "(null)";
        } else if (spec == 'd' || spec == 'i') {
            int64_t v = static_cast<int64_t>(next_i());
            if (lng == 0) v = static_cast<int32_t>(v);
            std::snprintf(tmp, sizeof(tmp), "%lld", static_cast<long long>(v));
            o += tmp;
        } else if (spec == 'u') {
            std::snprintf(tmp, sizeof(tmp), "%llu", static_cast<unsigned long long>(next_i()));
            o += tmp;
        } else if (spec == 'x' || spec == 'X' || spec == 'p') {
            unsigned long long v = next_i();
            if (spec == 'p') std::snprintf(tmp, sizeof(tmp), "0x%llx", v);
            else if (spec == 'X') std::snprintf(tmp, sizeof(tmp), "%llX", v);
            else std::snprintf(tmp, sizeof(tmp), "%llx", v);
            o += tmp;
        } else if (spec == 'f' || spec == 'g' || spec == 'e') {
            std::snprintf(tmp, sizeof(tmp), "%g", next_d());
            o += tmp;
        } else if (spec == 'c') {
            o.push_back(static_cast<char>(next_i()));
        } else {
            o.push_back('%');
            if (spec) o.push_back(spec);
        }
    }
    if (o.size() >= cap) o.resize(cap - 1);
    std::memcpy(out, o.data(), o.size());
    out[o.size()] = 0;
    return static_cast<int>(o.size());
}

thread_local int g_call_depth = 0;

void reset_call_depth() { g_call_depth = 0; }

uint64_t call_guest(uint64_t pc, uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3, Guest* parent) {
    if (!pc) return 0;
    thread_local uint64_t stacks[8] {};
    int& depth = g_call_depth;
    if (depth >= 8) {
        if (parent) {
            parent->stop = 1;
            parent->stop_why = "call-depth";
        }
        return 0;
    }
    if (!stacks[depth]) {
        void* mem = ::mmap(nullptr, 1 << 20, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        stacks[depth] = mem ? reinterpret_cast<uint64_t>(mem) + (1 << 20) - 64 : 0;
    }
    Guest child;
    child.pc = pc;
    child.x[0] = a0;
    child.x[1] = a1;
    child.x[2] = a2;
    child.x[3] = a3;
    child.x[30] = kReturnPc;
    child.sp = stacks[depth];
    Guest* prev = g_cur;
    g_cur = &child;
    ++depth;
    dbt_run(child, 2000000);
    --depth;
    g_cur = prev;
    if (child.stop && child.stop != 5 && parent) {
        parent->stop = child.stop;
        parent->stop_why = child.stop_why;
        parent->stop_pc = child.stop_pc;
        parent->stop_insn = child.stop_insn;
    }
    if (parent) parent->steps += child.steps;
    return child.x[0];
}

std::string bridge_executable() {
    if (const char* e = std::getenv("LB_BRIDGE")) return e;
    char buf[4096];
    ssize_t n = ::readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    if (n > 0) {
        buf[n] = 0;
        std::string s = buf;
        auto slash = s.rfind('/');
        if (slash != std::string::npos) return s.substr(0, slash + 1) + "lb-mpris-bridge";
    }
    return "lb-mpris-bridge";
}

SpawnPlan plan_spawn(const std::string& path, const std::vector<std::string>& argv) {
    SpawnPlan plan;
    plan.argv = argv;
    bool stream = false;
    for (const auto& a : argv) {
        if (a.find("stream_all") != std::string::npos || a.find("mediasession") != std::string::npos) stream = true;
    }
    bool perl = path.find("perl") != std::string::npos;
    if (!perl) {
        for (const auto& a : argv)
            if (a.find("perl") != std::string::npos) perl = true;
    }
    if (perl && stream) {
        plan.bridge = true;
        plan.argv = {bridge_executable()};
    }
    return plan;
}

bool Runtime::init(const std::string& path, std::string& err) {
    shim_arena_init();
    objc_init();
    metal_init();
    register_libc();
    std::string bin = path;
    if (bin.size() > 4 && bin.substr(bin.size() - 4) == ".app") bin += "/Contents/MacOS/LyricsBlossom";
    if (!image.load(bin, err)) return false;
    g_image = &image;
    g_exe = bin;
    auto slash = bin.rfind("/Contents/MacOS/");
    g_bundle = slash == std::string::npos ? bin : bin.substr(0, slash);
    if (!image.apply_fixups([](const std::string& name, int ord) { return resolve_symbol(name, ord); }, err)) return false;
    objc_load_guest(image);
    objc_finish_data();
    data_store_u64("___stack_chk_guard", 0xC0FFEEULL);
    data_store_u64("___stderrp", reinterpret_cast<uint64_t>(stderr));
    data_store_u64("___stdoutp", reinterpret_cast<uint64_t>(stdout));
    data_store_u64("___stdinp", reinterpret_cast<uint64_t>(stdin));
    double ver = 2485;
    std::memcpy(reinterpret_cast<void*>(data_symbol("_NSAppKitVersionNumber", 8)), &ver, 8);
    data_store_u64("_mach_task_self_", 1);
    return true;
}

void Runtime::prepare(Guest& g, int argc, char** argv) {
    if (!g_guest_stack) {
        void* mem = ::mmap(nullptr, 8 << 20, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        g_guest_stack = mem ? reinterpret_cast<uint64_t>(mem) + (8 << 20) : 0;
    }
    std::vector<std::string> args;
    args.push_back(g_exe);
    for (int i = 1; i < argc; ++i) args.emplace_back(argv[i]);
    std::vector<std::string> envs;
    for (char** e = environ; e && *e; ++e) envs.emplace_back(*e);
    auto pack = [](const std::vector<std::string>& in) {
        std::vector<uint64_t> ptrs;
        for (const auto& s : in) {
            char* c = static_cast<char*>(std::malloc(s.size() + 1));
            std::memcpy(c, s.data(), s.size() + 1);
            ptrs.push_back(reinterpret_cast<uint64_t>(c));
        }
        auto* arr = static_cast<uint64_t*>(std::calloc(ptrs.size() + 1, 8));
        for (size_t i = 0; i < ptrs.size(); ++i) arr[i] = ptrs[i];
        return arr;
    };
    // Keep the string storage alive.
    static std::vector<std::string> keep_args;
    static std::vector<std::string> keep_env;
    keep_args = args;
    keep_env = envs;
    uint64_t* argp = pack(keep_args);
    uint64_t* envp = pack(keep_env);
    std::string apple = "executable_path=" + g_exe;
    uint64_t* ap = pack(std::vector<std::string> {apple});
    data_store_u64("_environ", reinterpret_cast<uint64_t>(envp));
    g = Guest {};
    g.x[0] = keep_args.size();
    g.x[1] = reinterpret_cast<uint64_t>(argp);
    g.x[2] = reinterpret_cast<uint64_t>(envp);
    g.x[3] = reinterpret_cast<uint64_t>(ap);
    g.x[30] = g_exit_shim;
    g.pc = image.entry;
    g.sp = g_guest_stack - 64;
}

void run_static_inits(MachImage& image) {
    static bool done = false;
    if (done) return;
    done = true;
    const MachSection* sec = image.find_section("__TEXT", "__init_offsets");
    if (!sec || sec->size < 4) return;
    install_handler();
    uint32_t count = static_cast<uint32_t>(sec->size / 4);
    Guest* saved = g_cur;
    for (uint32_t i = 0; i < count; ++i) {
        uint32_t off = 0;
        std::memcpy(&off, reinterpret_cast<void*>(sec->addr + static_cast<uint64_t>(i) * 4), 4);
        uint64_t pc = image.base + off;
        if (sigsetjmp(g_jmp, 1) != 0) {
            std::fprintf(stderr, "init %u/%u fault pc=%llx addr=%llx\n", i, count,
                         static_cast<unsigned long long>(g_fault_pc),
                         static_cast<unsigned long long>(g_fault_addr));
            reset_call_depth();
            g_armed = 0;
            g_cur = saved;
            continue;
        }
        g_armed = 1;
        Guest sink;
        call_guest(pc, 0, 0, 0, 0, &sink);
        g_armed = 0;
        g_cur = saved;
        if (sink.stop && sink.stop != 5) {
            std::fprintf(stderr, "init %u/%u stop=%s pc=%llx insn=%08x\n", i, count,
                         sink.stop_why ? sink.stop_why : "?",
                         static_cast<unsigned long long>(sink.stop_pc), sink.stop_insn);
        }
    }
}

uint64_t Runtime::run(Guest& g, uint64_t max_insns) {
    run_static_inits(image);
    uint64_t n = run_guarded(g, max_insns);
    std::fprintf(stderr, "stopped after %llu insns pc=0x%llx why=%s insn=0x%08x\n",
                 static_cast<unsigned long long>(n), static_cast<unsigned long long>(g.stop_pc ? g.stop_pc : g.pc),
                 g.stop_why ? g.stop_why : "budget", g.stop_insn);
    if (!unknown_symbols().empty()) {
        std::fprintf(stderr, "unresolved shims:");
        for (const auto& s : unknown_symbols()) std::fprintf(stderr, " %s", s.c_str());
        std::fprintf(stderr, "\n");
    }
    if (!missed_selectors().empty()) {
        std::fprintf(stderr, "unhandled selectors:");
        for (const auto& s : missed_selectors()) std::fprintf(stderr, " %s", s.c_str());
        std::fprintf(stderr, "\n");
    }
    // Join guest threads before main destroys the runtime. Otherwise a
    // translator is still in the code cache when the process exits.
    stop_guest_threads();
    return n;
}

extern "C" bool lb_try_shim(Guest* gp) {
    if (!gp) return false;
    Guest& g = *gp;
    if (g.pc == kReturnPc) {
        g.stop = 5;
        g.stop_why = "nested-return";
        return true;
    }
    if (!g_shim_base || g.pc < g_shim_base || g.pc >= g_shim_base + g_shim_span) return false;
    size_t index = static_cast<size_t>((g.pc - g_shim_base) / 16);
    if (index >= g_shims.size()) return false;
    g.redirect = false;
    g_shims[index].fn(g);
    g.steps++;
    if (!g.redirect && !g.stop) g.pc = g.x[30];
    g.redirect = false;
    return true;
}

}  // namespace lb

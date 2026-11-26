#include "lb/image.hpp"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <unordered_map>

namespace {

int g_fails = 0;

void check(bool ok, const char* what) {
    if (!ok) {
        std::fprintf(stderr, "FAIL %s\n", what);
        ++g_fails;
    }
}

const char* binary_path() {
    if (const char* e = std::getenv("LB_BINARY")) return e;
    return "/tmp/lyricsblossom/LyricsBlossom-arm/LyricsBlossom.app/Contents/MacOS/LyricsBlossom";
}

uint64_t load64(uint64_t addr) {
    uint64_t v = 0;
    std::memcpy(&v, reinterpret_cast<void*>(addr & 0x00ffffffffffffffull), 8);
    return v;
}

const char* cstr(uint64_t addr) {
    return reinterpret_cast<const char*>(addr & 0x00ffffffffffffffull);
}

}  // namespace

int main() {
    const char* path = binary_path();
    if (FILE* f = std::fopen(path, "rb")) {
        std::fclose(f);
    } else {
        std::printf("mach-o loader checks skipped (no LyricsBlossom binary)\n");
        return 0;
    }

    lb::MachImage img;
    std::string err;
    check(img.load(path, err), err.c_str());
    if (!img.base) return 1;
    check(img.dylibs.size() == 30, "dylib count");
    check(!img.dylibs.empty() && img.dylibs[0].find("libSystem") != std::string::npos, "libSystem");
    check(img.entry - img.base == 0x2becfc, "entry offset");

    int calls = 0;
    std::unordered_map<std::string, uint64_t> slots;
    uint64_t next = 0x700000000000ull;
    bool ok = img.apply_fixups(
        [&](const std::string& name, int) {
            ++calls;
            auto it = slots.find(name);
            if (it != slots.end()) return it->second;
            uint64_t a = next;
            next += 16;
            slots.emplace(name, a);
            return a;
        },
        err);
    check(ok, err.empty() ? "fixups" : err.c_str());
    check(calls == 2377, "bind sites");
    check(img.imports.size() == 1180, "import count");

    auto has = [&](const char* n) { return slots.count(n) != 0; };
    check(has("_objc_msgSend"), "objc_msgSend imported");
    check(has("_malloc"), "malloc imported");

    const lb::MachSection* cl = img.find_section("__DATA_CONST", "__objc_classlist");
    if (!cl) cl = img.find_section("__DATA", "__objc_classlist");
    check(cl && cl->size >= 8, "classlist");
    if (cl && cl->size >= 8) {
        uint64_t cls = load64(cl->addr);
        uint64_t bits = load64(cls + 32);
        uint64_t ro = bits & 0x00007ffffffffff8ull;
        uint64_t namep = load64(ro + 24);
        check(std::strcmp(cstr(namep), "LBMetalDisplayLinkDelegate") == 0, "first class name");
        uint64_t methods = load64(ro + 32);
        uint32_t entsize = 0, count = 0;
        std::memcpy(&entsize, reinterpret_cast<void*>(methods), 4);
        std::memcpy(&count, reinterpret_cast<void*>(methods + 4), 4);
        check(count == 3, "first class method count");
        int32_t name_rel = 0;
        std::memcpy(&name_rel, reinterpret_cast<void*>(methods + 8), 4);
        uint64_t name_field = methods + 8;
        uint64_t selref = name_field + static_cast<int64_t>(name_rel);
        uint64_t sel = load64(selref);
        check(std::strcmp(cstr(sel), "metalDisplayLink:needsUpdate:") == 0, "first selector");
        int classes = 0;
        for (uint64_t i = 0; i + 8 <= cl->size; i += 8) {
            if (load64(cl->addr + i)) ++classes;
        }
        check(classes == 26, "class count");
    }

    if (g_fails) {
        std::fprintf(stderr, "%d mach-o checks failed\n", g_fails);
        return 1;
    }
    std::printf("mach-o loader checks passed\n");
    return 0;
}

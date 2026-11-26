#include "lb/runtime.hpp"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

int main() {
    const char* path = std::getenv("LB_BINARY");
    if (!path) path = "/tmp/lyricsblossom/LyricsBlossom-arm/LyricsBlossom.app/Contents/MacOS/LyricsBlossom";
    FILE* f = std::fopen(path, "rb");
    if (!f) {
        std::printf("boot check skipped (no LyricsBlossom binary)\n");
        return 0;
    }
    std::fclose(f);
    setenv("LB_BOOT_TEST", "1", 1);
    if (!std::getenv("LB_RUNLOOP")) setenv("LB_RUNLOOP", "1", 1);
    lb::Runtime rt;
    std::string err;
    if (!rt.init(path, err)) {
        std::fprintf(stderr, "boot init failed: %s\n", err.c_str());
        return 1;
    }
    lb::Guest g;
    char arg0[] = "LyricsBlossom";
    char* av[] = {arg0, nullptr};
    rt.prepare(g, 1, av);
    uint64_t budget = 1500000;
    if (const char* e = std::getenv("LB_BOOT_INSNS")) budget = std::strtoull(e, nullptr, 10);
    uint64_t n = rt.run(g, budget);
    if (n < 10000) {
        std::fprintf(stderr, "boot stopped too early (%llu)\n", static_cast<unsigned long long>(n));
        return 1;
    }
    if (g.stop_why && std::strcmp(g.stop_why, "sigsegv") == 0) {
        std::fprintf(stderr, "boot faulted\n");
        return 1;
    }
    std::printf("boot ran %llu instructions (%s)\n", static_cast<unsigned long long>(n), g.stop_why ? g.stop_why : "budget");
    return 0;
}

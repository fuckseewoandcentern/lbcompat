#include "lb/runtime.hpp"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

int main(int argc, char** argv) {
    const char* path = argc > 1 ? argv[1]
                                : "/tmp/lyricsblossom/LyricsBlossom-arm/LyricsBlossom.app";
    lb::Runtime rt;
    std::string err;
    if (!rt.init(path, err)) {
        std::fprintf(stderr, "lbcompat: %s\n", err.c_str());
        return 1;
    }
    lb::Guest guest;
    rt.prepare(guest, argc, argv);
    uint64_t budget = 20000000;
    if (const char* e = std::getenv("LB_MAX_INSNS")) budget = std::strtoull(e, nullptr, 10);
    rt.run(guest, budget);
    return 0;
}

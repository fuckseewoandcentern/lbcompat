#include "lb/guest.hpp"

#include <cstdio>
#include <string>

namespace lb {
bool metal_selftest(std::string& err);
}

int main() {
    std::string err;
    if (!lb::metal_selftest(err)) {
        std::fprintf(stderr, "metal selftest failed: %s\n", err.c_str());
        return 1;
    }
    std::printf("metal to vulkan checks passed\n");
    return 0;
}

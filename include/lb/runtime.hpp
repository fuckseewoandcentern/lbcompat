#pragma once

#include "lb/guest.hpp"
#include "lb/image.hpp"

#include <string>

namespace lb {

struct Runtime {
    MachImage image;
    bool init(const std::string& path, std::string& err);
    void prepare(Guest& g, int argc, char** argv);
    uint64_t run(Guest& g, uint64_t max_insns);
};

}  // namespace lb

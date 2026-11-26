#pragma once

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace lb {

struct MachSection {
    std::string seg;
    std::string name;
    uint64_t addr = 0;
    uint64_t size = 0;
    uint32_t offset = 0;
};

// A mapped arm64 Mach-O. Guest pointers into the image are host pointers.
struct MachImage {
    uint64_t base = 0;
    uint64_t preferred = 0;
    uint64_t entry = 0;
    uint64_t vmsize = 0;
    std::string path;
    std::vector<std::string> dylibs;
    std::vector<MachSection> sections;

    bool load(const std::string& path, std::string& err);
    // Called once per bind. The returned address is stored plus the bind addend.
    using Resolver = std::function<uint64_t(const std::string& name, int lib_ordinal)>;
    bool apply_fixups(const Resolver& resolve, std::string& err);
    const MachSection* find_section(const char* seg, const char* name) const;
    uint64_t ptr(uint64_t preferred_or_offset) const;
    bool contains(uint64_t addr) const {
        return addr >= base && addr < base + vmsize;
    }
    // Unique import names, in ordinal order.
    std::vector<std::string> imports;
    uint32_t bind_sites = 0;

    uint32_t fixup_off_ = 0;
    std::vector<uint8_t> file_copy_;
};

}  // namespace lb

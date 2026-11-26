#include "lb/image.hpp"

#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>

namespace lb {
namespace {

constexpr uint32_t MH_MAGIC_64 = 0xfeedfacf;
constexpr uint32_t CPU_TYPE_ARM64 = 0x0100000c;
constexpr uint32_t LC_SEGMENT_64 = 0x19;
constexpr uint32_t LC_SYMTAB = 0x2;
constexpr uint32_t LC_DYSYMTAB = 0xb;
constexpr uint32_t LC_LOAD_DYLIB = 0xc;
constexpr uint32_t LC_ID_DYLIB = 0xd;
constexpr uint32_t LC_LOAD_WEAK_DYLIB = 0x80000018;
constexpr uint32_t LC_MAIN = 0x80000028;
constexpr uint32_t LC_DYLD_CHAINED_FIXUPS = 0x80000034;
constexpr uint32_t DYLD_CHAINED_PTR_64_OFFSET = 6;

struct SegInfo {
    uint64_t vmaddr = 0;
    uint64_t vmsize = 0;
    uint64_t fileoff = 0;
    uint64_t filesize = 0;
    uint32_t nsects = 0;
    uint32_t sect_file = 0;
    char name[17]{};
};

uint64_t read_u64(const uint8_t* p) {
    uint64_t v;
    std::memcpy(&v, p, 8);
    return v;
}
uint32_t read_u32(const uint8_t* p) {
    uint32_t v;
    std::memcpy(&v, p, 4);
    return v;
}
uint16_t read_u16(const uint8_t* p) {
    uint16_t v;
    std::memcpy(&v, p, 2);
    return v;
}

std::string cstr_at(const uint8_t* base, const uint8_t* end, const uint8_t* p) {
    if (p < base || p >= end) return {};
    size_t n = 0;
    while (p + n < end && p[n] != 0 && n < 4096) ++n;
    return std::string(reinterpret_cast<const char*>(p), n);
}

}  // namespace

bool MachImage::load(const std::string& file, std::string& err) {
    path = file;
    int fd = ::open(file.c_str(), O_RDONLY);
    if (fd < 0) {
        err = "open failed: " + file;
        return false;
    }
    struct stat st {};
    if (fstat(fd, &st) != 0 || st.st_size < 32) {
        ::close(fd);
        err = "stat failed";
        return false;
    }
    std::vector<uint8_t> filebuf(static_cast<size_t>(st.st_size));
    size_t got = 0;
    while (got < filebuf.size()) {
        ssize_t n = ::read(fd, filebuf.data() + got, filebuf.size() - got);
        if (n <= 0) break;
        got += static_cast<size_t>(n);
    }
    ::close(fd);
    if (got != filebuf.size()) {
        err = "short read";
        return false;
    }
    const uint8_t* f = filebuf.data();
    if (read_u32(f) != MH_MAGIC_64 || read_u32(f + 4) != CPU_TYPE_ARM64) {
        err = "not an arm64 Mach-O";
        return false;
    }
    uint32_t ncmds = read_u32(f + 16);
    uint32_t sizeofcmds = read_u32(f + 20);
    if (32u + sizeofcmds > filebuf.size()) {
        err = "load commands past end of file";
        return false;
    }

    std::vector<SegInfo> segs;
    uint64_t entryoff = 0;
    uint32_t fixoff = 0;
    uint32_t at = 32;
    for (uint32_t i = 0; i < ncmds; ++i) {
        if (at + 8 > filebuf.size()) {
            err = "truncated load command";
            return false;
        }
        uint32_t cmd = read_u32(f + at);
        uint32_t sz = read_u32(f + at + 4);
        if (sz < 8 || at + sz > filebuf.size()) {
            err = "bad load command size";
            return false;
        }
        if (cmd == LC_SEGMENT_64 && sz >= 72) {
            SegInfo s;
            std::memcpy(s.name, f + at + 8, 16);
            s.vmaddr = read_u64(f + at + 24);
            s.vmsize = read_u64(f + at + 32);
            s.fileoff = read_u64(f + at + 40);
            s.filesize = read_u64(f + at + 48);
            s.nsects = read_u32(f + at + 64);
            s.sect_file = at + 72;
            segs.push_back(s);
        } else if (cmd == LC_LOAD_DYLIB || cmd == LC_LOAD_WEAK_DYLIB || cmd == LC_ID_DYLIB) {
            uint32_t nameoff = read_u32(f + at + 8);
            dylibs.push_back(cstr_at(f, f + filebuf.size(), f + at + nameoff));
        } else if (cmd == LC_MAIN && sz >= 16) {
            entryoff = read_u64(f + at + 8);
        } else if (cmd == LC_DYLD_CHAINED_FIXUPS && sz >= 12) {
            fixoff = read_u32(f + at + 8);
        }
        at += sz;
    }
    (void)sizeofcmds;

    uint64_t min_vm = ~0ull;
    uint64_t max_vm = 0;
    for (const SegInfo& s : segs) {
        if (s.vmsize == 0 || std::strcmp(s.name, "__PAGEZERO") == 0) continue;
        min_vm = std::min(min_vm, s.vmaddr);
        max_vm = std::max(max_vm, s.vmaddr + s.vmsize);
    }
    if (min_vm == ~0ull || max_vm <= min_vm) {
        err = "no loadable segments";
        return false;
    }
    preferred = min_vm;
    vmsize = (max_vm - min_vm + 0xfff) & ~0xfffull;
    void* mapped = ::mmap(reinterpret_cast<void*>(preferred), vmsize, PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
    if (mapped == MAP_FAILED) {
        mapped = ::mmap(nullptr, vmsize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    }
    if (mapped == MAP_FAILED) {
        err = "mmap failed";
        return false;
    }
    base = reinterpret_cast<uint64_t>(mapped);
    std::memset(mapped, 0, vmsize);
    for (const SegInfo& s : segs) {
        if (s.filesize == 0 || std::strcmp(s.name, "__PAGEZERO") == 0) continue;
        if (s.fileoff + s.filesize > filebuf.size()) {
            err = "segment past end of file";
            return false;
        }
        uint64_t dest = base + (s.vmaddr - preferred);
        std::memcpy(reinterpret_cast<void*>(dest), f + s.fileoff, static_cast<size_t>(s.filesize));
    }
    entry = base + entryoff;

    for (const SegInfo& s : segs) {
        uint32_t sect = s.sect_file;
        for (uint32_t i = 0; i < s.nsects; ++i) {
            if (sect + 80 > filebuf.size()) break;
            MachSection sec;
            sec.name = std::string(reinterpret_cast<const char*>(f + sect),
                                   strnlen(reinterpret_cast<const char*>(f + sect), 16));
            sec.seg = std::string(reinterpret_cast<const char*>(f + sect + 16),
                                  strnlen(reinterpret_cast<const char*>(f + sect + 16), 16));
            uint64_t addr = read_u64(f + sect + 32);
            sec.size = read_u64(f + sect + 40);
            sec.offset = read_u32(f + sect + 48);
            sec.addr = base + (addr - preferred);
            sections.push_back(sec);
            sect += 80;
        }
    }

    // Stash the fixup blob's file offset in entry's unused high... keep it on the object
    // by re-reading from the mapped file later. Store it in a side field via the first
    // section list: we re-parse from a copy kept below.
    fixup_off_ = fixoff;
    file_copy_ = std::move(filebuf);
    (void)LC_SYMTAB;
    (void)LC_DYSYMTAB;
    return true;
}

bool MachImage::apply_fixups(const Resolver& resolve, std::string& err) {
    if (!base || fixup_off_ == 0 || fixup_off_ + 28 > file_copy_.size()) {
        err = "no chained fixups";
        return false;
    }
    const uint8_t* blob = file_copy_.data() + fixup_off_;
    const uint8_t* bend = file_copy_.data() + file_copy_.size();
    uint32_t starts_off = read_u32(blob + 4);
    uint32_t imports_off = read_u32(blob + 8);
    uint32_t symbols_off = read_u32(blob + 12);
    uint32_t imports_count = read_u32(blob + 16);
    uint32_t imports_format = read_u32(blob + 20);
    if (imports_format != 1) {
        err = "unsupported chained import format";
        return false;
    }
    const uint8_t* starts = blob + starts_off;
    if (starts + 4 > bend) {
        err = "fixup starts past end";
        return false;
    }
    uint32_t seg_count = read_u32(starts);
    imports.clear();
    imports.resize(imports_count);
    std::vector<int> ordinals(imports_count);
    for (uint32_t i = 0; i < imports_count; ++i) {
        const uint8_t* ip = blob + imports_off + i * 4;
        if (ip + 4 > bend) {
            err = "import past end";
            return false;
        }
        uint32_t w = read_u32(ip);
        ordinals[i] = static_cast<int>(w & 0xff);
        uint32_t name_off = w >> 9;
        imports[i] = cstr_at(file_copy_.data(), bend, blob + symbols_off + name_off);
    }

    const uint8_t* seg_info_off_table = starts + 4;
    bind_sites = 0;
    for (uint32_t si = 0; si < seg_count; ++si) {
        uint32_t info_off = read_u32(seg_info_off_table + si * 4);
        if (info_off == 0) continue;
        const uint8_t* info = starts + info_off;
        if (info + 22 > bend) continue;
        uint16_t page_size = read_u16(info + 4);
        uint16_t pointer_format = read_u16(info + 6);
        uint64_t segment_offset = read_u64(info + 8);
        uint16_t page_count = read_u16(info + 20);
        if (pointer_format != DYLD_CHAINED_PTR_64_OFFSET) {
            err = "unsupported pointer format";
            return false;
        }
        const uint8_t* pages = info + 22;
        for (uint16_t p = 0; p < page_count; ++p) {
            uint16_t start = read_u16(pages + p * 2);
            if (start == 0xffff) continue;
            if (start & 0x8000) {
                err = "multi-start fixup page";
                return false;
            }
            uint32_t off = static_cast<uint32_t>(segment_offset) + p * page_size + start;
            for (int guard = 0; guard < 100000; ++guard) {
                if (base + off + 8 > base + vmsize) {
                    err = "fixup outside image";
                    return false;
                }
                uint64_t raw = read_u64(reinterpret_cast<uint8_t*>(base + off));
                uint64_t next = (raw >> 51) & 0xfff;
                bool bind = (raw >> 63) & 1;
                uint64_t value;
                if (bind) {
                    uint32_t ordinal = static_cast<uint32_t>(raw & 0xffffffu);
                    uint64_t addend = (raw >> 24) & 0xff;
                    if (ordinal >= imports.size()) {
                        err = "bind ordinal out of range";
                        return false;
                    }
                    value = resolve(imports[ordinal], ordinals[ordinal]) + addend;
                    ++bind_sites;
                } else {
                    uint64_t target = raw & 0xfffffffffull;
                    uint64_t high8 = (raw >> 36) & 0xff;
                    value = (high8 << 56) | (base + target);
                }
                std::memcpy(reinterpret_cast<void*>(base + off), &value, 8);
                if (next == 0) break;
                off += static_cast<uint32_t>(next * 4);
            }
        }
    }
    return true;
}

const MachSection* MachImage::find_section(const char* seg, const char* name) const {
    for (const MachSection& s : sections) {
        if (s.seg == seg && s.name == name) return &s;
    }
    return nullptr;
}

uint64_t MachImage::ptr(uint64_t guest) const {
    if (guest >= preferred && guest < preferred + vmsize) return base + (guest - preferred);
    return guest;
}

}  // namespace lb

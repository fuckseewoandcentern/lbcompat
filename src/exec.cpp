#include "lb/guest.hpp"

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <type_traits>

namespace lb {
namespace {

constexpr uint32_t Nbit = 0x80000000u;
constexpr uint32_t Zbit = 0x40000000u;
constexpr uint32_t Cbit = 0x20000000u;
constexpr uint32_t Vbit = 0x10000000u;

inline uint32_t bit(uint32_t i, int b) { return (i >> b) & 1u; }
inline uint32_t bits(uint32_t i, int hi, int lo) {
    return (i >> lo) & ((1u << (hi - lo + 1)) - 1u);
}
inline int64_t sext_bits(uint64_t v, int n) {
    uint64_t s = 1ull << (n - 1);
    return static_cast<int64_t>((v ^ s) - s);
}

inline uint64_t rx(const Guest& g, int r) { return r == 31 ? 0 : g.x[r]; }
inline void wx(Guest& g, int r, uint64_t v, bool sf) {
    if (r == 31) return;
    g.x[r] = sf ? v : static_cast<uint32_t>(v);
}
inline uint64_t rbase(const Guest& g, int r) { return r == 31 ? g.sp : g.x[r]; }
inline void wbase(Guest& g, int r, uint64_t v) {
    if (r == 31) g.sp = v;
    else g.x[r] = v;
}

inline void set_nzcv(Guest& g, bool n, bool z, bool c, bool v) {
    g.nzcv = (n ? Nbit : 0) | (z ? Zbit : 0) | (c ? Cbit : 0) | (v ? Vbit : 0);
}

inline bool cond_ok(uint32_t nzcv, unsigned cond) {
    bool n = nzcv & Nbit;
    bool z = nzcv & Zbit;
    bool c = nzcv & Cbit;
    bool v = nzcv & Vbit;
    switch (cond & 0xF) {
        case 0: return z;
        case 1: return !z;
        case 2: return c;
        case 3: return !c;
        case 4: return n;
        case 5: return !n;
        case 6: return v;
        case 7: return !v;
        case 8: return c && !z;
        case 9: return !c || z;
        case 10: return n == v;
        case 11: return n != v;
        case 12: return !z && n == v;
        case 13: return z || n != v;
        default: return true;
    }
}

inline void flags_logic(Guest& g, uint64_t result, bool sf) {
    if (!sf) result &= 0xffffffffull;
    bool n = sf ? (result >> 63) != 0 : ((result >> 31) & 1) != 0;
    set_nzcv(g, n, result == 0, false, false);
}

inline void flags_add(Guest& g, uint64_t a, uint64_t b, uint64_t r, bool sf) {
    if (!sf) {
        a &= 0xffffffffull;
        b &= 0xffffffffull;
        r &= 0xffffffffull;
    }
    bool n = sf ? (r >> 63) != 0 : ((r >> 31) & 1) != 0;
    bool c = sf ? (r < a) : (static_cast<uint32_t>(r) < static_cast<uint32_t>(a));
    uint64_t sign = sf ? (1ull << 63) : 0x80000000ull;
    bool v = ((~(a ^ b) & (a ^ r)) & sign) != 0;
    set_nzcv(g, n, r == 0, c, v);
}

inline void flags_sub(Guest& g, uint64_t a, uint64_t b, uint64_t r, bool sf) {
    if (!sf) {
        a &= 0xffffffffull;
        b &= 0xffffffffull;
        r &= 0xffffffffull;
    }
    bool n = sf ? (r >> 63) != 0 : ((r >> 31) & 1) != 0;
    bool c = sf ? (a >= b) : (static_cast<uint32_t>(a) >= static_cast<uint32_t>(b));
    uint64_t sign = sf ? (1ull << 63) : 0x80000000ull;
    bool v = (((a ^ b) & (a ^ r)) & sign) != 0;
    set_nzcv(g, n, r == 0, c, v);
}

inline uint64_t add_with_carry(uint64_t a, uint64_t b, uint64_t cin, bool sf, bool& c, bool& v) {
    if (!sf) {
        uint32_t aa = static_cast<uint32_t>(a);
        uint32_t bb = static_cast<uint32_t>(b);
        uint64_t sum = static_cast<uint64_t>(aa) + bb + cin;
        uint32_t r = static_cast<uint32_t>(sum);
        c = sum >> 32;
        v = ((~(aa ^ bb) & (aa ^ r)) & 0x80000000u) != 0;
        return r;
    }
    unsigned __int128 sum = static_cast<unsigned __int128>(a) + b + cin;
    uint64_t r = static_cast<uint64_t>(sum);
    c = static_cast<bool>(sum >> 64);
    v = ((~(a ^ b) & (a ^ r)) & (1ull << 63)) != 0;
    return r;
}

// Logical-immediate / bitfield mask expansion (ARM DecodeBitMasks).
bool decode_bit_masks(unsigned n, unsigned imms, unsigned immr, bool logical, uint64_t& wmask, uint64_t& tmask) {
    unsigned combined = ((n & 1u) << 6) | ((~imms) & 0x3fu);
    if (combined == 0) return false;
    int len = 31 - __builtin_clz(combined);
    if (len < 1) return false;
    unsigned esize = 1u << len;
    unsigned levels = esize - 1u;
    unsigned S = imms & levels;
    unsigned R = immr & levels;
    if (logical && S == levels) return false;
    unsigned diff = (S - R) & levels;
    auto ones = [](unsigned n) -> uint64_t {
        return n >= 64 ? ~0ull : ((1ull << n) - 1ull);
    };
    uint64_t welem = ones(S + 1);
    uint64_t telem = ones(diff + 1);
    if (R != 0) {
        uint64_t m = esize == 64 ? ~0ull : ((1ull << esize) - 1ull);
        unsigned r = R & (esize - 1);
        welem = ((welem >> r) | (welem << (esize - r))) & m;
    }
    wmask = 0;
    tmask = 0;
    for (unsigned i = 0; i < 64; i += esize) {
        wmask |= welem << i;
        tmask |= telem << i;
    }
    return true;
}

inline uint64_t ror(uint64_t v, unsigned sh, unsigned bits) {
    sh &= bits - 1;
    if (sh == 0) return bits == 64 ? v : (v & ((bits == 32) ? 0xffffffffull : ~0ull));
    if (bits == 32) {
        v &= 0xffffffffull;
        return ((v >> sh) | (v << (32 - sh))) & 0xffffffffull;
    }
    return (v >> sh) | (v << (64 - sh));
}

inline uint64_t extend_reg(uint64_t v, unsigned option) {
    switch (option & 7) {
        case 0: return v & 0xff;
        case 1: return v & 0xffff;
        case 2: return v & 0xffffffffull;
        case 3: return v;
        case 4: return static_cast<uint64_t>(sext_bits(v & 0xff, 8));
        case 5: return static_cast<uint64_t>(sext_bits(v & 0xffff, 16));
        case 6: return static_cast<uint64_t>(sext_bits(v & 0xffffffffull, 32));
        default: return v;
    }
}

void read_v(const Guest& g, int r, uint8_t o[16]) { std::memcpy(o, g.v[r], 16); }
void write_v(Guest& g, int r, const uint8_t in[16]) { std::memcpy(g.v[r], in, 16); }
void write_partial(Guest& g, int r, const uint8_t* in, int bytes) {
    std::memset(g.v[r], 0, 16);
    std::memcpy(g.v[r], in, static_cast<size_t>(bytes));
}

uint32_t expand_fimm32(uint8_t imm8) {
    uint32_t a = imm8 >> 7;
    uint32_t b = (imm8 >> 6) & 1u;
    return (a << 31) | ((b ^ 1u) << 30) | ((b ? 0x1fu : 0u) << 25) | ((imm8 & 0x3fu) << 19);
}
uint64_t expand_fimm64(uint8_t imm8) {
    uint32_t a = imm8 >> 7;
    uint32_t b = (imm8 >> 6) & 1u;
    return (static_cast<uint64_t>(a) << 63) | (static_cast<uint64_t>(b ^ 1u) << 62) |
           (b ? (0xffull << 54) : 0ull) | (static_cast<uint64_t>(imm8 & 0x3fu) << 48);
}

float u2f(uint32_t u) {
    float f;
    std::memcpy(&f, &u, 4);
    return f;
}
uint32_t f2u(float f) {
    uint32_t u;
    std::memcpy(&u, &f, 4);
    return u;
}
double u2d(uint64_t u) {
    double d;
    std::memcpy(&d, &u, 8);
    return d;
}
uint64_t d2u(double d) {
    uint64_t u;
    std::memcpy(&u, &d, 8);
    return u;
}
float ld_f32(const uint8_t* p) {
    float f;
    std::memcpy(&f, p, 4);
    return f;
}
double ld_f64(const uint8_t* p) {
    double d;
    std::memcpy(&d, p, 8);
    return d;
}
void st_f32(uint8_t* p, float f) { std::memcpy(p, &f, 4); }
void st_f64(uint8_t* p, double d) { std::memcpy(p, &d, 8); }

void fcmp_flags(Guest& g, double a, double b) {
    if (std::isnan(a) || std::isnan(b)) set_nzcv(g, false, false, true, true);
    else if (a == b) set_nzcv(g, false, true, true, false);
    else if (a < b) set_nzcv(g, true, false, false, false);
    else set_nzcv(g, false, false, true, false);
}

// ---- integer / system / branches ---------------------------------------

bool try_int(Guest& g, uint32_t insn, ExecResult& er) {
    const bool sf = bit(insn, 31);
    const unsigned datasize = sf ? 64u : 32u;
    auto mask = [&](uint64_t v) { return sf ? v : (v & 0xffffffffull); };

    // ADR / ADRP
    if ((insn & 0x1F000000u) == 0x10000000u) {
        uint32_t immlo = bits(insn, 30, 29);
        uint32_t immhi = bits(insn, 23, 5);
        int64_t imm = sext_bits((static_cast<uint64_t>(immhi) << 2) | immlo, 21);
        uint64_t base = bit(insn, 31) ? (g.pc & ~0xfffull) : g.pc;
        if (bit(insn, 31)) imm <<= 12;
        wx(g, insn & 31, base + static_cast<uint64_t>(imm), true);
        er = EX_NEXT;
        return true;
    }

    // Add/sub immediate. Rn/Rd == 31 means SP.
    if ((insn & 0x1F000000u) == 0x11000000u) {
        unsigned shift = bits(insn, 23, 22);
        if (shift > 1) return false;
        uint64_t imm = bits(insn, 21, 10);
        if (shift == 1) imm <<= 12;
        int rn = bits(insn, 9, 5);
        int rd = insn & 31;
        // Rn==31 is SP. Rd==31 is SP only when flags are not written.
        uint64_t a = rbase(g, rn);
        bool op = bit(insn, 30);
        bool S = bit(insn, 29);
        uint64_t b = imm;
        uint64_t r = op ? mask(a - b) : mask(a + b);
        if (S) {
            if (op) flags_sub(g, a, b, r, sf);
            else flags_add(g, a, b, r, sf);
            wx(g, rd, r, sf);
        } else {
            wbase(g, rd, sf ? r : static_cast<uint32_t>(r));
        }
        er = EX_NEXT;
        return true;
    }

    // Logical immediate.
    if ((insn & 0x1F800000u) == 0x12000000u) {
        unsigned N = bit(insn, 22);
        unsigned immr = bits(insn, 21, 16);
        unsigned imms = bits(insn, 15, 10);
        if (!sf && N) return false;
        uint64_t wmask = 0, tmask = 0;
        if (!decode_bit_masks(N, imms, immr, true, wmask, tmask)) return false;
        if (!sf) wmask &= 0xffffffffull;
        int rn = bits(insn, 9, 5);
        int rd = insn & 31;
        uint64_t src = rx(g, rn);
        unsigned opc = bits(insn, 30, 29);
        uint64_t r = 0;
        switch (opc) {
            case 0: r = src & wmask; break;
            case 1: r = src | wmask; break;
            case 2: r = src ^ wmask; break;
            default: r = src & wmask; break;
        }
        r = mask(r);
        if (opc == 3) flags_logic(g, r, sf);
        wx(g, rd, r, sf);
        er = EX_NEXT;
        return true;
    }

    // Move wide.
    if ((insn & 0x1F800000u) == 0x12800000u) {
        unsigned opc = bits(insn, 30, 29);
        if (opc == 1) return false;
        unsigned hw = bits(insn, 22, 21);
        if (!sf && hw > 1) return false;
        unsigned shift = hw * 16;
        uint64_t imm = static_cast<uint64_t>(bits(insn, 20, 5)) << shift;
        int rd = insn & 31;
        uint64_t r = 0;
        if (opc == 0) r = ~imm;             // MOVN
        else if (opc == 2) r = imm;         // MOVZ
        else r = (rx(g, rd) & ~(0xffffull << shift)) | imm;  // MOVK
        wx(g, rd, mask(r), sf);
        er = EX_NEXT;
        return true;
    }

    // Bitfield.
    if ((insn & 0x1F800000u) == 0x13000000u) {
        unsigned opc = bits(insn, 30, 29);
        if (opc == 3) return false;
        unsigned N = bit(insn, 22);
        if (N != (sf ? 1u : 0u)) return false;
        unsigned immr = bits(insn, 21, 16);
        unsigned imms = bits(insn, 15, 10);
        uint64_t wmask = 0, tmask = 0;
        if (!decode_bit_masks(N, imms, immr, false, wmask, tmask)) return false;
        if (!sf) {
            wmask &= 0xffffffffull;
            tmask &= 0xffffffffull;
        }
        uint64_t src = mask(rx(g, bits(insn, 9, 5)));
        uint64_t bot = ror(src, immr, datasize) & wmask;
        uint64_t dst = mask(rx(g, insn & 31));
        uint64_t r = 0;
        if (opc == 0) {
            // SBFM
            uint64_t top = (tmask >> 1) ^ tmask;  // sign bit of the field
            uint64_t sign = (bot & top) ? ~0ull : 0ull;
            r = (sign & ~tmask) | (bot & tmask);
        } else if (opc == 1) {
            r = (dst & ~wmask) | bot;  // BFM
        } else {
            r = bot & tmask;  // UBFM
        }
        wx(g, insn & 31, mask(r), sf);
        er = EX_NEXT;
        return true;
    }

    // Extract / ROR.
    if ((insn & 0x1F800000u) == 0x13800000u) {
        if (bit(insn, 29) || bit(insn, 22) != (sf ? 1u : 0u)) return false;
        unsigned lsb = bits(insn, 15, 10);
        if (!sf && lsb > 31) return false;
        uint64_t hi = mask(rx(g, bits(insn, 9, 5)));
        uint64_t lo = mask(rx(g, bits(insn, 20, 16)));
        unsigned __int128 cat = (static_cast<unsigned __int128>(hi) << datasize) | lo;
        uint64_t r = static_cast<uint64_t>(cat >> lsb);
        wx(g, insn & 31, mask(r), sf);
        er = EX_NEXT;
        return true;
    }

    // Add/sub extended register (bit 21 set). SP allowed.
    if ((insn & 0x1F200000u) == 0x0B200000u) {
        unsigned option = bits(insn, 15, 13);
        unsigned imm3 = bits(insn, 12, 10);
        if (imm3 > 4) return false;
        uint64_t ext = extend_reg(rx(g, bits(insn, 20, 16)), option);
        ext <<= imm3;
        int rn = bits(insn, 9, 5);
        int rd = insn & 31;
        uint64_t a = rbase(g, rn);
        bool op = bit(insn, 30);
        bool S = bit(insn, 29);
        uint64_t r = op ? mask(a - ext) : mask(a + ext);
        if (S) {
            if (op) flags_sub(g, a, ext, r, sf);
            else flags_add(g, a, ext, r, sf);
            wx(g, rd, r, sf);
        } else {
            wbase(g, rd, sf ? r : static_cast<uint32_t>(r));
        }
        er = EX_NEXT;
        return true;
    }

    // Add/sub shifted register. Rn/Rd == 31 means ZR.
    if ((insn & 0x1F200000u) == 0x0B000000u) {
        unsigned shift = bits(insn, 23, 22);
        unsigned amt = bits(insn, 15, 10);
        if (amt >= datasize) return false;
        uint64_t m = mask(rx(g, bits(insn, 20, 16)));
        uint64_t shifted = m;
        if (shift == 0) shifted = m << amt;
        else if (shift == 1) shifted = m >> amt;
        else if (shift == 2) {
            if (sf) shifted = static_cast<uint64_t>(static_cast<int64_t>(m) >> amt);
            else shifted = static_cast<uint32_t>(static_cast<int32_t>(m) >> amt);
        } else return false;
        shifted = mask(shifted);
        uint64_t a = mask(rx(g, bits(insn, 9, 5)));
        bool op = bit(insn, 30);
        bool S = bit(insn, 29);
        uint64_t r = op ? mask(a - shifted) : mask(a + shifted);
        if (S) {
            if (op) flags_sub(g, a, shifted, r, sf);
            else flags_add(g, a, shifted, r, sf);
        }
        wx(g, insn & 31, r, sf);
        er = EX_NEXT;
        return true;
    }

    // Logical shifted register.
    if ((insn & 0x1F000000u) == 0x0A000000u) {
        unsigned shift = bits(insn, 23, 22);
        unsigned amt = bits(insn, 15, 10);
        if (amt >= datasize) return false;
        bool N = bit(insn, 21);
        uint64_t m = mask(rx(g, bits(insn, 20, 16)));
        uint64_t shifted = m;
        if (shift == 0) shifted = mask(m << amt);
        else if (shift == 1) shifted = m >> amt;
        else if (shift == 2) {
            shifted = sf ? static_cast<uint64_t>(static_cast<int64_t>(m) >> amt)
                         : static_cast<uint32_t>(static_cast<int32_t>(static_cast<uint32_t>(m)) >> amt);
        } else {
            shifted = ror(m, amt, datasize);
        }
        if (N) shifted = mask(~shifted);
        uint64_t n = mask(rx(g, bits(insn, 9, 5)));
        unsigned opc = bits(insn, 30, 29);
        uint64_t r = 0;
        switch (opc) {
            case 0: r = n & shifted; break;
            case 1: r = n | shifted; break;
            case 2: r = n ^ shifted; break;
            default: r = n & shifted; break;
        }
        r = mask(r);
        if (opc == 3) flags_logic(g, r, sf);
        wx(g, insn & 31, r, sf);
        er = EX_NEXT;
        return true;
    }

    // Add/sub with carry. Bits 15-10 are zero.
    if ((insn & 0x1FE0FC00u) == 0x1A000000u) {
        uint64_t a = mask(rx(g, bits(insn, 9, 5)));
        uint64_t b = mask(rx(g, bits(insn, 20, 16)));
        uint64_t cin = (g.nzcv & Cbit) ? 1u : 0u;
        bool op = bit(insn, 30);
        if (op) b = mask(~b);
        bool c = false, v = false;
        uint64_t r = add_with_carry(a, b, cin, sf, c, v);
        if (bit(insn, 29)) {
            bool n = sf ? (r >> 63) != 0 : ((r >> 31) & 1) != 0;
            set_nzcv(g, n, mask(r) == 0, c, v);
        }
        wx(g, insn & 31, r, sf);
        er = EX_NEXT;
        return true;
    }

    // Conditional compare. Bit 11 selects an immediate (1) or a register (0).
    if ((insn & 0x1FE00000u) == 0x1A400000u && bit(insn, 4) == 0) {
        unsigned cond = bits(insn, 15, 12);
        unsigned nz = insn & 0xF;
        bool op = bit(insn, 30);  // 1 = SUB (CCMP), 0 = ADD (CCMN)
        if (cond_ok(g.nzcv, cond)) {
            uint64_t a = mask(rx(g, bits(insn, 9, 5)));
            uint64_t b = bit(insn, 11) ? bits(insn, 20, 16) : mask(rx(g, bits(insn, 20, 16)));
            uint64_t r = op ? mask(a - b) : mask(a + b);
            if (op) flags_sub(g, a, b, r, sf);
            else flags_add(g, a, b, r, sf);
        } else {
            g.nzcv = (nz & 0xF) << 28;
        }
        er = EX_NEXT;
        return true;
    }

    // Conditional select.
    if ((insn & 0x1FE00000u) == 0x1A800000u && bit(insn, 11) == 0) {
        unsigned cond = bits(insn, 15, 12);
        bool inv = bit(insn, 30);
        bool inc = bit(insn, 10);
        uint64_t n = mask(rx(g, bits(insn, 9, 5)));
        uint64_t m = mask(rx(g, bits(insn, 20, 16)));
        uint64_t other = m;
        if (inc && inv) other = mask(~m + 1);       // CSNEG
        else if (inv) other = mask(~m);             // CSINV
        else if (inc) other = mask(m + 1);          // CSINC
        uint64_t r = cond_ok(g.nzcv, cond) ? n : other;
        wx(g, insn & 31, r, sf);
        er = EX_NEXT;
        return true;
    }

    // Data-processing (1 source): bit 30 = 1, Rm field = 0.
    // Data-processing (1 source). Bit 30 distinguishes this from the 2-source group.
    if ((insn & 0x7FFF0000u) == 0x5AC00000u) {
        unsigned opcode = bits(insn, 15, 10);
        uint64_t a = mask(rx(g, bits(insn, 9, 5)));
        uint64_t r = 0;
        switch (opcode) {
            case 0: {  // RBIT
                r = 0;
                for (unsigned i = 0; i < datasize; i++)
                    if (a & (1ull << i)) r |= 1ull << (datasize - 1 - i);
                break;
            }
            case 1: {  // REV16
                r = 0;
                unsigned n = datasize / 16;
                for (unsigned i = 0; i < n; i++) {
                    uint16_t h = static_cast<uint16_t>(a >> (16 * i));
                    h = static_cast<uint16_t>((h >> 8) | (h << 8));
                    r |= static_cast<uint64_t>(h) << (16 * i);
                }
                break;
            }
            case 2: {  // REV32 (within each word). 64-bit only in practice.
                uint32_t lo = __builtin_bswap32(static_cast<uint32_t>(a));
                uint32_t hi = __builtin_bswap32(static_cast<uint32_t>(a >> 32));
                r = sf ? (static_cast<uint64_t>(lo) | (static_cast<uint64_t>(hi) << 32)) : lo;
                break;
            }
            case 3:  // REV
                r = sf ? __builtin_bswap64(a) : __builtin_bswap32(static_cast<uint32_t>(a));
                break;
            case 4: {  // CLZ
                if (!sf) a &= 0xffffffffull;
                if (a == 0) r = datasize;
                else r = sf ? __builtin_clzll(a) : __builtin_clz(static_cast<uint32_t>(a));
                break;
            }
            case 5: {  // CLS
                uint64_t x = sf ? a : (a & 0xffffffffull);
                uint64_t y = sf ? static_cast<uint64_t>(static_cast<int64_t>(x) >> 63)
                                : static_cast<uint32_t>(static_cast<int32_t>(x) >> 31);
                uint64_t z = x ^ y;
                if (!sf) z &= 0xffffffffull;
                r = (z == 0 ? datasize : (sf ? __builtin_clzll(z) : __builtin_clz(static_cast<uint32_t>(z)))) - 1;
                break;
            }
            default: return false;
        }
        wx(g, insn & 31, mask(r), sf);
        er = EX_NEXT;
        return true;
    }

    // Data-processing (2 source).
    if ((insn & 0x5FE00000u) == 0x1AC00000u) {
        unsigned opcode = bits(insn, 15, 10);
        uint64_t a = mask(rx(g, bits(insn, 9, 5)));
        uint64_t b = mask(rx(g, bits(insn, 20, 16)));
        uint64_t r = 0;
        auto sh = [&](uint64_t amt) { return amt & (datasize - 1); };
        switch (opcode) {
            case 2:  // UDIV
                r = b == 0 ? 0 : a / b;
                break;
            case 3: {  // SDIV
                if (b == 0) r = 0;
                else if (sf && a == 0x8000000000000000ull && b == ~0ull) r = a;
                else if (!sf && static_cast<uint32_t>(a) == 0x80000000u && static_cast<uint32_t>(b) == 0xffffffffu) r = a;
                else if (sf) r = static_cast<uint64_t>(static_cast<int64_t>(a) / static_cast<int64_t>(b));
                else r = static_cast<uint32_t>(static_cast<int32_t>(a) / static_cast<int32_t>(b));
                break;
            }
            case 8: r = mask(a << sh(b)); break;                  // LSLV
            case 9: r = a >> sh(b); break;                        // LSRV
            case 10:                                              // ASRV
                if (sf) r = static_cast<uint64_t>(static_cast<int64_t>(a) >> sh(b));
                else r = static_cast<uint32_t>(static_cast<int32_t>(a) >> sh(b));
                break;
            case 11: r = ror(a, static_cast<unsigned>(b), datasize); break;
            case 16: {  // CRC32B/H/W/X share this space; opcode subfield differs.
                return false;
            }
            default: return false;
        }
        wx(g, insn & 31, mask(r), sf);
        er = EX_NEXT;
        return true;
    }

    // Data-processing (3 source): MADD and widening multiplies.
    if ((insn & 0x1F000000u) == 0x1B000000u) {
        unsigned op31 = bits(insn, 23, 21);
        unsigned o0 = bit(insn, 15);
        uint64_t n = rx(g, bits(insn, 9, 5));
        uint64_t m = rx(g, bits(insn, 20, 16));
        uint64_t a = rx(g, bits(insn, 14, 10));
        uint64_t r = 0;
        bool ok = true;
        if (!sf && op31 == 0) {
            uint32_t nn = static_cast<uint32_t>(n);
            uint32_t mm = static_cast<uint32_t>(m);
            uint32_t aa = static_cast<uint32_t>(a);
            uint32_t p = nn * mm;
            r = o0 ? (aa - p) : (aa + p);
        } else if (sf && op31 == 0) {
            r = o0 ? (a - n * m) : (a + n * m);
        } else if (sf && op31 == 1) {  // SMADDL / SMSUBL
            int64_t nn = static_cast<int32_t>(n);
            int64_t mm = static_cast<int32_t>(m);
            int64_t p = nn * mm;
            r = static_cast<uint64_t>(o0 ? (static_cast<int64_t>(a) - p) : (static_cast<int64_t>(a) + p));
        } else if (sf && op31 == 2 && o0 == 0) {  // SMULH
            __int128 p = static_cast<__int128>(static_cast<int64_t>(n)) * static_cast<int64_t>(m);
            r = static_cast<uint64_t>(p >> 64);
        } else if (sf && op31 == 5) {  // UMADDL / UMSUBL
            uint64_t p = static_cast<uint64_t>(static_cast<uint32_t>(n)) * static_cast<uint32_t>(m);
            r = o0 ? (a - p) : (a + p);
        } else if (sf && op31 == 6 && o0 == 0) {  // UMULH
            unsigned __int128 p = static_cast<unsigned __int128>(n) * m;
            r = static_cast<uint64_t>(p >> 64);
        } else ok = false;
        if (!ok) return false;
        wx(g, insn & 31, sf ? r : static_cast<uint32_t>(r), sf);
        er = EX_NEXT;
        return true;
    }

    return false;
}

bool try_branch(Guest& g, uint32_t insn, ExecResult& er) {
    auto branch = [&](uint64_t target, bool link) {
        if (link) g.x[30] = g.pc + 4;
        g.pc = target;
        er = EX_BRANCH;
    };
    if ((insn & 0xFC000000u) == 0x14000000u || (insn & 0xFC000000u) == 0x94000000u) {
        int64_t off = sext_bits(insn & 0x03ffffffu, 26) << 2;
        branch(g.pc + static_cast<uint64_t>(off), bit(insn, 31));
        return true;
    }
    if ((insn & 0xFF000010u) == 0x54000000u) {
        int64_t off = sext_bits(bits(insn, 23, 5), 19) << 2;
        unsigned cond = insn & 0xF;
        g.pc = cond_ok(g.nzcv, cond) ? g.pc + static_cast<uint64_t>(off) : g.pc + 4;
        er = EX_BRANCH;
        return true;
    }
    if ((insn & 0x7E000000u) == 0x34000000u) {
        bool sf = bit(insn, 31);
        bool op = bit(insn, 24);
        uint64_t v = rx(g, insn & 31);
        if (!sf) v &= 0xffffffffull;
        bool taken = op ? (v != 0) : (v == 0);
        int64_t off = sext_bits(bits(insn, 23, 5), 19) << 2;
        g.pc = taken ? g.pc + static_cast<uint64_t>(off) : g.pc + 4;
        er = EX_BRANCH;
        return true;
    }
    if ((insn & 0x7E000000u) == 0x36000000u) {
        unsigned bitno = (bit(insn, 31) << 5) | bits(insn, 23, 19);
        bool op = bit(insn, 24);
        uint64_t v = rx(g, insn & 31);
        bool set = ((v >> bitno) & 1ull) != 0;
        bool taken = op ? set : !set;
        int64_t off = sext_bits(bits(insn, 18, 5), 14) << 2;
        g.pc = taken ? g.pc + static_cast<uint64_t>(off) : g.pc + 4;
        er = EX_BRANCH;
        return true;
    }
    if ((insn & 0xFFFFFC1Fu) == 0xD61F0000u) {
        branch(rx(g, bits(insn, 9, 5)), false);
        return true;
    }
    if ((insn & 0xFFFFFC1Fu) == 0xD63F0000u) {
        branch(rx(g, bits(insn, 9, 5)), true);
        return true;
    }
    if ((insn & 0xFFFFFC1Fu) == 0xD65F0000u) {
        branch(g.x[30], false);
        return true;
    }
    return false;
}

bool try_system(Guest& g, uint32_t insn, ExecResult& er) {
    if ((insn & 0xFFFFF01Fu) == 0xD503201Fu) {
        er = EX_NEXT;  // NOP / hint / PAC-as-hint
        return true;
    }
    if ((insn & 0xFFFFF0FFu) == 0xD50330BFu || (insn & 0xFFFFF0FFu) == 0xD503309Fu) {
        er = EX_NEXT;  // DMB / DSB / ISB
        return true;
    }
    if ((insn & 0xFFF00000u) == 0xD5300000u) {
        unsigned sys = (insn >> 5) & 0x7fffu;
        uint64_t val = 0;
        if (sys == 0x5a10) val = g.nzcv;
        else if (sys == 0x5f01 || sys == 0x5f02) {
            // Physical / virtual counter. A nanosecond clock is enough for timeouts.
            timespec ts{};
            clock_gettime(CLOCK_MONOTONIC, &ts);
            val = static_cast<uint64_t>(ts.tv_sec) * 1000000000ull + static_cast<uint64_t>(ts.tv_nsec);
        } else if (sys == 0x5f00) {
            val = 1000000000ull;  // CNTFRQ
        } else {
            val = 0;  // ID registers: no optional ISA, so callers take the scalar path
        }
        wx(g, insn & 31, val, true);
        er = EX_NEXT;
        return true;
    }
    if ((insn & 0xFFF00000u) == 0xD5100000u) {
        unsigned sys = (insn >> 5) & 0x7fffu;
        if (sys == 0x5a10) g.nzcv = static_cast<uint32_t>(rx(g, insn & 31)) & 0xF0000000u;
        er = EX_NEXT;
        return true;
    }
    if ((insn & 0xFFE0001Fu) == 0xD4200000u) {
        g.stop = 3;
        g.stop_insn = insn;
        g.stop_pc = g.pc;
        g.stop_why = "brk";
        er = EX_STOP;
        return true;
    }
    return false;
}

// ---- memory -------------------------------------------------------------

int access_bytes(bool simd, unsigned size, unsigned opc, bool& sign, bool& to64, bool& store, bool& prfm) {
    sign = false;
    to64 = true;
    store = false;
    prfm = false;
    if (!simd) {
        if (size == 3 && opc == 2) {
            prfm = true;
            return 0;
        }
        if (opc == 0) {
            store = true;
            return 1 << size;
        }
        if (opc == 1) return 1 << size;
        if (opc == 2) {
            sign = true;
            to64 = true;
            return 1 << size;
        }
        if (opc == 3 && size <= 1) {
            sign = true;
            to64 = false;
            return 1 << size;
        }
        return -1;
    }
    if (opc == 0) {
        store = true;
        return 1 << size;
    }
    if (opc == 1) return 1 << size;
    if (size == 0 && opc == 2) {
        store = true;
        return 16;
    }
    if (size == 0 && opc == 3) return 16;
    return -1;
}

void load_reg(Guest& g, int rt, int bytes, uint64_t addr, bool sign, bool to64, bool simd) {
    if (simd) {
        uint8_t tmp[16]{};
        std::memcpy(tmp, reinterpret_cast<void*>(tbi(addr)), static_cast<size_t>(bytes));
        write_partial(g, rt, tmp, bytes);
        return;
    }
    uint64_t v = mem_load(addr, bytes);
    if (sign) v = static_cast<uint64_t>(sext_bits(v, bytes * 8));
    wx(g, rt, v, to64 || bytes == 8);
}

void store_reg(Guest& g, int rt, int bytes, uint64_t addr, bool simd) {
    if (simd) {
        uint8_t tmp[16];
        read_v(g, rt, tmp);
        std::memcpy(reinterpret_cast<void*>(tbi(addr)), tmp, static_cast<size_t>(bytes));
        return;
    }
    mem_store(addr, rx(g, rt), bytes);
}

template <typename T>
uint64_t atomic_minmax(T* p, T v, bool is_max, bool is_signed, int mem) {
    T old = __atomic_load_n(p, __ATOMIC_RELAXED);
    for (;;) {
        T next;
        if (is_signed) {
            using S = std::make_signed_t<T>;
            S so = static_cast<S>(old);
            S sv = static_cast<S>(v);
            next = static_cast<T>(is_max ? (so > sv ? so : sv) : (so < sv ? so : sv));
        } else {
            next = is_max ? (old > v ? old : v) : (old < v ? old : v);
        }
        if (__atomic_compare_exchange_n(p, &old, next, true, mem, __ATOMIC_RELAXED)) return static_cast<uint64_t>(old);
    }
}

uint64_t atomic_rmw(uint64_t addr, uint64_t val, int bytes, unsigned opc, int order) {
    auto mem = __ATOMIC_RELAXED;
    if (order == 3) mem = __ATOMIC_ACQ_REL;
    else if (order == 2) mem = __ATOMIC_RELEASE;
    else if (order == 1) mem = __ATOMIC_ACQUIRE;
    switch (bytes) {
        case 1: {
            auto* p = reinterpret_cast<uint8_t*>(tbi(addr));
            uint8_t v = static_cast<uint8_t>(val);
            switch (opc) {
                case 0: return __atomic_fetch_add(p, v, mem);
                case 1: return __atomic_fetch_and(p, static_cast<uint8_t>(~v), mem);
                case 2: return __atomic_fetch_xor(p, v, mem);
                case 3: return __atomic_fetch_or(p, v, mem);
                case 4: return atomic_minmax(p, v, true, true, mem);
                case 5: return atomic_minmax(p, v, false, true, mem);
                case 6: return atomic_minmax(p, v, true, false, mem);
                case 7: return atomic_minmax(p, v, false, false, mem);
                case 8: return __atomic_exchange_n(p, v, mem);
                default: return __atomic_load_n(p, mem);
            }
        }
        case 2: {
            auto* p = reinterpret_cast<uint16_t*>(tbi(addr));
            uint16_t v = static_cast<uint16_t>(val);
            switch (opc) {
                case 0: return __atomic_fetch_add(p, v, mem);
                case 1: return __atomic_fetch_and(p, static_cast<uint16_t>(~v), mem);
                case 2: return __atomic_fetch_xor(p, v, mem);
                case 3: return __atomic_fetch_or(p, v, mem);
                case 4: return atomic_minmax(p, v, true, true, mem);
                case 5: return atomic_minmax(p, v, false, true, mem);
                case 6: return atomic_minmax(p, v, true, false, mem);
                case 7: return atomic_minmax(p, v, false, false, mem);
                case 8: return __atomic_exchange_n(p, v, mem);
                default: return __atomic_load_n(p, mem);
            }
        }
        case 4: {
            auto* p = reinterpret_cast<uint32_t*>(tbi(addr));
            uint32_t v = static_cast<uint32_t>(val);
            switch (opc) {
                case 0: return __atomic_fetch_add(p, v, mem);
                case 1: return __atomic_fetch_and(p, ~v, mem);
                case 2: return __atomic_fetch_xor(p, v, mem);
                case 3: return __atomic_fetch_or(p, v, mem);
                case 4: return atomic_minmax(p, v, true, true, mem);
                case 5: return atomic_minmax(p, v, false, true, mem);
                case 6: return atomic_minmax(p, v, true, false, mem);
                case 7: return atomic_minmax(p, v, false, false, mem);
                case 8: return __atomic_exchange_n(p, v, mem);
                default: return __atomic_load_n(p, mem);
            }
        }
        default: {
            auto* p = reinterpret_cast<uint64_t*>(tbi(addr));
            switch (opc) {
                case 0: return __atomic_fetch_add(p, val, mem);
                case 1: return __atomic_fetch_and(p, ~val, mem);
                case 2: return __atomic_fetch_xor(p, val, mem);
                case 3: return __atomic_fetch_or(p, val, mem);
                case 4: return atomic_minmax(p, val, true, true, mem);
                case 5: return atomic_minmax(p, val, false, true, mem);
                case 6: return atomic_minmax(p, val, true, false, mem);
                case 7: return atomic_minmax(p, val, false, false, mem);
                case 8: return __atomic_exchange_n(p, val, mem);
                default: return __atomic_load_n(p, mem);
            }
        }
    }
}

struct ExclMon {
    uint64_t addr = 0;
    int bytes = 0;
    bool valid = false;
};
ExclMon g_excl;

bool try_mem(Guest& g, uint32_t insn, ExecResult& er) {
    // Unsigned immediate.
    if ((insn & 0x3B000000u) == 0x39000000u) {
        bool sign = false, to64 = true, store = false, prfm = false;
        bool simd = bit(insn, 26);
        int bytes = access_bytes(simd, bits(insn, 31, 30), bits(insn, 23, 22), sign, to64, store, prfm);
        if (bytes < 0) return false;
        if (prfm) {
            er = EX_NEXT;
            return true;
        }
        uint64_t addr = rbase(g, bits(insn, 9, 5)) + static_cast<uint64_t>(bits(insn, 21, 10)) * static_cast<uint64_t>(bytes);
        if (store) store_reg(g, insn & 31, bytes, addr, simd);
        else load_reg(g, insn & 31, bytes, addr, sign, to64, simd);
        er = EX_NEXT;
        return true;
    }

    // LDP/STP and LDPSW. Mode in bits 24-23 must be nonzero.
    if ((insn & 0x3A000000u) == 0x28000000u && bits(insn, 24, 23) != 0) {
        unsigned opc = bits(insn, 31, 30);
        bool simd = bit(insn, 26);
        bool load = bit(insn, 22);
        unsigned mode = bits(insn, 24, 23);
        int scale = 0;
        bool sign32 = false;
        if (!simd) {
            if (opc == 0) scale = 4;
            else if (opc == 1) {
                scale = 4;
                sign32 = true;
            } else if (opc == 2) scale = 8;
            else return false;
        } else {
            if (opc == 0) scale = 4;
            else if (opc == 1) scale = 8;
            else if (opc == 2) scale = 16;
            else return false;
        }
        int64_t off = sext_bits(bits(insn, 21, 15), 7) * scale;
        int rt = insn & 31;
        int rn = bits(insn, 9, 5);
        int rt2 = bits(insn, 14, 10);
        uint64_t base = rbase(g, rn);
        uint64_t addr = base;
        uint64_t wb = base;
        if (mode == 2) addr = static_cast<uint64_t>(static_cast<int64_t>(base) + off);
        else if (mode == 3) {
            addr = static_cast<uint64_t>(static_cast<int64_t>(base) + off);
            wb = addr;
        } else if (mode == 1) {
            addr = base;
            wb = static_cast<uint64_t>(static_cast<int64_t>(base) + off);
        } else return false;
        if (!simd && scale != 16) {
            if (load) {
                uint64_t a = mem_load(addr, scale == 8 && !sign32 ? 8 : 4);
                uint64_t b = mem_load(addr + static_cast<uint64_t>(scale == 8 && !sign32 ? 8 : 4), scale == 8 && !sign32 ? 8 : 4);
                if (sign32) {
                    a = static_cast<uint64_t>(sext_bits(a, 32));
                    b = static_cast<uint64_t>(sext_bits(b, 32));
                }
                if (mode != 2) wbase(g, rn, wb);
                bool wide = scale == 8 || sign32;
                wx(g, rt, a, wide);
                wx(g, rt2, b, wide);
            } else {
                int sb = scale == 8 ? 8 : 4;
                mem_store(addr, rx(g, rt), sb);
                mem_store(addr + static_cast<uint64_t>(sb), rx(g, rt2), sb);
                if (mode != 2) wbase(g, rn, wb);
            }
        } else {
            if (load) {
                uint8_t a[16]{}, b[16]{};
                std::memcpy(a, reinterpret_cast<void*>(tbi(addr)), static_cast<size_t>(scale));
                std::memcpy(b, reinterpret_cast<void*>(tbi(addr) + scale), static_cast<size_t>(scale));
                if (mode != 2) wbase(g, rn, wb);
                write_partial(g, rt, a, scale);
                write_partial(g, rt2, b, scale);
            } else {
                uint8_t a[16], b[16];
                read_v(g, rt, a);
                read_v(g, rt2, b);
                std::memcpy(reinterpret_cast<void*>(tbi(addr)), a, static_cast<size_t>(scale));
                std::memcpy(reinterpret_cast<void*>(tbi(addr) + scale), b, static_cast<size_t>(scale));
                if (mode != 2) wbase(g, rn, wb);
            }
        }
        er = EX_NEXT;
        return true;
    }

    // Literal load.
    if ((insn & 0x3B000000u) == 0x18000000u) {
        bool simd = bit(insn, 26);
        unsigned opc = bits(insn, 31, 30);
        int bytes = 0;
        bool sign = false;
        if (!simd) {
            if (opc == 0) bytes = 4;
            else if (opc == 1) bytes = 8;
            else if (opc == 2) {
                bytes = 4;
                sign = true;
            } else return false;
        } else {
            if (opc == 0) bytes = 4;
            else if (opc == 1) bytes = 8;
            else if (opc == 2) bytes = 16;
            else return false;
        }
        int64_t off = sext_bits(bits(insn, 23, 5), 19) << 2;
        uint64_t addr = g.pc + static_cast<uint64_t>(off);
        if (simd) {
            uint8_t tmp[16]{};
            std::memcpy(tmp, reinterpret_cast<void*>(tbi(addr)), static_cast<size_t>(bytes));
            write_partial(g, insn & 31, tmp, bytes);
        } else {
            uint64_t v = mem_load(addr, bytes);
            if (sign) v = static_cast<uint64_t>(sext_bits(v, 32));
            wx(g, insn & 31, v, bytes == 8 || sign);
        }
        er = EX_NEXT;
        return true;
    }

    if ((insn & 0x3FFFFC00u) == 0x38BFC000u) {
        unsigned size = bits(insn, 31, 30);
        int bytes = 1 << size;
        uint64_t v = mem_load(rbase(g, bits(insn, 9, 5)), bytes);
        wx(g, insn & 31, v, size == 3);
        er = EX_NEXT;
        return true;
    }
    if ((insn & 0x3FFFFC00u) == 0x08DFFC00u) {
        unsigned size = bits(insn, 31, 30);
        int bytes = 1 << size;
        uint64_t v = mem_load(rbase(g, bits(insn, 9, 5)), bytes);
        wx(g, insn & 31, v, size == 3);
        er = EX_NEXT;
        return true;
    }
    if ((insn & 0x3FFFFC00u) == 0x089FFC00u) {
        unsigned size = bits(insn, 31, 30);
        int bytes = 1 << size;
        mem_store(rbase(g, bits(insn, 9, 5)), rx(g, insn & 31), bytes);
        er = EX_NEXT;
        return true;
    }

    // LSE atomics. Distinguished from register-offset loads by bits 11-10 == 00.
    if (((insn >> 24) & 0x3Fu) == 0x38u && bit(insn, 21) && bits(insn, 11, 10) == 0) {
        unsigned size = bits(insn, 31, 30);
        int bytes = 1 << size;
        unsigned opc = bits(insn, 15, 12);
        if (opc > 8) return false;
        int order = (bit(insn, 23) ? 1 : 0) + (bit(insn, 22) ? 2 : 0);
        uint64_t addr = rbase(g, bits(insn, 9, 5));
        uint64_t val = rx(g, bits(insn, 20, 16));
        uint64_t old = atomic_rmw(addr, val, bytes, opc, order);
        wx(g, insn & 31, old, size == 3);
        er = EX_NEXT;
        return true;
    }

    // CAS.
    if (((insn >> 24) & 0x3Fu) == 0x08u && bit(insn, 21)) {
        unsigned size = bits(insn, 31, 30);
        int bytes = 1 << size;
        int order = (bit(insn, 22) ? 1 : 0) + (bit(insn, 15) ? 2 : 0);
        auto mem = order == 3 ? __ATOMIC_ACQ_REL : order == 2 ? __ATOMIC_RELEASE : order == 1 ? __ATOMIC_ACQUIRE : __ATOMIC_RELAXED;
        uint64_t addr = tbi(rbase(g, bits(insn, 9, 5)));
        int rs = bits(insn, 20, 16);
        int rt = insn & 31;
        uint64_t expected = rx(g, rs);
        uint64_t desired = rx(g, rt);
        switch (bytes) {
            case 1: {
                uint8_t e = static_cast<uint8_t>(expected), d = static_cast<uint8_t>(desired);
                __atomic_compare_exchange_n(reinterpret_cast<uint8_t*>(addr), &e, d, false, mem, __ATOMIC_RELAXED);
                wx(g, rs, e, false);
                break;
            }
            case 2: {
                uint16_t e = static_cast<uint16_t>(expected), d = static_cast<uint16_t>(desired);
                __atomic_compare_exchange_n(reinterpret_cast<uint16_t*>(addr), &e, d, false, mem, __ATOMIC_RELAXED);
                wx(g, rs, e, false);
                break;
            }
            case 4: {
                uint32_t e = static_cast<uint32_t>(expected), d = static_cast<uint32_t>(desired);
                __atomic_compare_exchange_n(reinterpret_cast<uint32_t*>(addr), &e, d, false, mem, __ATOMIC_RELAXED);
                wx(g, rs, e, false);
                break;
            }
            default: {
                uint64_t e = expected, d = desired;
                __atomic_compare_exchange_n(reinterpret_cast<uint64_t*>(addr), &e, d, false, mem, __ATOMIC_RELAXED);
                wx(g, rs, e, true);
                break;
            }
        }
        er = EX_NEXT;
        return true;
    }

    // LDXR / STXR / LDAXR / STLXR.
    if (((insn >> 24) & 0x3Fu) == 0x08u && bit(insn, 21) == 0 && bits(insn, 14, 10) == 0x1F) {
        unsigned size = bits(insn, 31, 30);
        int bytes = 1 << size;
        int rs = bits(insn, 20, 16);
        int rn = bits(insn, 9, 5);
        int rt = insn & 31;
        bool bit23 = bit(insn, 23);
        bool bit15 = bit(insn, 15);
        uint64_t addr = rbase(g, rn);
        if (rs == 31) {
            uint64_t v = mem_load(addr, bytes);
            wx(g, rt, v, size == 3);
            g_excl = {tbi(addr), bytes, true};
        } else {
            bool ok = g_excl.valid && g_excl.addr == tbi(addr) && g_excl.bytes == bytes;
            if (ok) mem_store(addr, rx(g, rt), bytes);
            g_excl.valid = false;
            wx(g, rs, ok ? 0 : 1, false);
            (void)bit23;
            (void)bit15;
        }
        er = EX_NEXT;
        return true;
    }

    // Unscaled / pre / post / register offset.
    if ((insn & 0x3B000000u) == 0x38000000u) {
        bool simd = bit(insn, 26);
        bool sign = false, to64 = true, store = false, prfm = false;
        int bytes = access_bytes(simd, bits(insn, 31, 30), bits(insn, 23, 22), sign, to64, store, prfm);
        if (bytes < 0) return false;
        if (prfm) {
            er = EX_NEXT;
            return true;
        }
        int rn = bits(insn, 9, 5);
        int rt = insn & 31;
        uint64_t base = rbase(g, rn);
        uint64_t addr = base;
        bool wb = false;
        uint64_t wbv = base;
        if (bit(insn, 21)) {
            if (bits(insn, 11, 10) != 2) return false;
            unsigned option = bits(insn, 15, 13);
            unsigned S = bit(insn, 12);
            int sh = S ? (bytes == 16 ? 4 : (bytes == 8 ? 3 : bytes == 4 ? 2 : bytes == 2 ? 1 : 0)) : 0;
            uint64_t idx = extend_reg(rx(g, bits(insn, 20, 16)), option) << sh;
            addr = base + idx;
        } else {
            int64_t imm = sext_bits(bits(insn, 20, 12), 9);
            unsigned mode = bits(insn, 11, 10);
            if (mode == 0) addr = static_cast<uint64_t>(static_cast<int64_t>(base) + imm);
            else if (mode == 1) {
                addr = base;
                wb = true;
                wbv = static_cast<uint64_t>(static_cast<int64_t>(base) + imm);
            } else if (mode == 3) {
                addr = static_cast<uint64_t>(static_cast<int64_t>(base) + imm);
                wb = true;
                wbv = addr;
            } else return false;
        }
        if (store) store_reg(g, rt, bytes, addr, simd);
        else load_reg(g, rt, bytes, addr, sign, to64, simd);
        if (wb) wbase(g, rn, wbv);
        er = EX_NEXT;
        return true;
    }

    // LD1/ST1 multiple structures and LD1R. bit31 = 0, bits 29-25 = 00110, bit21 = 0.
    if (bit(insn, 31) == 0 && ((insn >> 25) & 0x1F) == 0x06 && bit(insn, 21) == 0) {
        bool Q = bit(insn, 30);
        bool post = bit(insn, 23);
        bool load = bit(insn, 22);
        bool replicate = bit(insn, 24);
        unsigned rm = bits(insn, 20, 16);
        unsigned opcode = bits(insn, 15, 12);
        unsigned sz = bits(insn, 11, 10);
        int rn = bits(insn, 9, 5);
        int rt = insn & 31;
        int reg_bytes = Q ? 16 : 8;
        int nregs = 0;
        bool deinterleave2 = false;
        if (replicate) {
            if (opcode != 0xC) return false;
            nregs = 1;
        } else {
            if (opcode == 0x7) nregs = 1;
            else if (opcode == 0xA) nregs = 2;
            else if (opcode == 0x6) nregs = 3;
            else if (opcode == 0x2) nregs = 4;
            else if (opcode == 0x8) {
                nregs = 2;
                deinterleave2 = true;
            } else return false;
        }
        (void)sz;
        uint64_t base = rbase(g, rn);
        int elem = 1 << sz;
        if (replicate) {
            uint8_t e[8]{};
            if (load) std::memcpy(e, reinterpret_cast<void*>(tbi(base)), static_cast<size_t>(elem));
            uint8_t tmp[16]{};
            for (int o = 0; o < reg_bytes; o += elem)
                std::memcpy(tmp + o, e, static_cast<size_t>(elem));
            if (load) write_partial(g, rt, tmp, reg_bytes);
            else {
                // ST1R is rare; store one element from lane 0.
                read_v(g, rt, tmp);
                std::memcpy(reinterpret_cast<void*>(tbi(base)), tmp, static_cast<size_t>(elem));
            }
        } else if (!deinterleave2) {
            for (int i = 0; i < nregs; i++) {
                uint64_t addr = base + static_cast<uint64_t>(i * reg_bytes);
                int r = (rt + i) & 31;
                if (load) {
                    uint8_t tmp[16]{};
                    std::memcpy(tmp, reinterpret_cast<void*>(tbi(addr)), static_cast<size_t>(reg_bytes));
                    write_partial(g, r, tmp, reg_bytes);
                } else {
                    uint8_t tmp[16];
                    read_v(g, r, tmp);
                    std::memcpy(reinterpret_cast<void*>(tbi(addr)), tmp, static_cast<size_t>(reg_bytes));
                }
            }
        } else {
            // LD2/ST2: pairs of elements interleaved.
            int elems = reg_bytes / elem;
            uint8_t raw[32];
            uint8_t a[16]{}, b[16]{};
            if (load) {
                std::memcpy(raw, reinterpret_cast<void*>(tbi(base)), static_cast<size_t>(reg_bytes * 2));
                for (int i = 0; i < elems; i++) {
                    std::memcpy(a + i * elem, raw + (2 * i) * elem, static_cast<size_t>(elem));
                    std::memcpy(b + i * elem, raw + (2 * i + 1) * elem, static_cast<size_t>(elem));
                }
                write_partial(g, rt, a, reg_bytes);
                write_partial(g, (rt + 1) & 31, b, reg_bytes);
            } else {
                read_v(g, rt, a);
                read_v(g, (rt + 1) & 31, b);
                for (int i = 0; i < elems; i++) {
                    std::memcpy(raw + (2 * i) * elem, a + i * elem, static_cast<size_t>(elem));
                    std::memcpy(raw + (2 * i + 1) * elem, b + i * elem, static_cast<size_t>(elem));
                }
                std::memcpy(reinterpret_cast<void*>(tbi(base)), raw, static_cast<size_t>(reg_bytes * 2));
            }
        }
        if (post) {
            int64_t add = 0;
            if (rm == 31) add = replicate ? elem : (deinterleave2 ? reg_bytes * 2 : reg_bytes * nregs);
            else add = static_cast<int64_t>(rx(g, rm));
            wbase(g, rn, static_cast<uint64_t>(static_cast<int64_t>(base) + add));
        }
        er = EX_NEXT;
        return true;
    }

    return false;
}

// ---- SIMD / FP ----------------------------------------------------------

const uint8_t kSbox[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16};
const uint8_t kInvSbox[256] = {
    0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
    0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
    0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
    0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
    0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
    0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
    0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
    0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
    0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
    0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
    0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
    0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
    0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
    0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
    0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
    0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d};

uint8_t xtime(uint8_t x) { return static_cast<uint8_t>((x << 1) ^ ((x & 0x80) ? 0x1b : 0)); }

void mix_columns(uint8_t s[16], bool inv) {
    for (int c = 0; c < 4; c++) {
        uint8_t* col = s + 4 * c;
        uint8_t a0 = col[0], a1 = col[1], a2 = col[2], a3 = col[3];
        if (!inv) {
            col[0] = static_cast<uint8_t>(xtime(a0) ^ xtime(a1) ^ a1 ^ a2 ^ a3);
            col[1] = static_cast<uint8_t>(a0 ^ xtime(a1) ^ xtime(a2) ^ a2 ^ a3);
            col[2] = static_cast<uint8_t>(a0 ^ a1 ^ xtime(a2) ^ xtime(a3) ^ a3);
            col[3] = static_cast<uint8_t>(xtime(a0) ^ a0 ^ a1 ^ a2 ^ xtime(a3));
        } else {
            auto m = [](uint8_t a, uint8_t n) {
                uint8_t r = 0;
                while (n) {
                    if (n & 1) r ^= a;
                    a = xtime(a);
                    n >>= 1;
                }
                return r;
            };
            col[0] = static_cast<uint8_t>(m(a0, 14) ^ m(a1, 11) ^ m(a2, 13) ^ m(a3, 9));
            col[1] = static_cast<uint8_t>(m(a0, 9) ^ m(a1, 14) ^ m(a2, 11) ^ m(a3, 13));
            col[2] = static_cast<uint8_t>(m(a0, 13) ^ m(a1, 9) ^ m(a2, 14) ^ m(a3, 11));
            col[3] = static_cast<uint8_t>(m(a0, 11) ^ m(a1, 13) ^ m(a2, 9) ^ m(a3, 14));
        }
    }
}

void aes_round(uint8_t d[16], const uint8_t n[16], bool decrypt) {
    uint8_t s[16];
    for (int i = 0; i < 16; i++) s[i] = decrypt ? kInvSbox[d[i]] : kSbox[d[i]];
    uint8_t t[16];
    if (!decrypt) {
        for (int r = 0; r < 4; r++)
            for (int c = 0; c < 4; c++) t[r + 4 * c] = s[r + 4 * ((c + r) & 3)];
    } else {
        // InvShiftRows then InvSubBytes is the ARM AESD order. Apply InvShiftRows
        // on the original bytes, then InvSubBytes.
        uint8_t sh[16];
        for (int r = 0; r < 4; r++)
            for (int c = 0; c < 4; c++) sh[r + 4 * c] = d[r + 4 * ((c - r) & 3)];
        for (int i = 0; i < 16; i++) t[i] = kInvSbox[sh[i]];
    }
    for (int i = 0; i < 16; i++) d[i] = static_cast<uint8_t>(t[i] ^ n[i]);
}

unsigned __int128 poly_mul(uint64_t a, uint64_t b) {
    unsigned __int128 r = 0;
    for (int i = 0; i < 64; i++)
        if ((b >> i) & 1) r ^= static_cast<unsigned __int128>(a) << i;
    return r;
}

uint32_t ror32(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }
uint32_t sha_S0(uint32_t x) { return ror32(x, 2) ^ ror32(x, 13) ^ ror32(x, 22); }
uint32_t sha_S1(uint32_t x) { return ror32(x, 6) ^ ror32(x, 11) ^ ror32(x, 25); }
uint32_t sha_s0(uint32_t x) { return ror32(x, 7) ^ ror32(x, 18) ^ (x >> 3); }
uint32_t sha_s1(uint32_t x) { return ror32(x, 17) ^ ror32(x, 19) ^ (x >> 10); }

void sha256_quad(uint32_t d[4], const uint32_t n[4], const uint32_t w[4]) {
    uint32_t a = d[0], b = d[1], c = d[2], dd = d[3];
    uint32_t e = n[0], f = n[1], g = n[2], h = n[3];
    for (int i = 0; i < 4; i++) {
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t1 = h + sha_S1(e) + ch + w[3 - i];
        uint32_t t2 = sha_S0(a) + maj;
        h = g;
        g = f;
        f = e;
        e = dd + t1;
        dd = c;
        c = b;
        b = a;
        a = t1 + t2;
    }
    d[0] = a;
    d[1] = b;
    d[2] = c;
    d[3] = dd;
}

bool try_fp_scalar(Guest& g, uint32_t insn, ExecResult& er) {
    if (((insn >> 24) & 0x1Fu) == 0x1Fu) {
        // FP 3-source: FMADD / FMSUB / FNMADD / FNMSUB.
        bool neg = bit(insn, 21);
        bool sub = bit(insn, 15);
        bool dbl = bit(insn, 22);
        int rd = insn & 31;
        int rn = bits(insn, 9, 5);
        int rm = bits(insn, 20, 16);
        int ra = bits(insn, 14, 10);
        if (!dbl) {
            float a = ld_f32(g.v[rn]);
            float b = ld_f32(g.v[rm]);
            float c = ld_f32(g.v[ra]);
            float r = a * b;
            if (sub) r = -r;
            r = c + r;
            if (neg) r = -r;
            uint8_t tmp[4];
            st_f32(tmp, r);
            write_partial(g, rd, tmp, 4);
        } else {
            double a = ld_f64(g.v[rn]);
            double b = ld_f64(g.v[rm]);
            double c = ld_f64(g.v[ra]);
            double r = a * b;
            if (sub) r = -r;
            r = c + r;
            if (neg) r = -r;
            uint8_t tmp[8];
            st_f64(tmp, r);
            write_partial(g, rd, tmp, 8);
        }
        er = EX_NEXT;
        return true;
    }
    if (((insn >> 24) & 0x1Fu) != 0x1Eu) return false;
    bool dbl = bit(insn, 22);
    bool sf = bit(insn, 31);
    int rd = insn & 31;
    int rn = bits(insn, 9, 5);
    int rm = bits(insn, 20, 16);
    unsigned op = bits(insn, 15, 10);
    unsigned b1110 = bits(insn, 11, 10);
    if (!bit(insn, 21) && b1110 != 0) return false;
    if (bit(insn, 21) && b1110 == 2) {
        unsigned opc = bits(insn, 15, 12);
        auto bin32 = [&](auto fn) {
            float r = fn(ld_f32(g.v[rn]), ld_f32(g.v[rm]));
            uint8_t t[4];
            st_f32(t, r);
            write_partial(g, rd, t, 4);
        };
        auto bin64 = [&](auto fn) {
            double r = fn(ld_f64(g.v[rn]), ld_f64(g.v[rm]));
            uint8_t t[8];
            st_f64(t, r);
            write_partial(g, rd, t, 8);
        };
        switch (opc) {
            case 0:
                if (!dbl) bin32([](float a, float b) { return a * b; });
                else bin64([](double a, double b) { return a * b; });
                break;
            case 1:
                if (!dbl) bin32([](float a, float b) { return a / b; });
                else bin64([](double a, double b) { return a / b; });
                break;
            case 2:
                if (!dbl) bin32([](float a, float b) { return a + b; });
                else bin64([](double a, double b) { return a + b; });
                break;
            case 3:
                if (!dbl) bin32([](float a, float b) { return a - b; });
                else bin64([](double a, double b) { return a - b; });
                break;
            case 4:
                if (!dbl) bin32([](float a, float b) { return std::fmax(a, b); });
                else bin64([](double a, double b) { return std::fmax(a, b); });
                break;
            case 5:
                if (!dbl) bin32([](float a, float b) { return std::fmin(a, b); });
                else bin64([](double a, double b) { return std::fmin(a, b); });
                break;
            case 6:
                if (!dbl) bin32([](float a, float b) { return std::fmax(a, b); });
                else bin64([](double a, double b) { return std::fmax(a, b); });
                break;
            case 7:
                if (!dbl) bin32([](float a, float b) { return std::fmin(a, b); });
                else bin64([](double a, double b) { return std::fmin(a, b); });
                break;
            default: return false;
        }
        er = EX_NEXT;
        return true;
    }
    if (bit(insn, 21) && op == 0x08) {
        if ((insn & 31) == 0) {
            if (!dbl) fcmp_flags(g, ld_f32(g.v[rn]), ld_f32(g.v[rm]));
            else fcmp_flags(g, ld_f64(g.v[rn]), ld_f64(g.v[rm]));
        } else if ((insn & 31) == 8 && rm == 0) {
            if (!dbl) fcmp_flags(g, ld_f32(g.v[rn]), 0.f);
            else fcmp_flags(g, ld_f64(g.v[rn]), 0.0);
        } else return false;
        er = EX_NEXT;
        return true;
    }
    // FMOV immediate. The low bits of imm8 sit in bits 15-13, so they are not a fixed opcode.
    if (bit(insn, 21) && bits(insn, 12, 10) == 4 && bits(insn, 9, 5) == 0) {
        if (bit(insn, 23)) return false;
        uint8_t imm8 = static_cast<uint8_t>(bits(insn, 20, 13));
        if (!dbl) {
            uint32_t u = expand_fimm32(imm8);
            write_partial(g, rd, reinterpret_cast<uint8_t*>(&u), 4);
        } else {
            uint64_t u = expand_fimm64(imm8);
            write_partial(g, rd, reinterpret_cast<uint8_t*>(&u), 8);
        }
        er = EX_NEXT;
        return true;
    }
    if (bit(insn, 21) && b1110 == 3) {
        unsigned cond = bits(insn, 15, 12);
        bool take = cond_ok(g.nzcv, cond);
        int src = take ? rn : rm;
        if (!dbl) {
            uint8_t t[4];
            std::memcpy(t, g.v[src], 4);
            write_partial(g, rd, t, 4);
        } else {
            uint8_t t[8];
            std::memcpy(t, g.v[src], 8);
            write_partial(g, rd, t, 8);
        }
        er = EX_NEXT;
        return true;
    }
    if (bit(insn, 21) && b1110 == 1) {
        unsigned cond = bits(insn, 15, 12);
        unsigned nz = insn & 0xF;
        if (cond_ok(g.nzcv, cond)) {
            if (!dbl) fcmp_flags(g, ld_f32(g.v[rn]), ld_f32(g.v[rm]));
            else fcmp_flags(g, ld_f64(g.v[rn]), ld_f64(g.v[rm]));
        } else g.nzcv = (nz & 0xF) << 28;
        er = EX_NEXT;
        return true;
    }
    if (bit(insn, 21) && op == 0 && (rm == 6 || rm == 7)) {
        int bytes = dbl ? 8 : 4;
        if (rm == 7) {
            uint64_t v = rx(g, rn);
            write_partial(g, rd, reinterpret_cast<uint8_t*>(&v), bytes);
        } else {
            uint64_t v = 0;
            std::memcpy(&v, g.v[rn], static_cast<size_t>(bytes));
            wx(g, rd, v, bytes == 8);
        }
        er = EX_NEXT;
        return true;
    }
    if (bit(insn, 21) && op == 0) {
        // Integer <-> FP conversion. rm is the opcode.
        int src_bytes = dbl ? 8 : 4;
        bool int64 = sf;
        if (rm == 0x02) {  // SCVTF
            double dv = int64 ? static_cast<double>(static_cast<int64_t>(rx(g, rn)))
                              : static_cast<double>(static_cast<int32_t>(rx(g, rn)));
            if (!dbl) {
                float f = static_cast<float>(int64 ? static_cast<int64_t>(rx(g, rn)) : static_cast<int32_t>(rx(g, rn)));
                uint8_t t[4];
                st_f32(t, f);
                write_partial(g, rd, t, 4);
            } else {
                uint8_t t[8];
                st_f64(t, dv);
                write_partial(g, rd, t, 8);
            }
        } else if (rm == 0x03) {  // UCVTF
            double dv = int64 ? static_cast<double>(rx(g, rn)) : static_cast<double>(static_cast<uint32_t>(rx(g, rn)));
            if (!dbl) {
                float f = static_cast<float>(dv);
                uint8_t t[4];
                st_f32(t, f);
                write_partial(g, rd, t, 4);
            } else {
                uint8_t t[8];
                st_f64(t, dv);
                write_partial(g, rd, t, 8);
            }
        } else if (rm <= 1 || rm == 4 || rm == 5 || rm == 8 || rm == 9 || rm == 0x10 || rm == 0x11 || rm == 0x18 ||
                   rm == 0x19) {
            // FCVT{N,A,P,M,Z}{S,U}: odd rm is the unsigned form.
            bool unsign = rm & 1u;
            double dv = dbl ? ld_f64(g.v[rn]) : static_cast<double>(ld_f32(g.v[rn]));
            if (std::isnan(dv)) dv = 0;
            else if (rm <= 1) dv = std::nearbyint(dv);
            else if (rm <= 5) dv = std::round(dv);
            else if (rm <= 9) dv = std::ceil(dv);
            else if (rm <= 0x11) dv = std::floor(dv);
            else dv = std::trunc(dv);
            uint64_t iv = 0;
            if (unsign) {
                if (dv <= 0) iv = 0;
                else if (int64) iv = dv >= static_cast<double>(~0ull) ? ~0ull : static_cast<uint64_t>(dv);
                else iv = dv >= 4294967296.0 ? 0xffffffffull : static_cast<uint32_t>(dv);
            } else if (int64) {
                if (dv >= 9223372036854775808.0) iv = 0x7fffffffffffffffll;
                else if (dv <= -9223372036854775808.0) iv = 0x8000000000000000ull;
                else iv = static_cast<uint64_t>(static_cast<int64_t>(dv));
            } else {
                if (dv >= 2147483648.0) iv = 0x7fffffff;
                else if (dv <= -2147483649.0) iv = 0x80000000u;
                else iv = static_cast<uint32_t>(static_cast<int32_t>(dv));
            }
            wx(g, rd, iv, int64);
            (void)src_bytes;
        } else return false;
        er = EX_NEXT;
        return true;
    }
    if (op == 0x30 || op == 0x10) {
        if (op == 0x10 && rm == 0) {
            int n = dbl ? 8 : 4;
            uint8_t t[8];
            std::memcpy(t, g.v[rn], static_cast<size_t>(n));
            write_partial(g, rd, t, n);
        } else if (op == 0x10 && rm == 1) {
            if (!dbl) {
                float f = -ld_f32(g.v[rn]);
                uint8_t t[4];
                st_f32(t, f);
                write_partial(g, rd, t, 4);
            } else {
                double d = -ld_f64(g.v[rn]);
                uint8_t t[8];
                st_f64(t, d);
                write_partial(g, rd, t, 8);
            }
        } else if (op == 0x30 && rm == 0) {
            if (!dbl) {
                float f = std::fabs(ld_f32(g.v[rn]));
                uint8_t t[4];
                st_f32(t, f);
                write_partial(g, rd, t, 4);
            } else {
                double d = std::fabs(ld_f64(g.v[rn]));
                uint8_t t[8];
                st_f64(t, d);
                write_partial(g, rd, t, 8);
            }
        } else if (op == 0x30 && rm == 1) {
            if (!dbl) {
                float f = std::sqrt(ld_f32(g.v[rn]));
                uint8_t t[4];
                st_f32(t, f);
                write_partial(g, rd, t, 4);
            } else {
                double d = std::sqrt(ld_f64(g.v[rn]));
                uint8_t t[8];
                st_f64(t, d);
                write_partial(g, rd, t, 8);
            }
        } else if ((op == 0x30 || op == 0x10) && rm == 2) {
            // FCVT between single and double. ty == 0 means source is single.
            if (!dbl) {
                double d = static_cast<double>(ld_f32(g.v[rn]));
                uint8_t t[8];
                st_f64(t, d);
                write_partial(g, rd, t, 8);
            } else {
                float f = static_cast<float>(ld_f64(g.v[rn]));
                uint8_t t[4];
                st_f32(t, f);
                write_partial(g, rd, t, 4);
            }
        } else if ((op == 0x10 || op == 0x30) && rm >= 4 && rm <= 7) {
            // FRINT*: opcode bits 20-16 plus bit 15 select the rounding mode.
            auto round = [&](double d) {
                if (rm == 4 && op == 0x10) return std::nearbyint(d);  // FRINTN
                if (rm == 4 && op == 0x30) return std::ceil(d);       // FRINTP
                if (rm == 5 && op == 0x10) return std::floor(d);      // FRINTM
                if (rm == 5 && op == 0x30) return std::trunc(d);      // FRINTZ
                if (rm == 6 && op == 0x10) return std::round(d);      // FRINTA
                if (rm == 6 && op == 0x30) return std::trunc(d);
                if (rm == 7 && op == 0x10) return std::nearbyint(d);  // FRINTX
                return std::nearbyint(d);                            // FRINTI
            };
            if (!dbl) {
                float f = static_cast<float>(round(ld_f32(g.v[rn])));
                uint8_t t[4];
                st_f32(t, f);
                write_partial(g, rd, t, 4);
            } else {
                double d = round(ld_f64(g.v[rn]));
                uint8_t t[8];
                st_f64(t, d);
                write_partial(g, rd, t, 8);
            }
        } else return false;
        er = EX_NEXT;
        return true;
    }
    return false;
}

float half_to_float(uint16_t h) {
    uint32_t sign = static_cast<uint32_t>(h & 0x8000u) << 16;
    int exp = (h >> 10) & 0x1f;
    int frac = h & 0x3ff;
    uint32_t bits;
    if (exp == 0) {
        float f = std::ldexp(static_cast<float>(frac), -24);
        return sign ? -f : f;
    }
    if (exp == 31) bits = sign | 0x7f800000u | (frac ? 0x400000u : 0);
    else bits = sign | (static_cast<uint32_t>(exp + (127 - 15)) << 23) | (static_cast<uint32_t>(frac) << 13);
    float f;
    std::memcpy(&f, &bits, 4);
    return f;
}

uint16_t float_to_half(float f) {
    uint32_t u = 0;
    std::memcpy(&u, &f, 4);
    uint16_t sign = static_cast<uint16_t>((u >> 16) & 0x8000u);
    int exp_bits = static_cast<int>((u >> 23) & 0xff);
    uint32_t frac = u & 0x7fffffu;
    if (exp_bits == 255) return static_cast<uint16_t>(sign | 0x7c00u | (frac ? 0x200u : 0));
    int exp = exp_bits - 127 + 15;
    if (exp >= 31) return static_cast<uint16_t>(sign | 0x7c00u);
    if (exp <= 0) {
        if (exp < -10) return sign;
        frac |= 0x800000u;
        int shift = 14 - exp;
        uint32_t half = frac >> shift;
        uint32_t rem_mask = (1u << shift) - 1u;
        if ((frac & rem_mask) > (1u << (shift - 1)) || (((frac & rem_mask) == (1u << (shift - 1))) && (half & 1u))) half++;
        return static_cast<uint16_t>(sign | half);
    }
    uint32_t half = frac >> 13;
    uint32_t rem = frac & 0x1fffu;
    if (rem > 0x1000u || (rem == 0x1000u && (half & 1u))) {
        half++;
        if (half == 0x400u) {
            half = 0;
            exp++;
            if (exp >= 31) return static_cast<uint16_t>(sign | 0x7c00u);
        }
    }
    return static_cast<uint16_t>(sign | (exp << 10) | half);
}

int reg_width(bool Q) { return Q ? 16 : 8; }

template <typename F>
void lanes(uint8_t* d, const uint8_t* a, const uint8_t* b, int esize, int bytes, F fn) {
    for (int o = 0; o < bytes; o += esize) fn(d + o, a + o, b ? b + o : nullptr);
}

bool try_simd(Guest& g, uint32_t insn, ExecResult& er) {
    // SIMD modified immediate (MOVI / MVNI). immh (bits 22-19) is zero;
    // a non-zero immh is the shift-by-immediate class instead.
    if (((insn >> 23) & 0x3Fu) == 0x1Eu && bits(insn, 11, 10) == 1 && bits(insn, 22, 19) == 0) {
        bool Q = bit(insn, 30);
        bool op = bit(insn, 29);
        unsigned cmode = bits(insn, 15, 12);
        unsigned imm8 = (bits(insn, 18, 16) << 5) | bits(insn, 9, 5);
        int bytes = reg_width(Q);
        uint8_t tmp[16]{};
        auto replicate32 = [&](uint32_t lane) {
            if (op && cmode != 0xE && cmode != 0xF) lane = ~lane;
            for (int i = 0; i < bytes; i += 4) std::memcpy(tmp + i, &lane, 4);
        };
        if (cmode == 0xE) {
            if (op) {
                // .2d form: each bit of imm8 expands to an 0x00 or 0xff byte.
                uint64_t lane = 0;
                for (int i = 0; i < 8; i++)
                    if (imm8 & (1u << i)) lane |= 0xffull << (8 * i);
                for (int i = 0; i < bytes; i += 8) std::memcpy(tmp + i, &lane, 8);
            } else {
                std::memset(tmp, static_cast<int>(imm8), bytes);
            }
        } else if (cmode == 0xF) {
            uint32_t u = expand_fimm32(static_cast<uint8_t>(imm8));
            if (op) {
                uint64_t d = expand_fimm64(static_cast<uint8_t>(imm8));
                for (int i = 0; i < bytes; i += 8) std::memcpy(tmp + i, &d, 8);
            } else {
                for (int i = 0; i < bytes; i += 4) std::memcpy(tmp + i, &u, 4);
            }
        } else if ((cmode & 0x9) == 0x0 || (cmode & 0xD) == 0x8 || (cmode & 1) == 0) {
            unsigned shift = 0;
            if ((cmode & 0xC) == 0) shift = ((cmode >> 1) & 3) * 8;
            else if ((cmode & 0xC) == 0x4) {
                // 16-bit immediate
                shift = (cmode & 2) ? 8 : 0;
                uint16_t lane = static_cast<uint16_t>(imm8 << shift);
                if (op) lane = static_cast<uint16_t>(~lane);
                for (int i = 0; i < bytes; i += 2) std::memcpy(tmp + i, &lane, 2);
                write_partial(g, insn & 31, tmp, bytes);
                er = EX_NEXT;
                return true;
            } else if ((cmode & 0xC) == 0xC && cmode != 0xE && cmode != 0xF) {
                // MSL: ones in the low bits, imm8 shifted.
                shift = (cmode == 0xC) ? 8 : 16;
                uint32_t lane = (static_cast<uint32_t>(imm8) << shift) | ((1u << shift) - 1u);
                replicate32(lane);
                write_partial(g, insn & 31, tmp, bytes);
                er = EX_NEXT;
                return true;
            }
            if ((cmode & 0xC) != 0x4) replicate32(static_cast<uint32_t>(imm8) << shift);
        } else if (cmode == 0xD) {
            uint32_t lane = (static_cast<uint32_t>(imm8) << 16) | 0xffffu;
            if (op) lane = ~lane;
            replicate32(lane);
        } else if ((cmode & 1u) && cmode < 0xC) {
            // ORR (op = 0) or BIC (op = 1) of a shifted immediate into the existing lanes.
            bool half = cmode >= 0x9;
            unsigned shift = half ? ((cmode & 2) ? 8 : 0) : ((cmode >> 1) & 3) * 8;
            uint32_t imm = static_cast<uint32_t>(imm8) << shift;
            int es = half ? 2 : 4;
            uint8_t cur[16];
            read_v(g, insn & 31, cur);
            for (int i = 0; i < bytes; i += es) {
                uint32_t lane = 0;
                std::memcpy(&lane, cur + i, static_cast<size_t>(es));
                lane = op ? (lane & ~imm) : (lane | imm);
                if (half) lane &= 0xffffu;
                std::memcpy(tmp + i, &lane, static_cast<size_t>(es));
            }
        } else {
            return false;
        }
        write_partial(g, insn & 31, tmp, bytes);
        er = EX_NEXT;
        return true;
    }

    // EXT.
    if (((insn >> 21) & 0x1FFu) == 0x170u && bit(insn, 15) == 0 && bit(insn, 10) == 0) {
        bool Q = bit(insn, 30);
        int bytes = reg_width(Q);
        unsigned imm4 = bits(insn, 14, 11);
        if (imm4 > static_cast<unsigned>(bytes)) return false;
        uint8_t a[16], b[16], d[16]{};
        read_v(g, bits(insn, 9, 5), a);
        read_v(g, bits(insn, 20, 16), b);
        for (unsigned i = 0; i < static_cast<unsigned>(bytes); i++) {
            unsigned idx = imm4 + i;
            d[i] = idx < static_cast<unsigned>(bytes) ? a[idx] : b[idx - bytes];
        }
        write_partial(g, insn & 31, d, bytes);
        er = EX_NEXT;
        return true;
    }

    // ZIP / UZP / TRN. opc bits 14-12 select which half of each pair is kept.
    if ((insn & 0xBF208C00u) == 0x0E000800u) {
        unsigned opc = bits(insn, 14, 12);
        if (opc == 0 || opc == 4) return false;
        int es = 1 << bits(insn, 23, 22);
        int bytes = bit(insn, 30) ? 16 : 8;
        if (es <= 0 || es > bytes || bytes % es) return false;
        int half = (bytes / es) / 2;
        uint8_t a[16], b[16], d[16]{};
        read_v(g, bits(insn, 9, 5), a);
        read_v(g, bits(insn, 20, 16), b);
        auto put = [&](int dst, const uint8_t* src, int index) {
            std::memcpy(d + dst * es, src + index * es, static_cast<size_t>(es));
        };
        for (int i = 0; i < half; ++i) {
            if (opc == 3 || opc == 7) {  // ZIP1 / ZIP2
                int base = opc == 7 ? half : 0;
                put(2 * i, a, base + i);
                put(2 * i + 1, b, base + i);
            } else if (opc == 1 || opc == 5) {  // UZP1 / UZP2
                int odd = opc == 5 ? 1 : 0;
                put(i, a, 2 * i + odd);
                put(half + i, b, 2 * i + odd);
            } else if (opc == 2 || opc == 6) {  // TRN1 / TRN2
                int odd = opc == 6 ? 1 : 0;
                put(2 * i, a, 2 * i + odd);
                put(2 * i + 1, b, 2 * i + odd);
            } else return false;
        }
        write_partial(g, insn & 31, d, bytes);
        er = EX_NEXT;
        return true;
    }

    // DUP <Vd>.<T>, <Xn>. imm5's lowest set bit selects the element size.
    if ((insn & 0xBFE0FC00u) == 0x0E000C00u) {
        unsigned imm5 = bits(insn, 20, 16);
        if (imm5 == 0) return false;
        int esize = 8 << __builtin_ctz(imm5);
        bool Q = bit(insn, 30);
        int bytes = reg_width(Q);
        int eb = esize / 8;
        if (eb <= 0 || eb > bytes) return false;
        uint64_t lane = rx(g, bits(insn, 9, 5));
        if (eb < 8) lane &= (1ull << (eb * 8)) - 1ull;
        uint8_t tmp[16]{};
        for (int i = 0; i < bytes; i += eb) std::memcpy(tmp + i, &lane, static_cast<size_t>(eb));
        write_partial(g, insn & 31, tmp, bytes);
        er = EX_NEXT;
        return true;
    }

    // DUP <Vd>.<T>, <Vn>.<Ts>[index]. The index is packed in imm5 the same way as UMOV.
    if ((insn & 0xBFE0FC00u) == 0x0E000400u) {
        unsigned imm5 = bits(insn, 20, 16);
        if (imm5 == 0) return false;
        int lsb = __builtin_ctz(imm5);
        int eb = 1 << lsb;
        int index = static_cast<int>(imm5 >> (lsb + 1));
        if (eb <= 0 || index * eb + eb > 16) return false;
        int bytes = bit(insn, 30) ? 16 : 8;
        if (eb > bytes) return false;
        uint64_t lane = 0;
        std::memcpy(&lane, g.v[bits(insn, 9, 5)] + index * eb, static_cast<size_t>(eb));
        uint8_t tmp[16]{};
        for (int i = 0; i < bytes; i += eb) std::memcpy(tmp + i, &lane, static_cast<size_t>(eb));
        write_partial(g, insn & 31, tmp, bytes);
        er = EX_NEXT;
        return true;
    }

    // Advanced SIMD three-same / vector FP (bits 28-24 = 01110, bit 21 = 1, bit 10 = 1).
    if (((insn >> 24) & 0x1Fu) == 0x0Eu && bit(insn, 21) && bit(insn, 10)) {
        bool Q = bit(insn, 30);
        bool U = bit(insn, 29);
        unsigned size = bits(insn, 23, 22);
        unsigned opc = bits(insn, 15, 11);
        int bytes = reg_width(Q);
        int rd = insn & 31;
        int rn = bits(insn, 9, 5);
        int rm = bits(insn, 20, 16);
        uint8_t a[16], b[16], d[16];
        read_v(g, rn, a);
        read_v(g, rm, b);
        std::memset(d, 0, 16);
        bool b23 = bit(insn, 23);
        bool pairwise = (U && !b23 && opc == 0x1A) || (U && (opc == 0x18 || opc == 0x1E));
        bool fp = (!U && (opc == 0x18 || opc == 0x19 || opc == 0x1A || opc == 0x1E || opc == 0x1F)) ||
                  (!b23 && opc == 0x1B) || (U && !b23 && opc == 0x1F) || (U && b23 && opc == 0x1A) ||
                  pairwise || (opc == 0x1C && !( !U && b23)) || (U && opc == 0x1D);
        if (fp) {
            bool dbl = bit(insn, 22);
            int es = dbl ? 8 : 4;
            if (bytes % es) return false;
            int lanes = bytes / es;
            if (pairwise && lanes < 2) return false;
            auto num = [](double x, double y, auto pick) {
                if (std::isnan(x)) return y;
                if (std::isnan(y)) return x;
                return pick(x, y);
            };
            auto lane = [&](double x, double y, double acc, uint64_t& bits_out, bool& is_mask) {
                is_mask = false;
                double r = 0;
                if (opc == 0x1A && !U && !b23) r = x + y;
                else if (opc == 0x1A && !U && b23) r = x - y;
                else if (opc == 0x1A && U && b23) r = std::fabs(x - y);
                else if (opc == 0x1B) r = x * y;
                else if (opc == 0x19 && !b23) r = acc + x * y;
                else if (opc == 0x19 && b23) r = acc - x * y;
                else if (opc == 0x18 && !U && !b23) r = num(x, y, [](double p, double q) { return std::max(p, q); });
                else if (opc == 0x18 && !U && b23) r = num(x, y, [](double p, double q) { return std::min(p, q); });
                else if (opc == 0x1E && !U && !b23) r = (std::isnan(x) || std::isnan(y)) ? std::nan("") : std::max(x, y);
                else if (opc == 0x1E && !U && b23) r = (std::isnan(x) || std::isnan(y)) ? std::nan("") : std::min(x, y);
                else if (opc == 0x1F && U && !b23) r = x / y;
                else if (opc == 0x1F && !U && !b23) r = 2.0 - x * y;
                else if (opc == 0x1F && !U && b23) r = (3.0 - x * y) / 2.0;
                else if (opc == 0x1C || opc == 0x1D) {
                    bool c = false;
                    double ax = std::fabs(x), ay = std::fabs(y);
                    if (opc == 0x1C && !U) c = x == y;
                    else if (opc == 0x1C && U && b23) c = x > y;
                    else if (opc == 0x1C && U && !b23) c = x >= y;
                    else if (opc == 0x1D && b23) c = ax > ay;
                    else c = ax >= ay;
                    is_mask = true;
                    bits_out = c ? (es == 8 ? ~0ull : 0xffffffffull) : 0;
                    return;
                } else {
                    bits_out = 0;
                    is_mask = true;
                    return;
                }
                if (!dbl) {
                    float f = static_cast<float>(r);
                    uint32_t u = 0;
                    std::memcpy(&u, &f, 4);
                    bits_out = u;
                } else {
                    std::memcpy(&bits_out, &r, 8);
                }
            };
            auto load = [&](const uint8_t* p, int lane) {
                return dbl ? ld_f64(p + lane * es) : static_cast<double>(ld_f32(p + lane * es));
            };
            for (int i = 0; i < lanes; ++i) {
                double x, y, acc = 0;
                if (pairwise) {
                    int half = lanes / 2;
                    const uint8_t* src = i < half ? a : b;
                    int base = (i % half) * 2;
                    auto pick = [&](double p, double q) {
                        if (opc == 0x1A) return p + q;
                        if (!b23) return num(p, q, [](double u, double v) { return std::max(u, v); });
                        return num(p, q, [](double u, double v) { return std::min(u, v); });
                    };
                    x = pick(load(src, base), load(src, base + 1));
                    y = 0;
                } else {
                    x = load(a, i);
                    y = load(b, i);
                    acc = load(g.v[rd], i);
                }
                uint64_t bits = 0;
                bool mask = false;
                (void)mask;
                if (pairwise) {
                    if (!dbl) {
                        float f = static_cast<float>(x);
                        uint32_t u = 0;
                        std::memcpy(&u, &f, 4);
                        bits = u;
                    } else std::memcpy(&bits, &x, 8);
                } else lane(x, y, acc, bits, mask);
                std::memcpy(d + i * es, &bits, static_cast<size_t>(es));
            }
            write_partial(g, rd, d, bytes);
            er = EX_NEXT;
            return true;
        }
        if (opc == 0x03) {
            // AND/ORR/EOR/BSL/BIT/BIF are bitwise across the register.
            for (int i = 0; i < bytes; i++) {
                uint8_t dst = g.v[rd][i];
                if (!U && size == 0) d[i] = a[i] & b[i];
                else if (!U && size == 2) d[i] = a[i] | b[i];
                else if (U && size == 0) d[i] = a[i] ^ b[i];
                else if (U && size == 1) d[i] = static_cast<uint8_t>((b[i] & a[i]) | (~b[i] & dst));  // BSL
                else if (U && size == 2) d[i] = static_cast<uint8_t>((a[i] & b[i]) | (~b[i] & dst));  // BIT
                else if (U && size == 3) d[i] = static_cast<uint8_t>((a[i] & ~b[i]) | (b[i] & dst));  // BIF
                else return false;
            }
            write_partial(g, rd, d, bytes);
            er = EX_NEXT;
            return true;
        }
        int es = 1 << size;
        if (es == 0 || bytes % es) return false;
        int elements = bytes / es;
        bool pair = opc == 0x14 || opc == 0x15 || (opc == 0x17 && !U);
        if (pair && elements < 2) return false;
        auto loadu = [&](const uint8_t* p) {
            uint64_t v = 0;
            std::memcpy(&v, p, static_cast<size_t>(es));
            return v;
        };
        for (int o = 0; o < bytes; o += es) {
            int i = o / es;
            uint64_t x, y;
            if (pair) {
                int half = elements / 2;
                const uint8_t* src = i < half ? a : b;
                int base = (i % half) * 2 * es;
                x = loadu(src + base);
                y = loadu(src + base + es);
            } else {
                x = loadu(a + o);
                y = loadu(b + o);
            }
            uint64_t r = 0;
            uint64_t lane_mask = es == 8 ? ~0ull : ((1ull << (es * 8)) - 1ull);
            auto as_signed = [&](uint64_t v) -> __int128 {
                if (es == 8) return static_cast<__int128>(static_cast<int64_t>(v));
                __int128 s = v & lane_mask;
                if (s & (static_cast<__int128>(1) << (es * 8 - 1))) s -= static_cast<__int128>(1) << (es * 8);
                return s;
            };
            auto sat_signed = [&](__int128 v) -> uint64_t {
                __int128 minv = -(static_cast<__int128>(1) << (es * 8 - 1));
                __int128 maxv = (static_cast<__int128>(1) << (es * 8 - 1)) - 1;
                if (v < minv) v = minv;
                if (v > maxv) v = maxv;
                return static_cast<uint64_t>(v) & lane_mask;
            };
            auto sat_unsigned = [&](__int128 v) -> uint64_t {
                if (v < 0) return 0;
                if (v > static_cast<__int128>(lane_mask)) return lane_mask;
                return static_cast<uint64_t>(v);
            };
            if (opc == 0x10 && !U) r = (x + y) & lane_mask;
            else if (opc == 0x10 && U) r = (x - y) & lane_mask;
            else if (opc == 0x13 && !U) r = (x * y) & lane_mask;
            else if (opc == 0x11 && U) r = (x == y) ? lane_mask : 0;  // CMEQ
            else if (opc == 0x06 || opc == 0x07) {
                bool ge = opc == 0x07;
                bool c;
                if (U) c = ge ? x >= y : x > y;
                else c = ge ? as_signed(x) >= as_signed(y) : as_signed(x) > as_signed(y);
                r = c ? lane_mask : 0;
            }
            else if (opc == 0x0C || opc == 0x14) {  // SMAX / UMAX, and the pairwise forms
                if (U) r = x > y ? x : y;
                else r = static_cast<uint64_t>(as_signed(x) > as_signed(y) ? as_signed(x) : as_signed(y)) & lane_mask;
            } else if (opc == 0x0D || opc == 0x15) {  // SMIN / UMIN, and the pairwise forms
                if (U) r = x < y ? x : y;
                else r = static_cast<uint64_t>(as_signed(x) < as_signed(y) ? as_signed(x) : as_signed(y)) & lane_mask;
            } else if (opc == 0x0E || opc == 0x0F) {  // SABD / UABD, and the accumulating forms
                uint64_t diff;
                if (U) diff = x > y ? x - y : y - x;
                else {
                    __int128 delta = as_signed(x) - as_signed(y);
                    if (delta < 0) delta = -delta;
                    diff = static_cast<uint64_t>(delta) & lane_mask;
                }
                r = opc == 0x0F ? (loadu(g.v[rd] + o) + diff) & lane_mask : diff;
            } else if (opc == 0x00 || opc == 0x02) {  // halving add, with a round bit for the R forms
                __int128 sum = U ? static_cast<__int128>(x) + y : as_signed(x) + as_signed(y);
                if (opc == 0x02) sum += 1;
                r = static_cast<uint64_t>(sum >> 1) & lane_mask;
            } else if (opc == 0x04) {  // SHSUB / UHSUB
                __int128 diff = U ? static_cast<__int128>(x) - y : as_signed(x) - as_signed(y);
                r = static_cast<uint64_t>(diff >> 1) & lane_mask;
            } else if (opc == 0x01) {  // SQADD / UQADD
                r = U ? sat_unsigned(static_cast<__int128>(x) + y) : sat_signed(as_signed(x) + as_signed(y));
            } else if (opc == 0x05) {  // SQSUB / UQSUB
                r = U ? sat_unsigned(static_cast<__int128>(x) - y) : sat_signed(as_signed(x) - as_signed(y));
            } else if (opc == 0x12) {  // MLA / MLS
                __int128 acc = loadu(g.v[rd] + o);
                __int128 prod = static_cast<__int128>(x) * y;
                r = static_cast<uint64_t>(U ? acc - prod : acc + prod) & lane_mask;
            } else if (opc == 0x16 && (es == 2 || es == 4)) {  // SQDMULH / SQRDMULH
                __int128 most_neg = -(static_cast<__int128>(1) << (es * 8 - 1));
                if (as_signed(x) == most_neg && as_signed(y) == most_neg) {
                    r = static_cast<uint64_t>((static_cast<__int128>(1) << (es * 8 - 1)) - 1);
                } else {
                    __int128 doubled = (as_signed(x) * as_signed(y)) << 1;
                    if (U) doubled += static_cast<__int128>(1) << (es * 8 - 1);
                    r = static_cast<uint64_t>(doubled >> (es * 8)) & lane_mask;
                }
            } else if (opc == 0x17 && !U) {  // ADDP
                r = (x + y) & lane_mask;
            }
            else if (opc == 0x08 && !U) {  // SSHL
                int sh = static_cast<int>(sext_bits(y, es * 8));
                if (sh >= 0) r = (x << sh) & lane_mask;
                else {
                    int s = -sh;
                    if (es == 8) r = static_cast<uint64_t>(static_cast<int64_t>(x) >> s);
                    else if (es == 4) r = static_cast<uint32_t>(static_cast<int32_t>(x) >> s);
                    else if (es == 2) r = static_cast<uint16_t>(static_cast<int16_t>(x) >> s);
                    else r = static_cast<uint8_t>(static_cast<int8_t>(x) >> s);
                }
            } else if (opc == 0x08 && U) {  // USHL
                int sh = static_cast<int>(sext_bits(y, es * 8));
                if (sh >= es * 8 || sh <= -es * 8) r = 0;
                else if (sh >= 0) r = (x << sh) & lane_mask;
                else r = x >> (-sh);
            } else return false;
            std::memcpy(d + o, &r, static_cast<size_t>(es));
        }
        write_partial(g, rd, d, bytes);
        er = EX_NEXT;
        return true;
    }

    // Advanced SIMD shift by immediate. immh != 0 distinguishes it from MOVI.
    if (((insn >> 23) & 0x3Fu) == 0x1Eu && bit(insn, 10)) {
        unsigned immh = bits(insn, 22, 19);
        if (immh != 0) {
            unsigned immb = bits(insn, 18, 16);
            unsigned imm = (immh << 3) | immb;
            int esize = (immh & 8) ? 64 : (immh & 4) ? 32 : (immh & 2) ? 16 : 8;
            bool U = bit(insn, 29);
            bool Q = bit(insn, 30);
            unsigned low = bits(insn, 15, 10);
            int bytes = reg_width(Q);
            if (esize / 8 > bytes) return false;
            bool left = false;
            unsigned shift = 0;
            bool insert = false;
            if (!U && low == 0x15) {  // SHL
                if (imm < static_cast<unsigned>(esize)) return false;
                shift = imm - static_cast<unsigned>(esize);
                left = true;
            } else if (U && low == 0x15) {  // SLI
                if (imm < static_cast<unsigned>(esize)) return false;
                shift = imm - static_cast<unsigned>(esize);
                left = true;
                insert = true;
            } else if (low == 0x00 || low == 0x01) {  // SSHR / USHR
                if (imm > static_cast<unsigned>(esize) * 2) return false;
                shift = static_cast<unsigned>(esize) * 2 - imm;
                left = false;
            } else if (low == 0x29) {  // SSHLL / USHLL, including SXTL / UXTL
                if (imm < static_cast<unsigned>(esize) || imm >= static_cast<unsigned>(esize) * 2) return false;
                unsigned sh = imm - static_cast<unsigned>(esize);
                int src_eb = esize / 8;
                int dst_eb = src_eb * 2;
                if (src_eb <= 0 || dst_eb > 16 || 8 % src_eb) return false;
                int elements = 8 / src_eb;
                uint8_t src[16], out[16]{};
                read_v(g, bits(insn, 9, 5), src);
                int src_off = Q ? 8 : 0;
                for (int i = 0; i < elements; ++i) {
                    uint64_t raw = 0;
                    std::memcpy(&raw, src + src_off + i * src_eb, static_cast<size_t>(src_eb));
                    unsigned __int128 wide;
                    if (!U && src_eb < 8) {
                        uint64_t sign = 1ull << (esize - 1);
                        if (raw & sign) raw |= ~((1ull << esize) - 1ull);
                        wide = static_cast<unsigned __int128>(static_cast<int64_t>(raw));
                    } else if (!U) {
                        wide = static_cast<unsigned __int128>(static_cast<int64_t>(raw));
                    } else {
                        wide = raw;
                    }
                    wide <<= sh;
                    std::memcpy(out + i * dst_eb, &wide, static_cast<size_t>(dst_eb));
                }
                write_v(g, insn & 31, out);
                er = EX_NEXT;
                return true;
            } else return false;
            uint8_t a[16], d[16]{};
            read_v(g, bits(insn, 9, 5), a);
            int eb = esize / 8;
            for (int o = 0; o + eb <= bytes; o += eb) {
                uint64_t v = 0;
                std::memcpy(&v, a + o, static_cast<size_t>(eb));
                uint64_t m = eb == 8 ? ~0ull : ((1ull << (eb * 8)) - 1ull);
                uint64_t r;
                if (left) r = (v << shift) & m;
                else if (!U && low == 0x00) {
                    if (eb == 8) r = static_cast<uint64_t>(static_cast<int64_t>(v) >> shift);
                    else if (eb == 4) r = static_cast<uint32_t>(static_cast<int32_t>(v) >> shift);
                    else if (eb == 2) r = static_cast<uint16_t>(static_cast<int16_t>(v) >> shift);
                    else r = static_cast<uint8_t>(static_cast<int8_t>(v) >> shift);
                } else r = v >> shift;
                if (insert) {
                    uint64_t old = 0;
                    std::memcpy(&old, g.v[insn & 31] + o, static_cast<size_t>(eb));
                    uint64_t keep = shift >= 64 ? 0 : (m << shift);
                    r = (r & ~keep) | (old & keep);
                }
                std::memcpy(d + o, &r, static_cast<size_t>(eb));
            }
            write_partial(g, insn & 31, d, bytes);
            er = EX_NEXT;
            return true;
        }
    }

    // AES / PMULL. Recognized by their fixed opcodes inside the 2-reg misc space.
    if ((insn & 0xFF3FFC00u) == 0x4E284800u || (insn & 0xFFFFFC00u) == 0x4E286800u ||
        (insn & 0xFF3FFC00u) == 0x4E285800u || (insn & 0xFFFFFC00u) == 0x4E287800u) {
        uint8_t d[16], n[16];
        int rd = insn & 31;
        int rn = bits(insn, 9, 5);
        bool mix = (insn & 0xFFFFFC00u) == 0x4E286800u || (insn & 0xFFFFFC00u) == 0x4E287800u;
        if (mix) {
            read_v(g, rn, d);
            if ((insn & 0xFFFFFC00u) == 0x4E286800u) mix_columns(d, false);
            else mix_columns(d, true);
        } else {
            // AESE/AESD read the state from the destination and the key from Rn.
            read_v(g, rd, d);
            read_v(g, rn, n);
            aes_round(d, n, (insn & 0xFF3FFC00u) != 0x4E284800u);
        }
        write_v(g, rd, d);
        er = EX_NEXT;
        return true;
    }
    if ((insn & 0xBFF0FC00u) == 0x0EE0E000u) {
        bool high = bit(insn, 30);
        uint8_t a[16], b[16], d[16]{};
        read_v(g, bits(insn, 9, 5), a);
        read_v(g, bits(insn, 20, 16), b);
        int off = high ? 8 : 0;
        uint64_t aa = 0, bb = 0;
        std::memcpy(&aa, a + off, 8);
        std::memcpy(&bb, b + off, 8);
        unsigned __int128 p = poly_mul(aa, bb);
        uint64_t lo = static_cast<uint64_t>(p);
        uint64_t hi = static_cast<uint64_t>(p >> 64);
        std::memcpy(d, &lo, 8);
        std::memcpy(d + 8, &hi, 8);
        write_v(g, insn & 31, d);
        er = EX_NEXT;
        return true;
    }

    // SHA256 schedule / hash. Opcode bytes from the catalog.
    if ((insn & 0xFFFFF000u) == 0x5E024000u || (insn & 0xFFFFF000u) == 0x5E025000u ||
        (insn & 0xFFFFF000u) == 0x5E282000u || (insn & 0xFFFFF000u) == 0x5E026000u) {
        uint8_t vd[16], vn[16], vm[16];
        read_v(g, insn & 31, vd);
        read_v(g, bits(insn, 9, 5), vn);
        read_v(g, bits(insn, 20, 16), vm);
        uint32_t d[4], n[4], m[4];
        std::memcpy(d, vd, 16);
        std::memcpy(n, vn, 16);
        std::memcpy(m, vm, 16);
        if ((insn & 0xFFFFF000u) == 0x5E024000u) {
            sha256_quad(d, n, m);
            std::memcpy(vd, d, 16);
        } else if ((insn & 0xFFFFF000u) == 0x5E025000u) {
            // SHA256H2 updates the efgh half. Swap roles.
            uint32_t t[4] = {n[0], n[1], n[2], n[3]};
            sha256_quad(t, d, m);
            std::memcpy(vd, t, 16);
        } else if ((insn & 0xFFFFF000u) == 0x5E282000u) {
            uint32_t w[4];
            std::memcpy(w, vd, 16);
            uint32_t s[4];
            std::memcpy(s, vn, 16);
            w[0] = w[0] + sha_s0(s[1]);
            w[1] = w[1] + sha_s0(s[2]);
            w[2] = w[2] + sha_s0(s[3]);
            w[3] = w[3] + sha_s0(w[0]);
            std::memcpy(vd, w, 16);
        } else {
            uint32_t w[4], t0[4], t1[4];
            std::memcpy(w, vd, 16);
            std::memcpy(t0, vn, 16);
            std::memcpy(t1, vm, 16);
            uint32_t r0 = w[0] + sha_s1(t1[2]) + t0[1];
            uint32_t r1 = w[1] + sha_s1(t1[3]) + t0[2];
            uint32_t r2 = w[2] + sha_s1(r0) + t0[3];
            uint32_t r3 = w[3] + sha_s1(r1) + t0[0];
            w[0] = r0;
            w[1] = r1;
            w[2] = r2;
            w[3] = r3;
            std::memcpy(vd, w, 16);
        }
        write_v(g, insn & 31, vd);
        er = EX_NEXT;
        return true;
    }

    // Floating-point multiply by one indexed element, plus the integer forms that share the encoding.
    if (((insn >> 24) & 0x1Fu) == 0x0Fu && bit(insn, 31) == 0 && bit(insn, 10) == 0) {
        unsigned opc = bits(insn, 15, 12);
        bool U = bit(insn, 29);
        int kind = -1;
        if (!U && opc == 0x9) kind = 0;       // FMUL
        else if (U && opc == 0x9) kind = 1;   // FMULX
        else if (!U && opc == 0x1) kind = 2;  // FMLA
        else if (!U && opc == 0x5) kind = 3;  // FMLS
        else if (!U && opc == 0x8) kind = 4;  // MUL
        else if (U && opc == 0x0) kind = 5;   // MLA
        else if (U && opc == 0x4) kind = 6;   // MLS
        else if (!U && opc == 0xC) kind = 7;  // SQDMULH
        else if (!U && opc == 0xD) kind = 8;  // SQRDMULH
        else return false;
        unsigned sz = bits(insn, 23, 22);
        int esize = 0;
        int index = 0;
        int elem_reg = 0;
        if (sz == 0) {
            esize = 2;
            index = static_cast<int>((bit(insn, 11) << 2) | (bit(insn, 21) << 1) | bit(insn, 20));
            elem_reg = static_cast<int>(bits(insn, 19, 16));
        } else if (sz == 2) {
            esize = 4;
            index = static_cast<int>((bit(insn, 11) << 1) | bit(insn, 21));
            elem_reg = static_cast<int>((bit(insn, 20) << 4) | bits(insn, 19, 16));
        } else if (sz == 3) {
            if (bit(insn, 21)) return false;
            esize = 8;
            index = static_cast<int>(bit(insn, 11));
            elem_reg = static_cast<int>((bit(insn, 20) << 4) | bits(insn, 19, 16));
        } else return false;
        if (kind >= 4 && esize == 8) return false;
        if (index < 0 || index * esize + esize > 16) return false;
        int bytes = bit(insn, 30) ? 16 : 8;
        if (esize > bytes) return false;
        uint8_t src[16], dst[16];
        read_v(g, bits(insn, 9, 5), src);
        read_v(g, insn & 31, dst);
        uint64_t elem = 0;
        std::memcpy(&elem, g.v[elem_reg] + index * esize, static_cast<size_t>(esize));
        uint64_t lane_mask = esize == 8 ? ~0ull : (1ull << (esize * 8)) - 1ull;
        auto as_float = [&](uint64_t bitsv) {
            if (esize == 2) return static_cast<double>(half_to_float(static_cast<uint16_t>(bitsv)));
            if (esize == 4) {
                float f = 0;
                std::memcpy(&f, &bitsv, 4);
                return static_cast<double>(f);
            }
            double d = 0;
            std::memcpy(&d, &bitsv, 8);
            return d;
        };
        auto as_signed = [&](uint64_t v) -> __int128 {
            __int128 s = v & lane_mask;
            if (s & (static_cast<__int128>(1) << (esize * 8 - 1))) s -= static_cast<__int128>(1) << (esize * 8);
            return s;
        };
        for (int o = 0; o < bytes; o += esize) {
            uint64_t a = 0;
            std::memcpy(&a, src + o, static_cast<size_t>(esize));
            if (kind <= 3) {
                double x = as_float(a);
                double y = as_float(elem);
                double r;
                if (kind == 1 && ((x == 0.0 && std::isinf(y)) || (y == 0.0 && std::isinf(x)))) {
                    r = (std::signbit(x) != std::signbit(y)) ? -2.0 : 2.0;
                } else if (kind == 2 || kind == 3) {
                    uint64_t acc_bits = 0;
                    std::memcpy(&acc_bits, dst + o, static_cast<size_t>(esize));
                    double acc = as_float(acc_bits);
                    r = kind == 2 ? acc + x * y : acc - x * y;
                } else r = x * y;
                if (esize == 2) {
                    uint16_t h = float_to_half(static_cast<float>(r));
                    std::memcpy(dst + o, &h, 2);
                } else if (esize == 4) st_f32(dst + o, static_cast<float>(r));
                else st_f64(dst + o, r);
            } else if (kind == 7 || kind == 8) {
                __int128 most_neg = -(static_cast<__int128>(1) << (esize * 8 - 1));
                __int128 sx = as_signed(a);
                __int128 sy = as_signed(elem);
                uint64_t out;
                if (sx == most_neg && sy == most_neg) out = static_cast<uint64_t>((static_cast<__int128>(1) << (esize * 8 - 1)) - 1);
                else {
                    __int128 doubled = (sx * sy) << 1;
                    if (kind == 8) doubled += static_cast<__int128>(1) << (esize * 8 - 1);
                    out = static_cast<uint64_t>(doubled >> (esize * 8)) & lane_mask;
                }
                std::memcpy(dst + o, &out, static_cast<size_t>(esize));
            } else {
                uint64_t prod = static_cast<uint64_t>(static_cast<__int128>(a & lane_mask) * (elem & lane_mask)) & lane_mask;
                uint64_t out = prod;
                if (kind != 4) {
                    uint64_t acc = 0;
                    std::memcpy(&acc, dst + o, static_cast<size_t>(esize));
                    out = (kind == 5 ? acc + prod : acc - prod) & lane_mask;
                }
                std::memcpy(dst + o, &out, static_cast<size_t>(esize));
            }
        }
        write_partial(g, insn & 31, dst, bytes);
        er = EX_NEXT;
        return true;
    }

    // FCVT* from floating-point lanes to integers. Bit 23 and bits 15-12 select the rounding.
    if ((insn & 0x8F3F0C00u) == 0x0E210800u) {
        unsigned op = bits(insn, 15, 12);
        bool hi = bit(insn, 23);
        int mode = -1;
        if (!hi && op == 0xA) mode = 0;       // FCVTN, ties to even
        else if (!hi && op == 0xB) mode = 1;  // FCVTM
        else if (!hi && op == 0xC) mode = 2;  // FCVTA
        else if (hi && op == 0xA) mode = 3;   // FCVTP
        else if (hi && op == 0xB) mode = 4;   // FCVTZ
        if (mode >= 0) {
            bool uns = bit(insn, 29);
            bool scalar = bit(insn, 28);
            bool wide = bit(insn, 22);
            int es = wide ? 8 : 4;
            int bytes = scalar ? es : (bit(insn, 30) ? 16 : 8);
            uint8_t src[16], dst[16]{};
            read_v(g, bits(insn, 9, 5), src);
            for (int o = 0; o + es <= bytes; o += es) {
                double v = wide ? ld_f64(src + o) : static_cast<double>(ld_f32(src + o));
                if (std::isnan(v)) v = 0;
                else if (mode == 0) v = std::nearbyint(v);
                else if (mode == 1) v = std::floor(v);
                else if (mode == 2) v = std::round(v);
                else if (mode == 3) v = std::ceil(v);
                else v = std::trunc(v);
                uint64_t iv = 0;
                if (uns) {
                    if (v <= 0) iv = 0;
                    else if (es == 8) iv = v >= 18446744073709551616.0 ? ~0ull : static_cast<uint64_t>(v);
                    else iv = v >= 4294967296.0 ? 0xffffffffull : static_cast<uint32_t>(v);
                } else if (es == 8) {
                    if (v >= 9223372036854775808.0) iv = 0x7fffffffffffffffll;
                    else if (v <= -9223372036854775808.0) iv = 0x8000000000000000ull;
                    else iv = static_cast<uint64_t>(static_cast<int64_t>(v));
                } else if (v >= 2147483648.0) iv = 0x7fffffffu;
                else if (v <= -2147483649.0) iv = 0x80000000u;
                else iv = static_cast<uint32_t>(static_cast<int32_t>(v));
                std::memcpy(dst + o, &iv, static_cast<size_t>(es));
            }
            write_partial(g, insn & 31, dst, bytes);
            er = EX_NEXT;
            return true;
        }
    }

    // SCVTF / UCVTF, scalar and vector. Size is bit 22; bit 28 selects the scalar form.
    if ((insn & 0x8FBFFC00u) == 0x0E21D800u) {
        bool uns = bit(insn, 29);
        bool scalar = bit(insn, 28);
        bool wide = bit(insn, 22);
        bool Q = bit(insn, 30);
        int es = wide ? 8 : 4;
        int bytes = scalar ? es : (Q ? 16 : 8);
        uint8_t src[16], dst[16]{};
        read_v(g, bits(insn, 9, 5), src);
        for (int o = 0; o + es <= bytes; o += es) {
            uint64_t raw = 0;
            std::memcpy(&raw, src + o, static_cast<size_t>(es));
            double dv;
            if (uns) dv = wide ? static_cast<double>(raw) : static_cast<double>(static_cast<uint32_t>(raw));
            else if (wide) dv = static_cast<double>(static_cast<int64_t>(raw));
            else dv = static_cast<double>(static_cast<int32_t>(raw));
            if (wide) st_f64(dst + o, dv);
            else st_f32(dst + o, static_cast<float>(dv));
        }
        write_partial(g, insn & 31, dst, bytes);
        er = EX_NEXT;
        return true;
    }

    // LD1/ST1 of one lane, and LD1R. 11111 in Rm is an immediate post-index.
    if ((insn & 0xBF000000u) == 0x0D000000u) {
        unsigned op6 = bits(insn, 15, 10);
        bool Q = bit(insn, 30);
        bool load = bit(insn, 22);
        int rm = bits(insn, 20, 16);
        int rn = bits(insn, 9, 5);
        int rt = insn & 31;
        int esize = 0;
        int index = 0;
        bool replicate = false;
        if ((op6 >> 3) == 0) {
            esize = 1;
            index = (Q ? 8 : 0) | static_cast<int>(op6 & 7);
        } else if ((op6 >> 3) == 2 && (op6 & 1) == 0) {
            esize = 2;
            index = (Q ? 4 : 0) | static_cast<int>((op6 >> 1) & 3);
        } else if ((op6 >> 3) == 4 && (op6 & 3) == 0) {
            esize = 4;
            index = (Q ? 2 : 0) | static_cast<int>((op6 >> 2) & 1);
        } else if (op6 == 0x21) {
            esize = 8;
            index = Q ? 1 : 0;
        } else if (load && (op6 >> 2) == 0xC) {
            replicate = true;
            esize = 1 << (op6 & 3);
        } else return false;
        if (esize <= 0 || index * esize + esize > 16) return false;
        uint64_t addr = rbase(g, rn);
        if (replicate) {
            uint64_t v = mem_load(addr, esize);
            int bytes = Q ? 16 : 8;
            uint8_t dst[16]{};
            for (int o = 0; o + esize <= bytes; o += esize) std::memcpy(dst + o, &v, static_cast<size_t>(esize));
            write_partial(g, rt, dst, bytes);
        } else if (load) {
            uint64_t v = mem_load(addr, esize);
            std::memcpy(g.v[rt] + index * esize, &v, static_cast<size_t>(esize));
        } else {
            uint64_t v = 0;
            std::memcpy(&v, g.v[rt] + index * esize, static_cast<size_t>(esize));
            mem_store(addr, v, esize);
        }
        if (rm != 0) {
            uint64_t off = rm == 31 ? static_cast<uint64_t>(esize) : rx(g, rm);
            wbase(g, rn, addr + off);
        }
        er = EX_NEXT;
        return true;
    }

    // TBL / TBX. len is the table length in registers, minus one.
    if ((insn & 0xBFE08C00u) == 0x0E000000u) {
        bool Q = bit(insn, 30);
        int bytes = Q ? 16 : 8;
        int regs = static_cast<int>(bits(insn, 14, 13)) + 1;
        bool tbx = bit(insn, 12);
        uint8_t idx[16], dst[16], table[64];
        read_v(g, bits(insn, 20, 16), idx);
        read_v(g, insn & 31, dst);
        int base = bits(insn, 9, 5);
        for (int i = 0; i < regs; ++i) read_v(g, (base + i) & 31, table + i * 16);
        int table_bytes = regs * 16;
        for (int i = 0; i < bytes; ++i) {
            unsigned ix = idx[i];
            if (ix < static_cast<unsigned>(table_bytes)) dst[i] = table[ix];
            else if (!tbx) dst[i] = 0;
        }
        if (!Q && !tbx) std::memset(dst + 8, 0, 8);
        write_v(g, insn & 31, dst);
        er = EX_NEXT;
        return true;
    }

    // Half-precision negate / absolute value. The sign bit is enough.
    if ((insn & 0x9FFFFC00u) == 0x0EF8F800u) {
        bool neg = bit(insn, 29);
        int lanes = bit(insn, 30) ? 8 : 4;
        uint8_t a[16], d[16]{};
        read_v(g, bits(insn, 9, 5), a);
        for (int i = 0; i < lanes; ++i) {
            uint16_t h = 0;
            std::memcpy(&h, a + i * 2, 2);
            h = neg ? static_cast<uint16_t>(h ^ 0x8000u) : static_cast<uint16_t>(h & 0x7fffu);
            std::memcpy(d + i * 2, &h, 2);
        }
        write_partial(g, insn & 31, d, lanes * 2);
        er = EX_NEXT;
        return true;
    }
    // Half-precision three-same arithmetic. bit 22 marks the fp16 encoding.
    if (((insn >> 24) & 0x1Fu) == 0x0Eu && !bit(insn, 21) && bit(insn, 10) && bit(insn, 22)) {
        bool Q = bit(insn, 30);
        bool U = bit(insn, 29);
        bool b23 = bit(insn, 23);
        unsigned opc = bits(insn, 15, 11);
        int nlanes = Q ? 8 : 4;
        uint8_t a[16], b[16], d[16]{};
        read_v(g, bits(insn, 9, 5), a);
        read_v(g, bits(insn, 20, 16), b);
        for (int i = 0; i < nlanes; ++i) {
            uint16_t hx = 0, hy = 0;
            std::memcpy(&hx, a + i * 2, 2);
            std::memcpy(&hy, b + i * 2, 2);
            float x = half_to_float(hx), y = half_to_float(hy), r = 0;
            if (opc == 0x02 && !U && !b23) r = x + y;
            else if (opc == 0x02 && !U && b23) r = x - y;
            else if (opc == 0x03 && U && !b23) r = x * y;
            else if (opc == 0x07 && U && !b23) r = x / y;
            else if (opc == 0x00 && !U && !b23) r = std::isnan(x) ? y : std::isnan(y) ? x : std::max(x, y);
            else if (opc == 0x06 && !U && !b23) r = (std::isnan(x) || std::isnan(y)) ? std::nanf("") : std::max(x, y);
            else if (opc == 0x06 && !U && b23) r = (std::isnan(x) || std::isnan(y)) ? std::nanf("") : std::min(x, y);
            else return false;
            uint16_t hr = float_to_half(r);
            std::memcpy(d + i * 2, &hr, 2);
        }
        write_partial(g, insn & 31, d, nlanes * 2);
        er = EX_NEXT;
        return true;
    }
    // FCVTL / FCVTN between half and single.
    if ((insn & 0xBF3FFC00u) == 0x0E217800u || (insn & 0xBF3FFC00u) == 0x0E216800u) {
        bool widen = (insn & 0xBF3FFC00u) == 0x0E217800u;
        bool high = bit(insn, 30);
        uint8_t a[16], d[16]{};
        read_v(g, bits(insn, 9, 5), a);
        if (widen) {
            int off = high ? 8 : 0;
            for (int i = 0; i < 4; ++i) {
                uint16_t h = 0;
                std::memcpy(&h, a + off + i * 2, 2);
                st_f32(d + i * 4, half_to_float(h));
            }
        } else {
            if (high) read_v(g, insn & 31, d);
            int off = high ? 8 : 0;
            for (int i = 0; i < 4; ++i) {
                uint16_t h = float_to_half(ld_f32(a + i * 4));
                std::memcpy(d + off + i * 2, &h, 2);
            }
        }
        write_v(g, insn & 31, d);
        er = EX_NEXT;
        return true;
    }

    // Vector compare-with-zero, plus integer ABS / NEG in the same encoding.
    if ((insn & 0x9F3FCC00u) == 0x0E208800u) {
        bool U = bit(insn, 29);
        bool Q = bit(insn, 30);
        unsigned op = bits(insn, 13, 12);
        int esize = 1 << bits(insn, 23, 22);
        int bytes = Q ? 16 : 8;
        if (esize > bytes) return false;
        uint8_t a[16], d[16]{};
        read_v(g, bits(insn, 9, 5), a);
        for (int o = 0; o + esize <= bytes; o += esize) {
            uint64_t raw = 0;
            std::memcpy(&raw, a + o, static_cast<size_t>(esize));
            uint64_t sign = esize == 8 ? 0x8000000000000000ull : 1ull << (esize * 8 - 1);
            uint64_t ones = esize == 8 ? ~0ull : (1ull << (esize * 8)) - 1ull;
            int64_t sv = static_cast<int64_t>(raw & sign ? raw | ~ones : raw);
            uint64_t out = 0;
            if (op == 0 && !U) out = sv > 0 ? ones : 0;
            else if (op == 0 && U) out = sv >= 0 ? ones : 0;
            else if (op == 1 && !U) out = sv == 0 ? ones : 0;
            else if (op == 1 && U) out = sv <= 0 ? ones : 0;
            else if (op == 2 && !U) out = sv < 0 ? ones : 0;
            else if (op == 3 && !U) out = (raw & sign) ? ((~raw + 1) & ones) : (raw & ones);
            else if (op == 3 && U) out = (~raw + 1) & ones;
            else return false;
            std::memcpy(d + o, &out, static_cast<size_t>(esize));
        }
        write_partial(g, insn & 31, d, bytes);
        er = EX_NEXT;
        return true;
    }

    // UMOV / SMOV: copy one vector lane into a general register.
    if ((insn & 0xBFE0FC00u) == 0x0E003C00u || (insn & 0xBFE0FC00u) == 0x0E002C00u) {
        bool smov = (insn & 0xBFE0FC00u) == 0x0E002C00u;
        unsigned imm5 = bits(insn, 20, 16);
        if (imm5 == 0) return false;
        int lsb = __builtin_ctz(imm5);
        int esize = 8 << lsb;
        int index = static_cast<int>(imm5 >> (lsb + 1));
        bool to64 = bit(insn, 30);
        int eb = esize / 8;
        if (eb <= 0 || index * eb + eb > 16) return false;
        if (smov && esize >= 64) return false;
        if (!to64 && esize > 32) return false;
        uint64_t raw = 0;
        std::memcpy(&raw, g.v[bits(insn, 9, 5)] + index * eb, static_cast<size_t>(eb));
        if (smov) {
            uint64_t sign = 1ull << (esize - 1);
            uint64_t ones = (1ull << esize) - 1ull;
            if (raw & sign) raw |= ~ones;
        }
        wx(g, insn & 31, raw, to64);
        er = EX_NEXT;
        return true;
    }

    // MOV scalar from an element: the chosen lane becomes lane 0 and the rest is cleared.
    if ((insn & 0xFFE0FC00u) == 0x5E000400u) {
        unsigned imm5 = bits(insn, 20, 16);
        if (imm5 == 0) return false;
        int lsb = __builtin_ctz(imm5);
        int eb = 1 << lsb;
        int index = static_cast<int>(imm5 >> (lsb + 1));
        if (eb <= 0 || index * eb + eb > 16) return false;
        uint8_t lane[16]{};
        std::memcpy(lane, g.v[bits(insn, 9, 5)] + index * eb, static_cast<size_t>(eb));
        write_partial(g, insn & 31, lane, eb);
        er = EX_NEXT;
        return true;
    }
    // INS from a general register: mov Vd.T[index], Rn. Other lanes stay put.
    if ((insn & 0x7FE0FC00u) == 0x4E001C00u) {
        unsigned imm5 = bits(insn, 20, 16);
        if (imm5 == 0) return false;
        int lsb = __builtin_ctz(imm5);
        int eb = 1 << lsb;
        int index = static_cast<int>(imm5 >> (lsb + 1));
        if (eb > 8 || index * eb + eb > 16) return false;
        uint8_t lane[16];
        read_v(g, insn & 31, lane);
        uint64_t raw = rx(g, bits(insn, 9, 5));
        std::memcpy(lane + index * eb, &raw, static_cast<size_t>(eb));
        write_v(g, insn & 31, lane);
        er = EX_NEXT;
        return true;
    }
    // INS: copy one source lane into one destination lane.
    if ((insn & 0xFFE08400u) == 0x6E000400u) {
        unsigned imm5 = bits(insn, 20, 16);
        unsigned imm4 = bits(insn, 14, 11);
        if (imm5 == 0) return false;
        int lsb = __builtin_ctz(imm5);
        int eb = 1 << lsb;
        int dst_index = static_cast<int>(imm5 >> (lsb + 1));
        int src_index = static_cast<int>(imm4 >> lsb);
        if (eb > 8 || dst_index * eb + eb > 16 || src_index * eb + eb > 16) return false;
        uint8_t lane[16];
        read_v(g, insn & 31, lane);
        std::memcpy(lane + dst_index * eb, g.v[bits(insn, 9, 5)] + src_index * eb, static_cast<size_t>(eb));
        write_v(g, insn & 31, lane);
        er = EX_NEXT;
        return true;
    }
    // XTN / XTN2: keep the low half of each wider lane.
    if ((insn & 0xBF3FFC00u) == 0x0E212800u) {
        int dest_es = 1 << bits(insn, 23, 22);
        int src_es = dest_es * 2;
        if (dest_es <= 0 || dest_es > 4) return false;
        int elements = 8 / dest_es;
        bool high = bit(insn, 30);
        uint8_t src[16], dst[16]{};
        read_v(g, bits(insn, 9, 5), src);
        if (high) read_v(g, insn & 31, dst);
        int base = high ? 8 : 0;
        for (int i = 0; i < elements; ++i) std::memcpy(dst + base + i * dest_es, src + i * src_es, static_cast<size_t>(dest_es));
        write_v(g, insn & 31, dst);
        er = EX_NEXT;
        return true;
    }
    // SMINV / UMINV / SMAXV / UMAXV.
    if ((insn & 0x9F3EFC00u) == 0x0E30A800u) {
        bool uns = bit(insn, 29);
        bool is_min = bit(insn, 16);
        int es = 1 << bits(insn, 23, 22);
        int bytes = bit(insn, 30) ? 16 : 8;
        if (es <= 0 || es > bytes) return false;
        uint8_t src[16];
        read_v(g, bits(insn, 9, 5), src);
        uint64_t best = 0;
        for (int o = 0; o + es <= bytes; o += es) {
            uint64_t raw = 0;
            std::memcpy(&raw, src + o, static_cast<size_t>(es));
            if (o == 0) {
                best = raw;
                continue;
            }
            bool better;
            if (uns) better = is_min ? raw < best : raw > best;
            else {
                auto sx = [&](uint64_t v) {
                    uint64_t sign = 1ull << (es * 8 - 1);
                    uint64_t wide = es == 8 ? ~0ull : (1ull << (es * 8)) - 1ull;
                    return static_cast<int64_t>(v & sign ? v | ~wide : v);
                };
                better = is_min ? sx(raw) < sx(best) : sx(raw) > sx(best);
            }
            if (better) best = raw;
        }
        uint8_t dst[16]{};
        std::memcpy(dst, &best, static_cast<size_t>(es));
        write_partial(g, insn & 31, dst, es);
        er = EX_NEXT;
        return true;
    }

    return false;
}

}  // namespace

ExecResult exec_insn(Guest& g, uint32_t insn) {
    ExecResult er = EX_STOP;
    if (try_branch(g, insn, er)) return er;
    if (try_system(g, insn, er)) return er;
    if (try_int(g, insn, er)) return er;
    if (try_mem(g, insn, er)) return er;
    if (try_fp_scalar(g, insn, er)) return er;
    if (try_simd(g, insn, er)) return er;
    g.stop = 2;
    g.stop_insn = insn;
    g.stop_pc = g.pc;
    g.stop_why = "unimplemented";
    return EX_STOP;
}

ExecResult step(Guest& g) {
    uint32_t insn = 0;
    std::memcpy(&insn, reinterpret_cast<const void*>(tbi(g.pc)), 4);
    ExecResult r = exec_insn(g, insn);
    if (r == EX_NEXT) g.pc += 4;
    g.steps++;
    return r;
}

}  // namespace lb

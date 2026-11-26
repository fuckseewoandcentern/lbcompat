#include "lb/guest.hpp"

#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>

#include <sys/mman.h>

using namespace lb;

static int g_fails = 0;

#define CHECK(cond)                                                                 \
    do {                                                                            \
        if (!(cond)) {                                                              \
            std::fprintf(stderr, "FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond);   \
            g_fails++;                                                              \
        }                                                                           \
    } while (0)

static void run(Guest& g, uint32_t insn) {
    ExecResult r = exec_insn(g, insn);
    if (r == EX_NEXT) g.pc += 4;
}

static void set_f32(Guest& g, int r, float f) {
    std::memset(g.v[r], 0, 16);
    std::memcpy(g.v[r], &f, 4);
}
static float get_f32(const Guest& g, int r) {
    float f;
    std::memcpy(&f, g.v[r], 4);
    return f;
}
static void set_f64(Guest& g, int r, double d) {
    std::memset(g.v[r], 0, 16);
    std::memcpy(g.v[r], &d, 8);
}
static double get_f64(const Guest& g, int r) {
    double d;
    std::memcpy(&d, g.v[r], 8);
    return d;
}
static bool bytes_eq(const uint8_t* p, std::initializer_list<uint8_t> xs) {
    size_t i = 0;
    for (uint8_t b : xs) {
        if (p[i++] != b) return false;
    }
    return true;
}

static uint8_t* map_page() {
    void* p = mmap(nullptr, 65536, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(p != MAP_FAILED);
    return static_cast<uint8_t*>(p);
}

static void test_integer() {
    Guest g;
    g.x[1] = 10;
    run(g, 0x91001420);  // add x0, x1, #5
    CHECK(g.x[0] == 15);

    g = {};
    g.x[1] = 0xffffffffu;
    run(g, 0x11001420);  // add w0, w1, #5
    CHECK(g.x[0] == 4);

    g = {};
    g.x[1] = 0x7fffffffffffffffll;
    run(g, 0xb1000420);  // adds x0, x1, #1
    CHECK(g.x[0] == 0x8000000000000000ull);
    CHECK(g.nzcv == 0x90000000u);  // N V

    g = {};
    g.sp = 0x1000;
    run(g, 0xd10e83ff);  // sub sp, sp, #0x3a0
    CHECK(g.sp == 0x1000 - 0x3a0);
    run(g, 0x910043fd);  // add x29, sp, #0x10
    CHECK(g.x[29] == 0x1000 - 0x3a0 + 0x10);

    g = {};
    g.x[1] = 20;
    g.x[2] = 5;
    run(g, 0xeb020020);  // subs x0, x1, x2
    CHECK(g.x[0] == 15);
    CHECK((g.nzcv & 0x40000000u) == 0);
    CHECK((g.nzcv & 0x20000000u) != 0);

    g = {};
    g.x[1] = 100;
    g.x[2] = 2;
    run(g, 0xcb020c20);  // sub x0, x1, x2, lsl #3
    CHECK(g.x[0] == 84);

    g = {};
    g.x[1] = 10;
    g.x[2] = 3;
    run(g, 0x8b224820);  // add x0, x1, w2, uxtw #2
    CHECK(g.x[0] == 22);

    g = {};
    g.sp = 100;
    g.x[1] = static_cast<uint64_t>(-2);
    run(g, 0x8b21efe0);  // add x0, sp, x1, sxtx #3
    CHECK(g.x[0] == 84);

    g = {};
    g.x[1] = 0x1ff;
    run(g, 0x92401c20);  // and x0, x1, #0xff
    CHECK(g.x[0] == 0xff);

    g = {};
    run(g, 0xb24003e0);  // orr x0, xzr, #1
    CHECK(g.x[0] == 1);

    g = {};
    g.x[1] = 0xf0;
    g.x[2] = 0x0f;
    run(g, 0xaa020020);  // orr x0, x1, x2
    CHECK(g.x[0] == 0xff);

    g = {};
    g.x[1] = 0x1234;
    run(g, 0xaa0103e2);  // mov x2, x1
    CHECK(g.x[2] == 0x1234);

    g = {};
    g.x[1] = 0xff;
    g.x[2] = 0x0f;
    run(g, 0xea020020);  // ands x0, x1, x2
    CHECK(g.x[0] == 0x0f);
    CHECK((g.nzcv & 0x30000000u) == 0);

    g = {};
    g.x[0] = 2;
    run(g, 0xf240001f);  // tst x0, #1
    CHECK((g.nzcv & 0x40000000u) != 0);
    g.x[0] = 1;
    run(g, 0xf240001f);
    CHECK((g.nzcv & 0x40000000u) == 0);

    g = {};
    run(g, 0xd2815780);  // movz x0, #0xabc
    run(g, 0xf2a1bde0);  // movk x0, #0xdef, lsl #16
    CHECK(g.x[0] == 0xdef0abcu);

    g = {};
    run(g, 0x12800000);  // movn w0, #0
    CHECK(g.x[0] == 0xffffffffu);

    g = {};
    g.x[1] = 0x10;
    run(g, 0xd344fc20);  // lsr x0, x1, #4
    CHECK(g.x[0] == 1);

    g = {};
    g.x[1] = 0x1fffffff;
    run(g, 0x531d7020);  // lsl w0, w1, #3
    CHECK(g.x[0] == 0xfffffff8u);

    g = {};
    g.x[1] = 0x8000000000000000ull;
    run(g, 0x9344fc20);  // asr x0, x1, #4
    CHECK(g.x[0] == 0xf800000000000000ull);

    g = {};
    g.x[1] = 0xab0;
    run(g, 0xd3442c20);  // ubfx x0, x1, #4, #8
    CHECK(g.x[0] == 0xab);

    g = {};
    g.x[1] = 0xffffffffu;
    run(g, 0x93407c20);  // sxtw x0, w1
    CHECK(g.x[0] == ~0ull);

    g = {};
    g.x[1] = 0x1ff;
    run(g, 0x93401c20);  // sxtb x0, w1
    CHECK(g.x[0] == ~0ull);

    g = {};
    g.x[0] = 0xffffffffffffffffull;
    g.x[1] = 0xab;
    run(g, 0xb37c1c20);  // bfi x0, x1, #4, #8
    CHECK(g.x[0] == 0xfffffffffffffabfull);

    g = {};
    g.x[1] = 0x0123456789abcdefull;
    g.x[2] = 0xfedcba9876543210ull;
    run(g, 0x93c22020);  // extr x0, x1, x2, #8
    CHECK(g.x[0] == ((g.x[1] << 56) | (0xfedcba9876543210ull >> 8)));

    g = {};
    g.x[1] = 2;
    g.x[2] = 3;
    g.x[3] = 4;
    run(g, 0x9b020c20);  // madd x0, x1, x2, x3
    CHECK(g.x[0] == 10);
    g.x[3] = 4;
    run(g, 0x9b028c20);  // msub
    CHECK(g.x[0] == static_cast<uint64_t>(-2));

    g = {};
    g.x[1] = 0xffffffffu;
    g.x[2] = 2;
    g.x[3] = 10;
    run(g, 0x9b220c20);  // smaddl
    CHECK(g.x[0] == 8);

    g = {};
    g.x[1] = ~0ull;
    g.x[2] = ~0ull;
    run(g, 0x9bc27c20);  // umulh
    CHECK(g.x[0] == 0xfffffffffffffffeull);

    g = {};
    g.x[1] = 20;
    g.x[2] = 3;
    run(g, 0x9ac20820);
    CHECK(g.x[0] == 6);
    g.x[2] = 0;
    run(g, 0x9ac20820);
    CHECK(g.x[0] == 0);

    g = {};
    g.x[1] = static_cast<uint64_t>(-20);
    g.x[2] = 3;
    run(g, 0x9ac20c20);
    CHECK(static_cast<int64_t>(g.x[0]) == -6);
    g.x[1] = 0x8000000000000000ull;
    g.x[2] = ~0ull;
    run(g, 0x9ac20c20);
    CHECK(g.x[0] == 0x8000000000000000ull);

    g = {};
    g.nzcv = 0x40000000u;  // Z
    g.x[1] = 5;
    g.x[2] = 9;
    run(g, 0x9a820020);  // csel eq
    CHECK(g.x[0] == 5);
    g.nzcv = 0;
    run(g, 0x9a820020);
    CHECK(g.x[0] == 9);

    g = {};
    g.nzcv = 0;
    g.x[1] = 5;
    g.x[2] = 8;
    run(g, 0x9a821420);  // csinc ne (ne is true)
    CHECK(g.x[0] == 5);
    g.nzcv = 0x40000000u;
    run(g, 0x9a821420);
    CHECK(g.x[0] == 9);

    g = {};
    g.nzcv = 0x40000000u;
    run(g, 0x9a9f17e0);  // cset eq
    CHECK(g.x[0] == 1);
    g.nzcv = 0;
    run(g, 0x9a9f17e0);
    CHECK(g.x[0] == 0);

    g = {};
    g.nzcv = 0;  // NE holds
    g.x[0] = 0;
    run(g, 0xfa401800);  // ccmp x0, #0, #0, ne
    CHECK((g.nzcv & 0x40000000u) != 0);
    g.nzcv = 0x40000000u;  // NE fails, nzcv becomes 0
    g.x[0] = 5;
    run(g, 0xfa401800);
    CHECK(g.nzcv == 0);

    g = {};
    g.nzcv = 0x20000000u;  // C
    g.x[1] = 5;
    g.x[2] = 7;
    run(g, 0x9a020020);  // adc
    CHECK(g.x[0] == 13);

    g = {};
    g.nzcv = 0x20000000u;
    g.x[1] = 10;
    g.x[2] = 3;
    run(g, 0xda020020);  // sbc with C=1 is a subtraction
    CHECK(g.x[0] == 7);
    g.nzcv = 0;
    g.x[1] = 10;
    g.x[2] = 3;
    run(g, 0xda020020);
    CHECK(g.x[0] == 6);

    g = {};
    g.x[1] = 1;
    run(g, 0xdac01020);  // clz
    CHECK(g.x[0] == 63);
    g.x[1] = 0;
    run(g, 0xdac01020);
    CHECK(g.x[0] == 64);

    g = {};
    g.x[1] = 1;
    run(g, 0xdac00020);  // rbit
    CHECK(g.x[0] == 0x8000000000000000ull);

    g = {};
    g.x[1] = 0x0102030405060708ull;
    run(g, 0xdac00c20);  // rev
    CHECK(g.x[0] == 0x0807060504030201ull);

    g = {};
    g.x[1] = 0x12345678;
    run(g, 0x5ac00420);  // rev16 w0, w1
    CHECK(g.x[0] == 0x34127856u);

    g = {};
    g.x[1] = 7;
    g.x[2] = 6;
    run(g, 0x9b027c20);  // mul x0, x1, x2
    CHECK(g.x[0] == 42);

    g = {};
    g.x[1] = 0xff00;
    g.x[2] = 0x0ff0;
    run(g, 0xca020020);  // eor
    CHECK(g.x[0] == 0xf0f0);

    g = {};
    g.pc = 0x123456789ull;
    run(g, 0x90000002);  // adrp x2, #0
    CHECK(g.x[2] == (0x123456789ull & ~0xfffull));
    g.pc = 0x123456789ull;
    run(g, 0x10000002);  // adr x2, #0
    CHECK(g.x[2] == 0x123456789ull);

    g = {};
    g.pc = 0x1000;
    run(g, 0xd503201f);  // nop
    CHECK(g.pc == 0x1004);

    g = {};
    g.nzcv = 0x60000000u;
    run(g, 0xd53b4200);  // mrs x0, nzcv
    CHECK(g.x[0] == 0x60000000u);
    g.x[0] = 0x90000000u;
    run(g, 0xd51b4200);  // msr nzcv, x0
    CHECK(g.nzcv == 0x90000000u);

    g = {};
    g.pc = 0x2000;
    ExecResult brk = exec_insn(g, 0xd4200020);
    CHECK(brk == EX_STOP);
    CHECK(g.stop_why != nullptr);
    CHECK(std::strcmp(g.stop_why, "brk") == 0);
}

static void test_branch() {
    Guest g;
    g.pc = 0x1000;
    ExecResult r = exec_insn(g, 0x14000002);  // b +8
    CHECK(r == EX_BRANCH);
    CHECK(g.pc == 0x1008);

    g.pc = 0x1000;
    g.x[30] = 0;
    r = exec_insn(g, 0x94000002);  // bl +8
    CHECK(g.pc == 0x1008);
    CHECK(g.x[30] == 0x1004);

    g.pc = 0x1000;
    g.x[0] = 0;
    r = exec_insn(g, 0xb4000040);  // cbz x0, +8
    CHECK(g.pc == 0x1008);
    g.pc = 0x1000;
    g.x[0] = 1;
    exec_insn(g, 0xb4000040);
    CHECK(g.pc == 0x1004);

    g.pc = 0x1000;
    g.x[0] = 8;
    exec_insn(g, 0x36180040);  // tbz w0, #3, +8
    CHECK(g.pc == 0x1004);
    g.pc = 0x1000;
    g.x[0] = 0;
    exec_insn(g, 0x36180040);
    CHECK(g.pc == 0x1008);

    g.pc = 0x1000;
    g.x[0] = 0x8000000000000000ull;
    exec_insn(g, 0xb7f80040);  // tbnz x0, #63, +8
    CHECK(g.pc == 0x1008);

    g.pc = 0x1000;
    g.x[30] = 0xabcdef0;
    exec_insn(g, 0xd65f03c0);  // ret
    CHECK(g.pc == 0xabcdef0);

    g.pc = 0x1000;
    g.x[1] = 0x5550;
    exec_insn(g, 0xd61f0020);  // br x1
    CHECK(g.pc == 0x5550);

    g.pc = 0x1000;
    g.x[2] = 0x6660;
    exec_insn(g, 0xd63f0040);  // blr x2
    CHECK(g.pc == 0x6660);
    CHECK(g.x[30] == 0x1004);

    g.pc = 0x1000;
    g.nzcv = 0;
    exec_insn(g, 0x54000061);  // b.ne +12
    CHECK(g.pc == 0x100c);
    g.pc = 0x1000;
    g.nzcv = 0x40000000u;
    exec_insn(g, 0x54000061);
    CHECK(g.pc == 0x1004);
}

static void test_memory() {
    uint8_t* mem = map_page();
    uint64_t b = reinterpret_cast<uint64_t>(mem);
    Guest g;

    std::memset(mem, 0, 256);
    for (int i = 0; i < 64; i++) mem[i] = static_cast<uint8_t>(i + 1);
    g.x[1] = b;
    run(g, 0xf9400820);  // ldr x0, [x1, #16]
    uint64_t expect = 0;
    std::memcpy(&expect, mem + 16, 8);
    CHECK(g.x[0] == expect);

    run(g, 0xb9400420);  // ldr w0, [x1, #4]
    uint32_t w = 0;
    std::memcpy(&w, mem + 4, 4);
    CHECK(g.x[0] == w);

    run(g, 0x39400420);  // ldrb w0, [x1, #1]
    CHECK(g.x[0] == mem[1]);

    mem[1] = 0x80;
    run(g, 0x39800420);  // ldrsb x0, [x1, #1]
    CHECK(g.x[0] == 0xffffffffffffff80ull);
    run(g, 0x39c00420);  // ldrsb w0
    CHECK(g.x[0] == 0xffffff80u);

    g.x[0] = 0x1122334455667788ull;
    run(g, 0xf9000420);  // str x0, [x1, #8]
    uint64_t got = 0;
    std::memcpy(&got, mem + 8, 8);
    CHECK(got == 0x1122334455667788ull);

    g.x[0] = 0xaabbccddeeff0011ull;
    run(g, 0xb9000420);  // str w0, [x1, #4]
    std::memcpy(&w, mem + 4, 4);
    CHECK(w == 0xeeff0011u);
    run(g, 0xb9400420);
    CHECK(g.x[0] == 0xeeff0011u);

    g.x[0] = 0x99;
    run(g, 0x39000c20);  // strb w0, [x1, #3]
    CHECK(mem[3] == 0x99);

    g.x[1] = b + 16;
    g.x[0] = 0x1234567890abcdefull;
    run(g, 0xf81fc020);  // stur x0, [x1, #-4]
    std::memcpy(&got, mem + 12, 8);
    CHECK(got == 0x1234567890abcdefull);

    g.x[1] = b;
    g.x[2] = 3;
    std::memcpy(&got, mem + 24, 8);
    run(g, 0xf8627820);  // ldr x0, [x1, x2, lsl #3]
    CHECK(g.x[0] == got);

    // Pre-index store and post-index load.
    g.x[1] = b + 32;
    g.x[0] = 0x55aa55aa55aa55aaull;
    run(g, 0xf8010c20);  // str x0, [x1, #16]!
    CHECK(g.x[1] == b + 48);
    std::memcpy(&got, mem + 48, 8);
    CHECK(got == 0x55aa55aa55aa55aaull);
    g.x[0] = 0;
    run(g, 0xf8408420);  // ldr x0, [x1], #8
    CHECK(g.x[0] == 0x55aa55aa55aa55aaull);
    CHECK(g.x[1] == b + 56);

    g.x[2] = b + 64;
    uint64_t pair0 = 0x1111, pair1 = 0x2222;
    std::memcpy(mem + 80, &pair0, 8);
    std::memcpy(mem + 88, &pair1, 8);
    g.x[2] = b + 64;
    run(g, 0xa9410440);  // ldp x0, x1, [x2, #16]
    CHECK(g.x[0] == 0x1111);
    CHECK(g.x[1] == 0x2222);

    g.sp = b + 128;
    g.x[0] = 0xaaaa;
    g.x[1] = 0xbbbb;
    run(g, 0xa9bf07e0);  // stp x0, x1, [sp, #-16]!
    CHECK(g.sp == b + 112);
    std::memcpy(&got, mem + 112, 8);
    CHECK(got == 0xaaaa);
    std::memcpy(&got, mem + 120, 8);
    CHECK(got == 0xbbbb);

    // TBI: a tag in the top byte still addresses the same byte.
    g.x[1] = b | (0x80ull << 56);
    *reinterpret_cast<uint64_t*>(mem) = 0x1234;
    run(g, 0xf9400020);  // ldr x0, [x1]
    CHECK(g.x[0] == 0x1234);

    // Prologue stores.
    uint8_t* stack = map_page();
    uint64_t top = reinterpret_cast<uint64_t>(stack) + 4096;
    g = {};
    g.sp = top;
    g.x[20] = 0x20;
    g.x[19] = 0x19;
    g.x[30] = 0x30;
    run(g, 0xa9be4ff4);
    run(g, 0xa9017bfd);
    run(g, 0x910043fd);
    run(g, 0xd10e83ff);
    CHECK(g.sp == top - 0x20 - 0x3a0);
    CHECK(g.x[29] == top - 0x20 + 0x10);
    uint64_t stored = 0;
    std::memcpy(&stored, reinterpret_cast<void*>(top - 32), 8);
    CHECK(stored == 0x20);
    std::memcpy(&stored, reinterpret_cast<void*>(top - 24), 8);
    CHECK(stored == 0x19);
    std::memcpy(&stored, reinterpret_cast<void*>(top - 16), 8);
    CHECK(stored == 0);
    std::memcpy(&stored, reinterpret_cast<void*>(top - 8), 8);
    CHECK(stored == 0x30);

    // Atomics.
    auto* slot = reinterpret_cast<uint64_t*>(mem + 256);
    *slot = 10;
    g = {};
    g.x[2] = reinterpret_cast<uint64_t>(slot);
    g.x[0] = 3;
    run(g, 0xf8e00043);  // ldaddal x0, x3, [x2]
    CHECK(*slot == 13);
    CHECK(g.x[3] == 10);

    *slot = 5;
    g.x[0] = 9;
    run(g, 0xf8208041);  // swp x0, x1, [x2]
    CHECK(*slot == 9);
    CHECK(g.x[1] == 5);

    *slot = 4;
    g.x[0] = 4;
    g.x[1] = 7;
    run(g, 0xc8a07c41);  // cas x0, x1, [x2]
    CHECK(*slot == 7);
    CHECK(g.x[0] == 4);
    g.x[0] = 1;
    g.x[1] = 8;
    run(g, 0xc8a07c41);
    CHECK(*slot == 7);
    CHECK(g.x[0] == 7);

    *slot = 0x99;
    g.x[1] = reinterpret_cast<uint64_t>(slot);
    run(g, 0xc85f7c20);  // ldxr x0, [x1]
    CHECK(g.x[0] == 0x99);
    g.x[2] = 0x77;
    run(g, 0xc8007c22);  // stxr w0, x2, [x1]
    CHECK(g.x[0] == 0);
    CHECK(*slot == 0x77);
    g.x[2] = 0x11;
    run(g, 0xc8007c22);
    CHECK(g.x[0] == 1);
    CHECK(*slot == 0x77);

    munmap(mem, 65536);
    munmap(stack, 65536);
}

static void test_simd_fp() {
    Guest g;
    run(g, 0x6f00e400);  // movi v0.2d, #0
    CHECK(g.v[0][0] == 0 && g.v[0][8] == 0);
    run(g, 0x6f00e420);  // movi v0.2d, #0xff
    uint64_t lane = 0;
    std::memcpy(&lane, g.v[0], 8);
    CHECK(lane == 0xff);
    run(g, 0x6f07e7e1);  // movi v1.2d, #all-ones
    CHECK(g.v[1][0] == 0xff && g.v[1][15] == 0xff);
    run(g, 0x4f03e7e0);  // movi v0.16b, #0x7f
    CHECK(g.v[0][0] == 0x7f && g.v[0][15] == 0x7f);
    g.x[8] = 0x1122334455667788ull;
    run(g, 0x4e080d01);  // dup v1.2d, x8
    uint64_t d0 = 0, d1 = 0;
    std::memcpy(&d0, g.v[1], 8);
    std::memcpy(&d1, g.v[1] + 8, 8);
    CHECK(d0 == 0x1122334455667788ull);
    CHECK(d1 == 0x1122334455667788ull);

    run(g, 0x4f000420);  // movi v0.4s, #1
    uint32_t s = 0;
    std::memcpy(&s, g.v[0], 4);
    CHECK(s == 1);
    std::memcpy(&s, g.v[0] + 12, 4);
    CHECK(s == 1);

    for (int i = 0; i < 16; i++) g.v[0][i] = static_cast<uint8_t>(i);
    for (int i = 0; i < 16; i++) g.v[1][i] = static_cast<uint8_t>(16 + i);
    run(g, 0x6e010800);  // ext v0.16b, v0.16b, v1.16b, #1
    CHECK(g.v[0][0] == 1);
    CHECK(g.v[0][14] == 15);
    CHECK(g.v[0][15] == 16);

    uint32_t src[4] = {1, 2, 3, 4};
    std::memcpy(g.v[1], src, 16);
    run(g, 0x4f235420);  // shl v0.4s, v1.4s, #3
    uint32_t out[4];
    std::memcpy(out, g.v[0], 16);
    CHECK(out[0] == 8 && out[1] == 16 && out[2] == 24 && out[3] == 32);
    run(g, 0x6f3d0420);  // ushr v0.4s, v1.4s, #3  -- v1 still holds 1,2,3,4? 
    // ushr reads v1, which was not overwritten. shl wrote v0.
    std::memcpy(out, g.v[0], 16);
    CHECK(out[0] == 0 && out[3] == 0);  // 1>>3 == 0
    uint32_t big[4] = {8, 16, 24, 32};
    std::memcpy(g.v[1], big, 16);
    run(g, 0x6f3d0420);
    std::memcpy(out, g.v[0], 16);
    CHECK(out[0] == 1 && out[1] == 2 && out[2] == 3 && out[3] == 4);

    std::memset(g.v[0], 0, 16);
    std::memset(g.v[1], 0, 16);
    run(g, 0x4e284820);  // aese v0.16b, v1.16b
    CHECK(g.v[0][0] == 0x63 && g.v[0][15] == 0x63);

    uint8_t col[16] = {0xdb, 0x13, 0x53, 0x45};
    std::memcpy(g.v[1], col, 16);
    run(g, 0x4e286820);  // aesmc v0.16b, v1.16b
    CHECK(g.v[0][0] == 0x8e);
    CHECK(g.v[0][1] == 0x4d);
    CHECK(g.v[0][2] == 0xa1);
    CHECK(g.v[0][3] == 0xbc);

    std::memset(g.v[1], 0, 16);
    std::memset(g.v[2], 0, 16);
    uint64_t three = 3;
    std::memcpy(g.v[1], &three, 8);
    std::memcpy(g.v[2], &three, 8);
    run(g, 0x0ee2e020);  // pmull v0.1q, v1.1d, v2.1d
    uint64_t lo = 0;
    std::memcpy(&lo, g.v[0], 8);
    CHECK(lo == 5);

    uint8_t a[16], bb[16];
    for (int i = 0; i < 16; i++) {
        a[i] = static_cast<uint8_t>(i);
        bb[i] = static_cast<uint8_t>(0xf0);
    }
    std::memcpy(g.v[0], a, 16);
    std::memcpy(g.v[1], bb, 16);
    run(g, 0x4e218400);  // add v0.16b, v0.16b, v1.16b
    CHECK(g.v[0][0] == 0xf0);
    CHECK(g.v[0][1] == 0xf1);

    uint32_t vs[4] = {1, 2, 3, 4};
    uint32_t vt[4] = {10, 20, 30, 40};
    std::memcpy(g.v[0], vs, 16);
    std::memcpy(g.v[1], vt, 16);
    run(g, 0x4ea18400);  // add v0.4s, v0.4s, v1.4s
    std::memcpy(out, g.v[0], 16);
    CHECK(out[0] == 11 && out[3] == 44);

    run(g, 0x6ea18c00);  // cmeq v0.4s, v0.4s, v1.4s -- v0 is 11.. and v1 is 10..
    std::memcpy(out, g.v[0], 16);
    CHECK(out[0] == 0);

    std::memcpy(g.v[1], vs, 16);
    std::memcpy(g.v[2], vs, 16);
    run(g, 0x4e221c20);  // and v0.16b, v1.16b, v2.16b
    CHECK(std::memcmp(g.v[0], vs, 16) == 0);

    set_f32(g, 1, 1.5f);
    set_f32(g, 2, 2.25f);
    run(g, 0x4e22d420);  // fadd v0.4s, v1.4s, v2.4s
    CHECK(get_f32(g, 0) == 3.75f);
    set_f32(g, 0, 1.0f);
    set_f32(g, 1, 4.0f);
    run(g, 0x0e21c400);  // fmaxnm v0.2s, v0.2s, v1.2s
    CHECK(get_f32(g, 0) == 4.0f);

    int32_t halves[2] = {-2, 5};
    std::memcpy(g.v[0], halves, 8);
    run(g, 0x0f20a400);  // sxtl v0.2d, v0.2s
    int64_t widened[2] = {};
    std::memcpy(widened, g.v[0], 16);
    CHECK(widened[0] == -2 && widened[1] == 5);

    int64_t neg = -3;
    std::memcpy(g.v[0], &neg, 8);
    run(g, 0x5e61d800);  // scvtf d0, d0
    CHECK(get_f64(g, 0) == -3.0);
    set_f64(g, 2, 6.5);
    run(g, 0x1e604042);  // fmov d2, d2
    CHECK(get_f64(g, 2) == 6.5);

    uint8_t table[16], idx[16] = {1, 0, 15, 16, 3, 2, 5, 4};
    for (int i = 0; i < 16; ++i) table[i] = static_cast<uint8_t>(i);
    std::memcpy(g.v[2], table, 16);
    std::memcpy(g.v[0], idx, 16);
    run(g, 0x0e000042);  // tbl v2.8b, {v2.16b}, v0.8b
    uint8_t looked[16] = {};
    std::memcpy(looked, g.v[2], 16);
    CHECK(looked[0] == 1 && looked[1] == 0 && looked[2] == 15 && looked[3] == 0);
    CHECK(looked[4] == 3 && looked[7] == 4 && looked[8] == 0);

    alignas(16) uint8_t lane_mem[16] = {};
    uint32_t lane_word = 0x11223344u;
    std::memcpy(g.v[2], &lane_word, 4);
    g.x[9] = reinterpret_cast<uint64_t>(lane_mem);
    run(g, 0x0d9f8122);  // st1 {v2.s}[0], [x9], #4
    uint32_t stored = 0;
    std::memcpy(&stored, lane_mem, 4);
    CHECK(stored == 0x11223344u);
    CHECK(g.x[9] == reinterpret_cast<uint64_t>(lane_mem) + 4);
    uint32_t repeated = 0xaabbccddu;
    std::memcpy(lane_mem, &repeated, 4);
    g.x[8] = reinterpret_cast<uint64_t>(lane_mem);
    run(g, 0x0d40c902);  // ld1r {v2.2s}, [x8]
    uint32_t lanes[4] = {};
    std::memcpy(lanes, g.v[2], 16);
    CHECK(lanes[0] == repeated && lanes[1] == repeated && lanes[2] == 0);

    uint16_t one = 0x3c00;
    std::memset(g.v[1], 0, 16);
    std::memcpy(g.v[1], &one, 2);
    run(g, 0x2ef8f821);  // fneg v1.4h, v1.4h
    uint16_t neg_one = 0;
    std::memcpy(&neg_one, g.v[1], 2);
    CHECK(neg_one == 0xbc00);
    std::memcpy(g.v[1], &one, 2);
    std::memcpy(g.v[2], &one, 2);
    run(g, 0x0e421420);  // fadd v0.4h, v1.4h, v2.4h
    uint16_t two = 0;
    std::memcpy(&two, g.v[0], 2);
    CHECK(two == 0x4000);

    int32_t signs[2] = {-1, 2};
    std::memcpy(g.v[0], signs, 8);
    run(g, 0x2ea09801);  // cmle v1.2s, v0.2s, #0
    uint32_t cmp[2] = {};
    std::memcpy(cmp, g.v[1], 8);
    CHECK(cmp[0] == 0xffffffffu && cmp[1] == 0);

    uint32_t words[4] = {1u, 0xffffffffu, 3u, 4u};
    std::memcpy(g.v[1], words, 16);
    run(g, 0x0e0c3c28);  // mov w8, v1.s[1]
    CHECK(g.x[8] == 0xffffffffu);

    uint64_t kept = 0x3333, inserted = 0x1111;
    std::memcpy(g.v[0], &kept, 8);
    std::memcpy(g.v[1], &inserted, 8);
    run(g, 0x6e180420);  // mov v0.d[1], v1.d[0]
    uint64_t pair[2] = {};
    std::memcpy(pair, g.v[0], 16);
    CHECK(pair[0] == kept && pair[1] == inserted);
    uint64_t wide[2] = {0x1111, 0x2222};
    std::memcpy(g.v[0], wide, 16);
    run(g, 0x5e180408);  // mov d8, v0.d[1]
    uint64_t scalar[2] = {};
    std::memcpy(scalar, g.v[8], 16);
    CHECK(scalar[0] == 0x2222 && scalar[1] == 0);

    int32_t left[4] = {1, -1, 5, 0};
    int32_t right[4] = {0, -2, 5, 1};
    std::memcpy(g.v[0], left, 16);
    std::memcpy(g.v[1], right, 16);
    run(g, 0x4ea13402);  // cmgt v2.4s, v0.4s, v1.4s
    uint32_t gt[4] = {};
    std::memcpy(gt, g.v[2], 16);
    CHECK(gt[0] == 0xffffffffu && gt[1] == 0xffffffffu && gt[2] == 0 && gt[3] == 0);

    uint16_t smalls[4] = {5, 1, 9, 3};
    std::memcpy(g.v[2], smalls, 8);
    run(g, 0x2e71a841);  // uminv h1, v2.4h
    uint16_t vmin = 0;
    std::memcpy(&vmin, g.v[1], 2);
    CHECK(vmin == 1);

    uint32_t kept_lane = 0x11111111u;
    std::memcpy(g.v[0], &kept_lane, 4);
    g.x[2] = 0xabcdu;
    run(g, 0x4e0c1c40);  // mov v0.s[1], w2
    uint32_t inserted_lane[2] = {};
    std::memcpy(inserted_lane, g.v[0], 8);
    CHECK(inserted_lane[0] == kept_lane && inserted_lane[1] == 0xabcdu);

    int32_t smax_a[2] = {-5, 9};
    int32_t smax_b[2] = {-1, 3};
    std::memcpy(g.v[1], smax_a, 8);
    std::memcpy(g.v[2], smax_b, 8);
    run(g, 0x0ea26420);  // smax v0.2s, v1.2s, v2.2s
    int32_t smax_out[2] = {};
    std::memcpy(smax_out, g.v[0], 8);
    CHECK(smax_out[0] == -1 && smax_out[1] == 9);
    run(g, 0x0ea27420);  // sabd v0.2s, v1.2s, v2.2s
    uint32_t abd[2] = {};
    std::memcpy(abd, g.v[0], 8);
    CHECK(abd[0] == 4 && abd[1] == 6);
    uint32_t umin_a[2] = {1u, 8u};
    uint32_t umin_b[2] = {3u, 2u};
    std::memcpy(g.v[1], umin_a, 8);
    std::memcpy(g.v[2], umin_b, 8);
    run(g, 0x2ea26c20);  // umin v0.2s, v1.2s, v2.2s
    uint32_t umin_out[2] = {};
    std::memcpy(umin_out, g.v[0], 8);
    CHECK(umin_out[0] == 1 && umin_out[1] == 2);

    float mul_src[2] = {2.f, 3.f};
    float mul_elem = 4.f;
    std::memcpy(g.v[2], mul_src, 8);
    std::memcpy(g.v[0], &mul_elem, 4);
    run(g, 0x0f809042);  // fmul v2.2s, v2.2s, v0.s[0]
    float mul_out[2] = {};
    std::memcpy(mul_out, g.v[2], 8);
    CHECK(mul_out[0] == 8.f && mul_out[1] == 12.f);
    float conv_src[2] = {1.9f, -1.9f};
    std::memcpy(g.v[2], conv_src, 8);
    run(g, 0x0ea1b842);  // fcvtzs v2.2s, v2.2s
    int32_t conv_out[2] = {};
    std::memcpy(conv_out, g.v[2], 8);
    CHECK(conv_out[0] == 1 && conv_out[1] == -1);

    double dup_src[2] = {1.25, 9.5};
    std::memcpy(g.v[3], dup_src, 16);
    run(g, 0x4e080463);  // dup v3.2d, v3.d[0]
    double dup_out[2] = {};
    std::memcpy(dup_out, g.v[3], 16);
    CHECK(dup_out[0] == 1.25 && dup_out[1] == 1.25);

    uint8_t zip_a[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    uint8_t zip_b[8] = {9, 10, 11, 12, 13, 14, 15, 16};
    std::memcpy(g.v[0], zip_a, 8);
    std::memcpy(g.v[1], zip_b, 8);
    run(g, 0x0e013800);  // zip1 v0.8b, v0.8b, v1.8b
    uint8_t zipped[8] = {};
    std::memcpy(zipped, g.v[0], 8);
    CHECK(zipped[0] == 1 && zipped[1] == 9 && zipped[2] == 2 && zipped[7] == 12);
    uint16_t bic_src[4] = {0x12ff, 0x34ff, 0x00ff, 0xffff};
    std::memcpy(g.v[0], bic_src, 8);
    run(g, 0x2f07b7e0);  // bic v0.4h, #0xff, lsl #8
    uint16_t bic_out[4] = {};
    std::memcpy(bic_out, g.v[0], 8);
    CHECK(bic_out[0] == 0x00ff && bic_out[1] == 0x00ff && bic_out[3] == 0x00ff);

    set_f32(g, 0, 0);
    run(g, 0x1e2e1000);  // fmov s0, #1.0
    CHECK(get_f32(g, 0) == 1.0f);
    run(g, 0x1e649001);  // fmov d1, #10.0
    CHECK(get_f64(g, 1) == 10.0);
    run(g, 0x1e7c1000);  // fmov d0, #-0.5
    CHECK(get_f64(g, 0) == -0.5);
    set_f32(g, 0, 1.2f);
    run(g, 0x9e290009);  // fcvtpu x9, s0
    CHECK(g.x[9] == 2);
    set_f32(g, 0, -1.2f);
    run(g, 0x9e290000);  // fcvtpu x0, s0
    CHECK(g.x[0] == 0);

    set_f32(g, 1, 1.0f);
    set_f32(g, 2, 2.0f);
    run(g, 0x1e222820);  // fadd s0, s1, s2
    CHECK(get_f32(g, 0) == 3.0f);
    run(g, 0x1e220820);  // fmul
    CHECK(get_f32(g, 0) == 2.0f);
    set_f32(g, 1, 8.0f);
    set_f32(g, 2, 2.0f);
    run(g, 0x1e221820);  // fdiv
    CHECK(get_f32(g, 0) == 4.0f);

    set_f32(g, 0, 1.0f);
    set_f32(g, 1, 2.0f);
    run(g, 0x1e212000);  // fcmp s0, s1
    CHECK(g.nzcv == 0x80000000u);
    set_f64(g, 0, 0.0);
    run(g, 0x1e602008);  // fcmp d0, #0
    CHECK(g.nzcv == 0x60000000u);

    g.x[1] = 0x3ff0000000000000ull;
    run(g, 0x9e670020);  // fmov d0, x1
    CHECK(get_f64(g, 0) == 1.0);
    run(g, 0x9e660020);  // fmov x0, d1 -- d1 is unset, set it first
    set_f64(g, 1, 2.0);
    run(g, 0x9e660020);
    CHECK(g.x[0] == 0x4000000000000000ull);

    set_f64(g, 1, -2.5);
    run(g, 0x1e60c020);  // fabs d0, d1
    CHECK(get_f64(g, 0) == 2.5);
    set_f32(g, 1, 3.0f);
    run(g, 0x1e214020);  // fneg s0, s1
    CHECK(get_f32(g, 0) == -3.0f);
    set_f64(g, 1, 9.0);
    run(g, 0x1e61c020);  // fsqrt
    CHECK(get_f64(g, 0) == 3.0);

    set_f32(g, 1, 1.25f);
    run(g, 0x1e22c020);  // fcvt d0, s1
    CHECK(get_f64(g, 0) == static_cast<double>(1.25f));
    double one_half = 1.5;
    std::memcpy(g.v[0], &one_half, 8);
    run(g, 0x1e624008);  // fcvt s8, d0
    float narrowed = 0;
    std::memcpy(&narrowed, g.v[8], 4);
    CHECK(narrowed == 1.5f);

    set_f32(g, 0, 1.5f);
    run(g, 0x1e264000);  // frinta s0, s0
    CHECK(get_f32(g, 0) == 2.0f);
    set_f32(g, 0, -1.5f);
    run(g, 0x1e264000);
    CHECK(get_f32(g, 0) == -2.0f);
    set_f32(g, 0, 2.5f);
    run(g, 0x1e244000);  // frintn s0, s0
    CHECK(get_f32(g, 0) == 2.0f);

    g.x[1] = static_cast<uint64_t>(static_cast<int32_t>(-3));
    run(g, 0x1e220020);  // scvtf s0, w1
    CHECK(get_f32(g, 0) == -3.0f);

    set_f64(g, 1, 3.9);
    run(g, 0x9e780020);  // fcvtzs x0, d1
    CHECK(g.x[0] == 3);
    set_f64(g, 1, -1.2);
    run(g, 0x9e780020);
    CHECK(static_cast<int64_t>(g.x[0]) == -1);

    set_f32(g, 1, 2.0f);
    set_f32(g, 2, 3.0f);
    set_f32(g, 3, 4.0f);
    run(g, 0x1f020c20);  // fmadd s0, s1, s2, s3
    CHECK(get_f32(g, 0) == 10.0f);

    g.nzcv = 0x40000000u;
    set_f32(g, 1, 1.0f);
    set_f32(g, 2, 2.0f);
    run(g, 0x1e220c20);  // fcsel eq
    CHECK(get_f32(g, 0) == 1.0f);
    g.nzcv = 0;
    run(g, 0x1e220c20);
    CHECK(get_f32(g, 0) == 2.0f);

    uint8_t* mem = map_page();
    float vals[4] = {1.f, 2.f, 3.f, 4.f};
    std::memcpy(mem, vals, sizeof(vals));
    g.x[1] = reinterpret_cast<uint64_t>(mem);
    run(g, 0x4c407820);  // ld1 {v0.4s}, [x1]
    CHECK(get_f32(g, 0) == 1.f);
    float last = 0;
    std::memcpy(&last, g.v[0] + 12, 4);
    CHECK(last == 4.f);

    g.v[0][0] = 0xab;
    run(g, 0x4c9f7c20);  // st1 {v0.2d}, [x1], #16
    CHECK(mem[0] == 0xab);
    CHECK(g.x[1] == reinterpret_cast<uint64_t>(mem) + 16);

    mem[0] = 0x5a;
    g.x[1] = reinterpret_cast<uint64_t>(mem);
    run(g, 0x0ddfc020);  // ld1r {v0.8b}, [x1], #1
    CHECK(g.v[0][0] == 0x5a && g.v[0][7] == 0x5a);
    CHECK(g.x[1] == reinterpret_cast<uint64_t>(mem) + 1);

    munmap(mem, 65536);
    (void)bytes_eq;
}

static bool same_cpu(const Guest& a, const Guest& b) {
    if (a.sp != b.sp || a.pc != b.pc || a.nzcv != b.nzcv) return false;
    if (std::memcmp(a.x, b.x, sizeof(a.x)) != 0) return false;
    if (std::memcmp(a.v, b.v, sizeof(a.v)) != 0) return false;
    return a.stop == b.stop;
}

static void test_dbt() {
    uint8_t* mem = map_page();
    uint64_t base = reinterpret_cast<uint64_t>(mem);
    uint32_t add = 0x91001420;  // add x0, x1, #5
    uint32_t brk = 0xd4200020;
    std::memcpy(mem, &add, 4);
    std::memcpy(mem + 4, &brk, 4);

    dbt_reset();
    const TranslatedBlock* block = dbt_translate(base);
    CHECK(block != nullptr);
    CHECK(block->native_alu >= 1);
    bool saw_add = false;
    for (size_t i = 0; i + 1 < block->code_size; i++) {
        if (block->code[i] == 0x48 && block->code[i + 1] == 0x05) saw_add = true;
    }
    CHECK(saw_add);

    Guest interp;
    interp.x[1] = 10;
    interp.pc = base;
    step(interp);
    Guest native;
    native.x[1] = 10;
    native.pc = base;
    dbt_run(native, 1);
    CHECK(native.x[0] == 15);
    CHECK(interp.x[0] == native.x[0]);

    // A short program with a taken and a not-taken branch, run both ways.
    uint32_t prog[] = {
        0xf100041f,  // cmp x0, #1
        0x54000061,  // b.ne +12
        0xd28000e1,  // mov x1, #7
        0x14000002,  // b +8
        0xd2800121,  // mov x1, #9
        0xd4200020,  // brk
    };
    std::memcpy(mem, prog, sizeof(prog));
    for (uint64_t x0 : {uint64_t{1}, uint64_t{0}}) {
        Guest a;
        a.pc = base;
        a.x[0] = x0;
        while (!a.stop && a.steps < 8) step(a);
        dbt_reset();
        Guest b;
        b.pc = base;
        b.x[0] = x0;
        dbt_run(b, 8);
        CHECK(same_cpu(a, b));
        CHECK(b.stop != 0);
        if (x0 == 1) CHECK(b.x[1] == 7);
        if (x0 == 0) CHECK(b.x[1] == 9);
    }

    // Prologue through the translator, matched against the interpreter.
    uint32_t prologue[] = {0xa9be4ff4, 0xa9017bfd, 0x910043fd, 0xd10e83ff, 0xd4200020};
    std::memcpy(mem, prologue, sizeof(prologue));
    uint8_t* stack = map_page();
    uint64_t top = reinterpret_cast<uint64_t>(stack) + 4096;
    Guest a;
    a.pc = base;
    a.sp = top;
    a.x[20] = 0x20;
    a.x[19] = 0x19;
    a.x[30] = 0x30;
    while (!a.stop && a.steps < 8) step(a);
    dbt_reset();
    Guest b;
    b.pc = base;
    b.sp = top;
    b.x[20] = 0x20;
    b.x[19] = 0x19;
    b.x[30] = 0x30;
    dbt_run(b, 8);
    CHECK(same_cpu(a, b));
    CHECK(b.sp == top - 0x20 - 0x3a0);
    CHECK(b.x[29] == top - 0x20 + 0x10);

    munmap(mem, 65536);
    munmap(stack, 65536);
}

int main() {
    test_integer();
    test_branch();
    test_memory();
    test_simd_fp();
    test_dbt();
    if (g_fails) {
        std::fprintf(stderr, "%d checks failed\n", g_fails);
        return 1;
    }
    std::printf("arm64 interpreter and translator checks passed\n");
    return 0;
}

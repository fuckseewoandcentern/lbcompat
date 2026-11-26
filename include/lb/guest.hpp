#pragma once

#include <cstdint>
#include <cstring>

namespace lb {

// Guest CPU state for the arm64 process. Pointers are host pointers
// (the image and heap are mapped into this address space). Loads and
// stores ignore the top address byte, matching Apple's TBI.
struct Guest {
    uint64_t x[31]{};
    uint64_t sp = 0;
    uint64_t pc = 0;
    // NZCV live in bits 31..28, same positions as SPSR/NZCV.
    uint32_t nzcv = 0;
    uint32_t fpcr = 0;
    uint32_t fpsr = 0;
    alignas(16) uint8_t v[32][16]{};
    int stop = 0;
    uint32_t stop_insn = 0;
    uint64_t stop_pc = 0;
    const char* stop_why = nullptr;
    uint64_t steps = 0;
    // Set by a host shim that tail-calls back into guest code.
    bool redirect = false;
};

enum ExecResult { EX_NEXT = 0, EX_BRANCH = 1, EX_STOP = 2 };

inline uint64_t tbi(uint64_t addr) { return addr & 0x00ffffffffffffffull; }

extern uint64_t g_debug_load_addr;
extern uint64_t g_exec_ring[32];
extern uint32_t g_exec_ring_i;

inline uint64_t mem_load(uint64_t addr, int bytes) {
    uint64_t v = 0;
    g_debug_load_addr = tbi(addr);
    std::memcpy(&v, reinterpret_cast<const void*>(tbi(addr)), static_cast<size_t>(bytes));
    return v;
}

inline void mem_store(uint64_t addr, uint64_t val, int bytes) {
    std::memcpy(reinterpret_cast<void*>(tbi(addr)), &val, static_cast<size_t>(bytes));
}

inline void mem_load16(uint64_t addr, uint8_t out[16]) {
    std::memcpy(out, reinterpret_cast<const void*>(tbi(addr)), 16);
}

inline void mem_store16(uint64_t addr, const uint8_t in[16]) {
    std::memcpy(reinterpret_cast<void*>(tbi(addr)), in, 16);
}

// Execute the instruction at g.pc. Branches write g.pc and return EX_BRANCH.
// Other instructions leave g.pc unchanged and return EX_NEXT.
ExecResult exec_insn(Guest& g, uint32_t insn);

// Fetch-execute one instruction. Used by tests and the safe dispatcher.
ExecResult step(Guest& g);

struct TranslatedBlock {
    uint64_t pc = 0;
    int count = 0;
    int native_alu = 0;
    void (*fn)(Guest*) = nullptr;
    const uint8_t* code = nullptr;
    size_t code_size = 0;
};

// Translate and run until g.stop or max_insns guest instructions have retired.
// Returns the number of guest instructions executed.
uint64_t dbt_run(Guest& g, uint64_t max_insns);

// Translate the block at pc (also entered into the cache) and return it.
const TranslatedBlock* dbt_translate(uint64_t pc);

void dbt_reset();

}  // namespace lb

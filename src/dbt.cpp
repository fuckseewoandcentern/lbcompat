#include "lb/guest.hpp"
#include "x86.hpp"

#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <list>
#include <mutex>
#include <unordered_map>
#include <vector>

#include <sys/mman.h>
#include <unistd.h>

namespace lb {

uint64_t g_exec_ring[32];
uint32_t g_exec_ring_i = 0;

namespace {

extern "C" int lb_dbt_exec(Guest* g, uint32_t insn) {
    g_exec_ring[g_exec_ring_i++ & 31] = g->pc;
    ExecResult r = exec_insn(*g, insn);
    g->steps++;
    if (r == EX_NEXT) g->pc += 4;
    return static_cast<int>(r);
}

int32_t gpr_off(int r) {
    if (r == 31) return static_cast<int32_t>(offsetof(Guest, sp));
    return static_cast<int32_t>(offsetof(Guest, x) + static_cast<size_t>(r) * 8);
}

uint32_t field(uint32_t insn, int hi, int lo) {
    return (insn >> lo) & ((1u << (hi - lo + 1)) - 1u);
}

bool is_branch(uint32_t insn) {
    if ((insn & 0xFC000000u) == 0x14000000u || (insn & 0xFC000000u) == 0x94000000u) return true;
    if ((insn & 0xFF000010u) == 0x54000000u) return true;
    if ((insn & 0x7E000000u) == 0x34000000u) return true;
    if ((insn & 0x7E000000u) == 0x36000000u) return true;
    if ((insn & 0xFFFFFC1Fu) == 0xD61F0000u) return true;
    if ((insn & 0xFFFFFC1Fu) == 0xD63F0000u) return true;
    if ((insn & 0xFFFFFC1Fu) == 0xD65F0000u) return true;
    return false;
}

bool is_brk(uint32_t insn) { return (insn & 0xFFE0001Fu) == 0xD4200000u; }

// Inline a few flag-free integer ops straight to x86. Everything else,
// including every branch, is call-threaded through the interpreter so the
// two paths stay in lockstep.
bool try_inline(X86& x, uint32_t insn, uint64_t pc) {
    if ((insn & 0x1F000000u) == 0x11000000u && ((insn >> 29) & 1u) == 0) {
        unsigned shift = field(insn, 23, 22);
        if (shift > 1) return false;
        uint32_t imm = field(insn, 21, 10);
        if (shift == 1) imm <<= 12;
        bool sf = (insn >> 31) & 1u;
        bool sub = (insn >> 30) & 1u;
        int rn = field(insn, 9, 5);
        int rd = insn & 31;
        if (sf) x.mov_rax_disp(gpr_off(rn));
        else x.mov_eax_disp(gpr_off(rn));
        if (imm != 0) {
            if (sub) {
                if (sf) x.sub_rax_imm32(static_cast<int32_t>(imm));
                else x.sub_eax_imm32(static_cast<int32_t>(imm));
            } else {
                if (sf) x.add_rax_imm32(static_cast<int32_t>(imm));
                else x.add_eax_imm32(static_cast<int32_t>(imm));
            }
        }
        x.mov_disp_rax(gpr_off(rd));
        return true;
    }

    // MOV is ORR with the stack pointer / zero register as the left source
    // and no shift. Register 31 is ZR here, not SP.
    if ((insn & 0x7F200000u) == 0x2A000000u && field(insn, 15, 10) == 0 && field(insn, 9, 5) == 31 &&
        ((insn >> 21) & 1u) == 0) {
        int rd = insn & 31;
        int rm = field(insn, 20, 16);
        if (rd == 31) return true;
        bool sf = (insn >> 31) & 1u;
        // Rm == 31 is the zero register, not the stack pointer.
        if (rm == 31) x.xor_eax_eax();
        else if (sf) x.mov_rax_disp(rm * 8);
        else x.mov_eax_disp(rm * 8);
        x.mov_disp_rax(rd * 8);
        return true;
    }

    // ADR / ADRP. The instruction's own address is known while translating.
    if ((insn & 0x1F000000u) == 0x10000000u) {
        bool page = (insn >> 31) & 1u;
        uint32_t immlo = field(insn, 30, 29);
        uint32_t immhi = field(insn, 23, 5);
        int32_t simm = static_cast<int32_t>((immhi << 2) | immlo);
        simm = (simm << 11) >> 11;
        int64_t imm = simm;
        uint64_t base = page ? (pc & ~0xfffull) : pc;
        if (page) imm <<= 12;
        int rd = insn & 31;
        uint64_t result = base + static_cast<uint64_t>(imm);
        if (rd != 31) {
            x.mov_rax_imm64(result);
            x.mov_disp_rax(rd * 8);
        }
        return true;
    }

    // Unsigned 32/64 load and store. The top address byte is ignored (TBI).
    if ((insn & 0x3B000000u) == 0x39000000u && ((insn >> 26) & 1u) == 0) {
        unsigned size = field(insn, 31, 30);
        unsigned opc = field(insn, 23, 22);
        if (size < 2 || opc > 1) return false;
        int bytes = 1 << size;
        uint32_t imm = field(insn, 21, 10) * static_cast<uint32_t>(bytes);
        int rn = field(insn, 9, 5);
        int rt = insn & 31;
        x.mov_rax_disp(gpr_off(rn));
        if (imm != 0) x.add_rax_imm32(static_cast<int32_t>(imm));
        x.mov_rcx_imm64(0x00ffffffffffffffull);
        x.and_rax_rcx();
        if (opc == 1) {
            if (size == 3) x.mov_rax_mem();
            else x.mov_eax_mem();
            if (rt != 31) x.mov_disp_rax(gpr_off(rt));
        } else {
            if (rt == 31) x.xor_ecx_ecx();
            else x.mov_rcx_disp(gpr_off(rt));
            if (size == 3) x.mov_mem_rcx();
            else x.mov_mem_ecx();
        }
        return true;
    }
    return false;
}

struct Cache {
    std::mutex mu;
    std::list<TranslatedBlock> blocks;
    std::unordered_map<uint64_t, TranslatedBlock*> index;
    std::vector<void*> pages;
};

std::atomic<int> g_dbt_shutdown{0};

bool dbt_stopping() { return g_dbt_shutdown.load(std::memory_order_acquire) != 0; }

Cache& cache() {
    // The cache lives for the whole process. A function-local Cache is
    // destroyed during exit while a guest thread can still be inside
    // dbt_translate, and that free aborts with a corrupted heap list.
    static Cache* c = new Cache;
    return *c;
}

TranslatedBlock compile_block(uint64_t pc) {
    X86 x;
    x.push_r12();
    x.mov_r12_rdi();
    const int32_t pc_off = static_cast<int32_t>(offsetof(Guest, pc));
    const int32_t steps_off = static_cast<int32_t>(offsetof(Guest, steps));
    std::vector<size_t> exits;
    int count = 0;
    int native = 0;
    int pending = 0;
    auto flush_steps = [&]() {
        if (pending == 0) return;
        x.add_qword_disp_imm32(steps_off, static_cast<uint32_t>(pending));
        pending = 0;
    };
    bool closed = false;
    for (int n = 0; n < 32; n++) {
        uint32_t insn = 0;
        std::memcpy(&insn, reinterpret_cast<const void*>(pc + static_cast<uint64_t>(n) * 4), 4);
        uint64_t ipc = pc + static_cast<uint64_t>(n) * 4;
        X86 native_op;
        if (try_inline(native_op, insn, ipc)) {
            // Record the guest pc before the op so a fault names this instruction.
            x.mov_rax_imm64(ipc);
            x.mov_disp_rax(pc_off);
            x.b.insert(x.b.end(), native_op.b.begin(), native_op.b.end());
            native++;
            pending++;
            count++;
            continue;
        }
        flush_steps();
        x.mov_rax_imm64(ipc);
        x.mov_disp_rax(pc_off);
        x.mov_esi_imm(insn);
        x.mov_rdi_r12();
        x.mov_rax_imm64(reinterpret_cast<uint64_t>(&lb_dbt_exec));
        x.call_rax();
        x.cmp_eax_0();
        x.jne_rel32_placeholder();
        exits.push_back(x.b.size() - 4);
        count++;
        if (is_branch(insn) || is_brk(insn)) {
            closed = true;
            break;
        }
    }
    if (!closed) {
        flush_steps();
        x.mov_rax_imm64(pc + static_cast<uint64_t>(count) * 4);
        x.mov_disp_rax(pc_off);
    } else {
        flush_steps();
    }
    size_t epi = x.b.size();
    x.pop_r12();
    x.ret();
    for (size_t at : exits) {
        int32_t rel = static_cast<int32_t>(epi) - static_cast<int32_t>(at + 4);
        x.patch_rel32(at, rel);
    }

    size_t bytes = x.b.size();
    void* mem = mmap(nullptr, 4096, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mem == MAP_FAILED) mem = nullptr;
    if (mem) std::memcpy(mem, x.b.data(), bytes);
    TranslatedBlock block;
    block.pc = pc;
    block.count = count;
    block.native_alu = native;
    block.fn = mem ? reinterpret_cast<void (*)(Guest*)>(mem) : nullptr;
    block.code = static_cast<const uint8_t*>(mem);
    block.code_size = bytes;
    if (mem) cache().pages.push_back(mem);
    return block;
}

}  // namespace

void dbt_request_shutdown() { g_dbt_shutdown.store(1, std::memory_order_release); }

const TranslatedBlock* dbt_translate(uint64_t pc) {
    if (dbt_stopping()) return nullptr;
    Cache& c = cache();
    std::lock_guard<std::mutex> lock(c.mu);
    if (dbt_stopping()) return nullptr;
    auto it = c.index.find(pc);
    if (it != c.index.end()) return it->second;
    c.blocks.push_back(compile_block(pc));
    TranslatedBlock* stored = &c.blocks.back();
    c.index.emplace(pc, stored);
    return stored;
}

// Defined weakly in shim_stub.cpp and strongly by the runtime. The body is
// not visible here, so a strong override is actually called.
extern "C" bool lb_try_shim(Guest* g) __attribute__((weak));

uint64_t dbt_run(Guest& g, uint64_t max_insns) {
    uint64_t start = g.steps;
    while (!g.stop && !dbt_stopping() && g.steps - start < max_insns) {
        if (lb_try_shim && lb_try_shim(&g)) continue;
        const TranslatedBlock* b = dbt_translate(g.pc);
        if (!b || !b->fn || b->count <= 0) {
            g.stop = 1;
            g.stop_why = "translate failed";
            g.stop_pc = g.pc;
            break;
        }
        uint64_t left = max_insns - (g.steps - start);
        if (static_cast<uint64_t>(b->count) > left) {
            while (!g.stop && g.steps - start < max_insns) {
                if (lb_try_shim && lb_try_shim(&g)) continue;
                step(g);
            }
            break;
        }
        uint64_t before = g.steps;
        b->fn(&g);
        if (g.steps == before) {
            g.stop = 1;
            g.stop_pc = g.pc;
            g.stop_why = "dbt made no progress";
            break;
        }
    }
    return g.steps - start;
}

void dbt_reset() {
    Cache& c = cache();
    std::lock_guard<std::mutex> lock(c.mu);
    for (void* p : c.pages) munmap(p, 4096);
    c.pages.clear();
    c.index.clear();
    c.blocks.clear();
}

}  // namespace lb

#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <vector>

namespace lb {

// Small x86-64 encoder used by the arm64 dynamic translator.
// Guest* arrives in rdi. r12 holds it across helper calls.
struct X86 {
    std::vector<uint8_t> b;

    void emit(std::initializer_list<uint8_t> xs) { b.insert(b.end(), xs); }
    void u32(uint32_t v) {
        for (int i = 0; i < 4; i++) b.push_back(static_cast<uint8_t>(v >> (8 * i)));
    }
    void u64(uint64_t v) {
        for (int i = 0; i < 8; i++) b.push_back(static_cast<uint8_t>(v >> (8 * i)));
    }

    void push_r12() { emit({0x41, 0x54}); }
    void pop_r12() { emit({0x41, 0x5C}); }
    void mov_r12_rdi() { emit({0x49, 0x89, 0xFC}); }
    void mov_rdi_r12() { emit({0x4C, 0x89, 0xE7}); }
    void ret() { emit({0xC3}); }
    void xor_eax_eax() { emit({0x31, 0xC0}); }
    void mov_esi_imm(uint32_t v) {
        emit({0xBE});
        u32(v);
    }
    void mov_rax_imm64(uint64_t v) {
        emit({0x48, 0xB8});
        u64(v);
    }
    void mov_rcx_imm64(uint64_t v) {
        emit({0x48, 0xB9});
        u64(v);
    }
    void call_rax() { emit({0xFF, 0xD0}); }
    void cmp_eax_0() { emit({0x83, 0xF8, 0x00}); }
    void jne_rel32_placeholder() { emit({0x0F, 0x85, 0, 0, 0, 0}); }
    void patch_rel32(size_t at, int32_t rel) {
        std::memcpy(&b[at], &rel, 4);
    }

    // mov rax, [r12+disp32]
    void mov_rax_disp(int32_t disp) {
        emit({0x49, 0x8B, 0x84, 0x24});
        u32(static_cast<uint32_t>(disp));
    }
    void mov_eax_disp(int32_t disp) {
        emit({0x41, 0x8B, 0x84, 0x24});
        u32(static_cast<uint32_t>(disp));
    }
    void mov_disp_rax(int32_t disp) {
        emit({0x49, 0x89, 0x84, 0x24});
        u32(static_cast<uint32_t>(disp));
    }
    void add_rax_imm32(int32_t imm) {
        emit({0x48, 0x05});
        u32(static_cast<uint32_t>(imm));
    }
    void sub_rax_imm32(int32_t imm) {
        emit({0x48, 0x2D});
        u32(static_cast<uint32_t>(imm));
    }
    void add_eax_imm32(int32_t imm) {
        emit({0x05});
        u32(static_cast<uint32_t>(imm));
    }
    void sub_eax_imm32(int32_t imm) {
        emit({0x2D});
        u32(static_cast<uint32_t>(imm));
    }
    void and_rax_imm32(uint32_t imm) {
        emit({0x48, 0x25});
        u32(imm);
    }
    void mov_qword_disp_imm32(int32_t disp, uint32_t imm) {
        // mov qword ptr [r12+disp], imm32 (sign-extended)
        emit({0x49, 0xC7, 0x84, 0x24});
        u32(static_cast<uint32_t>(disp));
        u32(imm);
    }
    void mov_rax_mem() { emit({0x48, 0x8B, 0x00}); }
    void mov_eax_mem() { emit({0x8B, 0x00}); }
    void mov_mem_rcx() { emit({0x48, 0x89, 0x08}); }
    void mov_mem_ecx() { emit({0x89, 0x08}); }
    void mov_rcx_disp(int32_t disp) {
        emit({0x49, 0x8B, 0x8C, 0x24});
        u32(static_cast<uint32_t>(disp));
    }
    void xor_ecx_ecx() { emit({0x31, 0xC9}); }
    void and_rax_rcx() { emit({0x48, 0x21, 0xC8}); }
    void add_qword_disp_imm32(int32_t disp, uint32_t imm) {
        emit({0x49, 0x81, 0x84, 0x24});
        u32(static_cast<uint32_t>(disp));
        u32(imm);
    }
};

}  // namespace lb

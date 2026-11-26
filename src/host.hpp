#pragma once

#include "lb/guest.hpp"
#include "lb/image.hpp"

#include <cstdint>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace lb {

constexpr uint64_t kPreferredShimBase = 0x700000000000ull;
constexpr uint64_t kReturnPc = 0x6fffffff0000ull;

using ShimFn = void (*)(Guest&);

struct Payload {
    std::string str;
    std::vector<uint64_t> items;
    std::vector<std::pair<uint64_t, uint64_t>> pairs;
    std::unordered_map<std::string, uint64_t> props;
    double number = 0;
    bool flag = false;
    int kind = 0;
    std::vector<uint8_t> bytes;
};

extern MachImage* g_image;
extern std::string g_bundle;
extern std::string g_exe;
extern uint64_t g_nsapp;

void shim_arena_init();
void register_shim(const std::string& name, ShimFn fn);
uint64_t resolve_symbol(const std::string& name, int ordinal);
bool is_data_symbol(const std::string& name);
uint64_t data_symbol(const std::string& name, size_t bytes);
void data_store_u64(const std::string& name, uint64_t value);
const char* shim_name_at(uint64_t pc);
void note_unknown(const std::string& name);
std::vector<std::string> unknown_symbols();

void objc_init();
void objc_load_guest(const MachImage& image);
void objc_finish_data();
void objc_msg_send(Guest& g);
void objc_msg_send_super2(Guest& g);
uint64_t ensure_class(const std::string& name, const std::string& super, uint32_t size);
uint64_t class_ptr(const std::string& name);
void add_method(const std::string& cls, const char* sel, ShimFn fn, bool class_method);
uint64_t make_object(const std::string& cls);
uint64_t make_string(const std::string& text);
Payload& payload(uint64_t obj);
bool has_payload(uint64_t obj);
const char* sel(const char* name);
std::vector<std::string> missed_selectors();

uint64_t read_u64(uint64_t addr);
void write_u64(uint64_t addr, uint64_t value);
const char* guest_cstr(uint64_t addr);
bool tracing();

int guest_format(char* out, size_t cap, const char* fmt, Guest& g, int first_gpr, int first_vec);

// Run a guest function and return x0. A stop other than a normal return is
// copied onto parent when parent is non-null.
uint64_t call_guest(uint64_t pc, uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3, Guest* parent);

void metal_init();
bool metal_selftest(std::string& err);
void audio_init();
void host_present(const uint8_t* rgba, int w, int h);

struct SpawnPlan {
    bool bridge = false;
    std::vector<std::string> argv;
};
SpawnPlan plan_spawn(const std::string& path, const std::vector<std::string>& argv);
std::string bridge_executable();

}  // namespace lb

#include "lb/guest.hpp"

// Placeholder so the translator links without the runtime. The runtime
// provides a strong definition that actually dispatches host calls.
extern "C" bool lb_try_shim(lb::Guest*) __attribute__((weak));
extern "C" bool lb_try_shim(lb::Guest*) { return false; }

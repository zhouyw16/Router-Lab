#include "router_hal.h"

// configure this to match the output of `ip a`
const char *interfaces[N_IFACE_ON_BOARD] = {
    "R2L",
    "R2R",
    "eth3",
    "eth4",
};

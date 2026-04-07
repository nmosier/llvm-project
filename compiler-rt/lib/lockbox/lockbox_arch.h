#pragma once

#if defined(__x86_64__)
#include "lockbox_x86.h"
#elif defined(__aarch64__)
#include "lockbox_aarch64.h"
#else
#error "bad architecture!"
#endif
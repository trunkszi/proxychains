#if __has_include("version.h")
#include "version.h"
#endif

#ifndef VERSION
#define VERSION "0.0.1"
#endif

extern "C" __attribute__((visibility("default"))) const char* proxychains_get_version() noexcept {
    return VERSION;
}

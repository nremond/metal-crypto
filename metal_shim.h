#pragma once
#include <cstdint>
#include <cstddef>
namespace metal {
using uchar = unsigned char;
using uint = uint32_t;
using ulong = uint64_t;
inline uint min(uint a, uint b) { return a < b ? a : b; }
inline ulong min(ulong a, ulong b) { return a < b ? a : b; }
}
#define thread
#define device
#define constant
#define kernel

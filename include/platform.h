#ifndef PLATFORM_H
#define PLATFORM_H

// Platform-specific includes and definitions for cross-platform compatibility
// This header provides portable byte-order conversion functions

#include <cstdint>

// Portable byte order conversion
// Works on any platform without requiring system headers
namespace PortableNet {

inline uint16_t swapBytes16(uint16_t value) {
    return ((value & 0xFF00) >> 8) | ((value & 0x00FF) << 8);
}

inline uint32_t swapBytes32(uint32_t value) {
    return ((value & 0xFF000000) >> 24) |
           ((value & 0x00FF0000) >> 8)  |
           ((value & 0x0000FF00) << 8)  |
           ((value & 0x000000FF) << 24);
}

// Check system endianness at runtime
inline bool isLittleEndian() {
    uint16_t test = 0x0001;
    return *reinterpret_cast<uint8_t*>(&test) == 0x01;
}

// Network to host byte order (16-bit)
// Network byte order is always big-endian
inline uint16_t netToHost16(uint16_t netValue) {
    if (isLittleEndian()) {
        return swapBytes16(netValue);
    }
    return netValue;
}

// Network to host byte order (32-bit)
inline uint32_t netToHost32(uint32_t netValue) {
    if (isLittleEndian()) {
        return swapBytes32(netValue);
    }
    return netValue;
}

// Host to network byte order (16-bit)
inline uint16_t hostToNet16(uint16_t hostValue) {
    return netToHost16(hostValue);  // Same operation
}

// Host to network byte order (32-bit)
inline uint32_t hostToNet32(uint32_t hostValue) {
    return netToHost32(hostValue);  // Same operation
}

} // namespace PortableNet

#endif // PLATFORM_H

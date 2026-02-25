#ifndef SNI_EXTRACTOR_H
#define SNI_EXTRACTOR_H

#include <string>
#include <cstdint>
#include <optional>
#include <vector>

namespace DPI {

// ============================================================================
// SNI Extractor - Parses TLS Client Hello to extract Server Name Indication
// ============================================================================
// 
// TLS Client Hello Structure (simplified):
// 
// Record Layer:
//   - Content Type (1 byte): 0x16 = Handshake
//   - Version (2 bytes): 0x0301 = TLS 1.0, 0x0303 = TLS 1.2
//   - Length (2 bytes)
//
// Handshake Layer:
//   - Handshake Type (1 byte): 0x01 = Client Hello
//   - Length (3 bytes)
//   - Client Version (2 bytes)
//   - Random (32 bytes)
//   - Session ID Length (1 byte)
//   - Session ID (variable)
//   - Cipher Suites Length (2 bytes)
//   - Cipher Suites (variable)
//   - Compression Methods Length (1 byte)
//   - Compression Methods (variable)
//   - Extensions Length (2 bytes)
//   - Extensions (variable)
//
// SNI Extension (type 0x0000):
//   - Extension Type (2 bytes): 0x0000
//   - Extension Length (2 bytes)
//   - SNI List Length (2 bytes)
//   - SNI Type (1 byte): 0x00 = hostname
//   - SNI Length (2 bytes)
//   - SNI Value (variable): The hostname!
//
// ============================================================================

class SNIExtractor {
public:
    // Extract SNI from a TLS Client Hello packet
    // payload should point to the start of TCP payload (after TCP header)
    static std::optional<std::string> extract(const uint8_t* payload, size_t length);
    
    // Check if this looks like a TLS Client Hello
    static bool isTLSClientHello(const uint8_t* payload, size_t length);
    
    // Extract all extensions (for debugging/logging)
    static std::vector<std::pair<uint16_t, std::string>> extractExtensions(
        const uint8_t* payload, size_t length);

private:
    // TLS Constants
    static constexpr uint8_t CONTENT_TYPE_HANDSHAKE = 0x16;
    static constexpr uint8_t HANDSHAKE_CLIENT_HELLO = 0x01;
    static constexpr uint16_t EXTENSION_SNI = 0x0000;
    static constexpr uint8_t SNI_TYPE_HOSTNAME = 0x00;
    
    // Helper to read big-endian values
    static uint16_t readUint16BE(const uint8_t* data);
    static uint32_t readUint24BE(const uint8_t* data);
};

// ============================================================================
// QUIC SNI Extractor - For QUIC/HTTP3 traffic
// ============================================================================
class QUICSNIExtractor {
public:
    // QUIC Initial packets also contain TLS Client Hello (in CRYPTO frames)
    // This is more complex as QUIC has its own framing
    static std::optional<std::string> extract(const uint8_t* payload, size_t length);
    
    // Check if this looks like a QUIC Initial packet
    static bool isQUICInitial(const uint8_t* payload, size_t length);
};

// ============================================================================
// HTTP Host Header Extractor (for unencrypted HTTP)
// ============================================================================
class HTTPHostExtractor {
public:
    // Extract Host header from HTTP request
    static std::optional<std::string> extract(const uint8_t* payload, size_t length);
    
    // Check if this looks like an HTTP request
    static bool isHTTPRequest(const uint8_t* payload, size_t length);
};

// ============================================================================
// DNS Query Extractor (to correlate domain names)
// ============================================================================
class DNSExtractor {
public:
    // Extract queried domain from DNS request
    static std::optional<std::string> extractQuery(const uint8_t* payload, size_t length);
    
    // Check if this is a DNS query (not response)
    static bool isDNSQuery(const uint8_t* payload, size_t length);
};

} // namespace DPI

#endif // SNI_EXTRACTOR_H

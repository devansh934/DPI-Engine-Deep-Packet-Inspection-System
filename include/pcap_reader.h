#ifndef PCAP_READER_H
#define PCAP_READER_H

#include <cstdint>
#include <string>
#include <vector>
#include <fstream>

namespace PacketAnalyzer {

// PCAP Global Header (24 bytes)
// This is at the very beginning of every .pcap file
struct PcapGlobalHeader {
    uint32_t magic_number;   // 0xa1b2c3d4 (or swapped for big-endian)
    uint16_t version_major;  // Usually 2
    uint16_t version_minor;  // Usually 4
    int32_t  thiszone;       // GMT offset (usually 0)
    uint32_t sigfigs;        // Accuracy of timestamps (usually 0)
    uint32_t snaplen;        // Max length of captured packets
    uint32_t network;        // Data link type (1 = Ethernet)
};

// PCAP Packet Header (16 bytes)
// Each packet in the file starts with this header
struct PcapPacketHeader {
    uint32_t ts_sec;         // Timestamp seconds
    uint32_t ts_usec;        // Timestamp microseconds
    uint32_t incl_len;       // Number of bytes saved in file
    uint32_t orig_len;       // Actual length of packet
};

// Represents a single captured packet
struct RawPacket {
    PcapPacketHeader header;
    std::vector<uint8_t> data;  // The actual packet bytes
};

// Class to read PCAP files
class PcapReader {
public:
    PcapReader() = default;
    ~PcapReader();

    // Open a pcap file for reading
    bool open(const std::string& filename);
    
    // Close the file
    void close();
    
    // Read the next packet, returns false if no more packets
    bool readNextPacket(RawPacket& packet);
    
    // Get the global header info
    const PcapGlobalHeader& getGlobalHeader() const { return global_header_; }
    
    // Check if file is open
    bool isOpen() const { return file_.is_open(); }
    
    // Check if we need to swap byte order
    bool needsByteSwap() const { return needs_byte_swap_; }

private:
    std::ifstream file_;
    PcapGlobalHeader global_header_;
    bool needs_byte_swap_ = false;
    
    // Helper to swap bytes if needed
    uint16_t maybeSwap16(uint16_t value);
    uint32_t maybeSwap32(uint32_t value);
};

} // namespace PacketAnalyzer

#endif // PCAP_READER_H

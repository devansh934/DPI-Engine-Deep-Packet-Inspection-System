// Working DPI Engine - Simplified but functional
#include <iostream>
#include <fstream>
#include <unordered_map>
#include <vector>
#include <iomanip>
#include <unordered_set>
#include <algorithm>

#include "pcap_reader.h"
#include "packet_parser.h"
#include "sni_extractor.h"
#include "types.h"

using namespace PacketAnalyzer;
using namespace DPI;

// Simplified connection tracking
struct Flow {
    FiveTuple tuple;
    AppType app_type = AppType::UNKNOWN;
    std::string sni;
    uint64_t packets = 0;
    uint64_t bytes = 0;
    bool blocked = false;
};

// Blocking rules
class BlockingRules {
public:
    std::unordered_set<uint32_t> blocked_ips;
    std::unordered_set<AppType> blocked_apps;
    std::vector<std::string> blocked_domains;  // Simple substring match
    
    void blockIP(const std::string& ip) {
        uint32_t addr = parseIP(ip);
        blocked_ips.insert(addr);
        std::cout << "[Rules] Blocked IP: " << ip << "\n";
    }
    
    void blockApp(const std::string& app) {
        for (int i = 0; i < static_cast<int>(AppType::APP_COUNT); i++) {
            if (appTypeToString(static_cast<AppType>(i)) == app) {
                blocked_apps.insert(static_cast<AppType>(i));
                std::cout << "[Rules] Blocked app: " << app << "\n";
                return;
            }
        }
        std::cerr << "[Rules] Unknown app: " << app << "\n";
    }
    
    void blockDomain(const std::string& domain) {
        blocked_domains.push_back(domain);
        std::cout << "[Rules] Blocked domain: " << domain << "\n";
    }
    
    bool isBlocked(uint32_t src_ip, AppType app, const std::string& sni) const {
        if (blocked_ips.count(src_ip)) return true;
        if (blocked_apps.count(app)) return true;
        for (const auto& dom : blocked_domains) {
            if (sni.find(dom) != std::string::npos) return true;
        }
        return false;
    }
    
private:
    static uint32_t parseIP(const std::string& ip) {
        uint32_t result = 0;
        int octet = 0, shift = 0;
        for (char c : ip) {
            if (c == '.') { result |= (octet << shift); shift += 8; octet = 0; }
            else if (c >= '0' && c <= '9') octet = octet * 10 + (c - '0');
        }
        return result | (octet << shift);
    }
};

void printUsage(const char* prog) {
    std::cout << R"(
DPI Engine - Deep Packet Inspection System
==========================================

Usage: )" << prog << R"( <input.pcap> <output.pcap> [options]

Options:
  --block-ip <ip>        Block traffic from source IP
  --block-app <app>      Block application (YouTube, Facebook, etc.)
  --block-domain <dom>   Block domain (substring match)

Example:
  )" << prog << R"( capture.pcap filtered.pcap --block-app YouTube --block-ip 192.168.1.50
)";
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        printUsage(argv[0]);
        return 1;
    }
    
    std::string input_file = argv[1];
    std::string output_file = argv[2];
    
    BlockingRules rules;
    
    // Parse options
    for (int i = 3; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "--block-ip" && i + 1 < argc) {
            rules.blockIP(argv[++i]);
        } else if (arg == "--block-app" && i + 1 < argc) {
            rules.blockApp(argv[++i]);
        } else if (arg == "--block-domain" && i + 1 < argc) {
            rules.blockDomain(argv[++i]);
        }
    }
    
    std::cout << "\n";
    std::cout << "╔══════════════════════════════════════════════════════════════╗\n";
    std::cout << "║                    DPI ENGINE v1.0                            ║\n";
    std::cout << "╚══════════════════════════════════════════════════════════════╝\n\n";
    
    // Open input
    PcapReader reader;
    if (!reader.open(input_file)) {
        return 1;
    }
    
    // Open output
    std::ofstream output(output_file, std::ios::binary);
    if (!output.is_open()) {
        std::cerr << "Error: Cannot open output file\n";
        return 1;
    }
    
    // Write PCAP header
    const auto& header = reader.getGlobalHeader();
    output.write(reinterpret_cast<const char*>(&header), sizeof(header));
    
    // Flow table
    std::unordered_map<FiveTuple, Flow, FiveTupleHash> flows;
    
    // Statistics
    uint64_t total_packets = 0;
    uint64_t forwarded = 0;
    uint64_t dropped = 0;
    std::unordered_map<AppType, uint64_t> app_stats;
    
    RawPacket raw;
    ParsedPacket parsed;
    
    std::cout << "[DPI] Processing packets...\n";
    
    while (reader.readNextPacket(raw)) {
        total_packets++;
        
        if (!PacketParser::parse(raw, parsed)) continue;
        if (!parsed.has_ip || (!parsed.has_tcp && !parsed.has_udp)) continue;
        
        // Create five-tuple
        FiveTuple tuple;
        auto parseIP = [](const std::string& ip) -> uint32_t {
            uint32_t result = 0;
            int octet = 0, shift = 0;
            for (char c : ip) {
                if (c == '.') { result |= (octet << shift); shift += 8; octet = 0; }
                else if (c >= '0' && c <= '9') octet = octet * 10 + (c - '0');
            }
            return result | (octet << shift);
        };
        
        tuple.src_ip = parseIP(parsed.src_ip);
        tuple.dst_ip = parseIP(parsed.dest_ip);
        tuple.src_port = parsed.src_port;
        tuple.dst_port = parsed.dest_port;
        tuple.protocol = parsed.protocol;
        
        // Get or create flow
        Flow& flow = flows[tuple];
        if (flow.packets == 0) {
            flow.tuple = tuple;
        }
        flow.packets++;
        flow.bytes += raw.data.size();
        
        // Try SNI extraction - even for flows already marked as generic HTTPS
        if ((flow.app_type == AppType::UNKNOWN || flow.app_type == AppType::HTTPS) && 
            flow.sni.empty() && parsed.has_tcp && parsed.dest_port == 443) {
            
            size_t payload_offset = 14;
            uint8_t ip_ihl = raw.data[14] & 0x0F;
            payload_offset += ip_ihl * 4;
            
            if (payload_offset + 12 < raw.data.size()) {
                uint8_t tcp_offset = (raw.data[payload_offset + 12] >> 4) & 0x0F;
                payload_offset += tcp_offset * 4;
                
                if (payload_offset < raw.data.size()) {
                    size_t payload_len = raw.data.size() - payload_offset;
                    if (payload_len > 5) {  // Minimum TLS record header
                        auto sni = SNIExtractor::extract(raw.data.data() + payload_offset, payload_len);
                        if (sni) {
                            flow.sni = *sni;
                            flow.app_type = sniToAppType(*sni);
                        }
                    }
                }
            }
        }
        
        // HTTP Host extraction
        if ((flow.app_type == AppType::UNKNOWN || flow.app_type == AppType::HTTP) &&
            flow.sni.empty() && parsed.has_tcp && parsed.dest_port == 80) {
            
            size_t payload_offset = 14;
            uint8_t ip_ihl = raw.data[14] & 0x0F;
            payload_offset += ip_ihl * 4;
            
            if (payload_offset + 12 < raw.data.size()) {
                uint8_t tcp_offset = (raw.data[payload_offset + 12] >> 4) & 0x0F;
                payload_offset += tcp_offset * 4;
                
                if (payload_offset < raw.data.size()) {
                    size_t payload_len = raw.data.size() - payload_offset;
                    auto host = HTTPHostExtractor::extract(raw.data.data() + payload_offset, payload_len);
                    if (host) {
                        flow.sni = *host;
                        flow.app_type = sniToAppType(*host);
                    }
                }
            }
        }
        
        // DNS classification
        if (flow.app_type == AppType::UNKNOWN && 
            (parsed.dest_port == 53 || parsed.src_port == 53)) {
            flow.app_type = AppType::DNS;
        }
        
        // Port-based fallback
        if (flow.app_type == AppType::UNKNOWN) {
            if (parsed.dest_port == 443) flow.app_type = AppType::HTTPS;
            else if (parsed.dest_port == 80) flow.app_type = AppType::HTTP;
        }
        
        // Check blocking rules
        if (!flow.blocked) {
            flow.blocked = rules.isBlocked(tuple.src_ip, flow.app_type, flow.sni);
            if (flow.blocked) {
                std::cout << "[BLOCKED] " << parsed.src_ip << " -> " << parsed.dest_ip
                          << " (" << appTypeToString(flow.app_type);
                if (!flow.sni.empty()) std::cout << ": " << flow.sni;
                std::cout << ")\n";
            }
        }
        
        // Update app stats
        app_stats[flow.app_type]++;
        
        // Forward or drop
        if (flow.blocked) {
            dropped++;
        } else {
            forwarded++;
            // Write to output
            PcapPacketHeader pkt_hdr;
            pkt_hdr.ts_sec = raw.header.ts_sec;
            pkt_hdr.ts_usec = raw.header.ts_usec;
            pkt_hdr.incl_len = raw.data.size();
            pkt_hdr.orig_len = raw.data.size();
            output.write(reinterpret_cast<const char*>(&pkt_hdr), sizeof(pkt_hdr));
            output.write(reinterpret_cast<const char*>(raw.data.data()), raw.data.size());
        }
    }
    
    reader.close();
    output.close();
    
    // Print report
    std::cout << "\n";
    std::cout << "╔══════════════════════════════════════════════════════════════╗\n";
    std::cout << "║                      PROCESSING REPORT                       ║\n";
    std::cout << "╠══════════════════════════════════════════════════════════════╣\n";
    std::cout << "║ Total Packets:      " << std::setw(10) << total_packets << "                             ║\n";
    std::cout << "║ Forwarded:          " << std::setw(10) << forwarded << "                             ║\n";
    std::cout << "║ Dropped:            " << std::setw(10) << dropped << "                             ║\n";
    std::cout << "║ Active Flows:       " << std::setw(10) << flows.size() << "                             ║\n";
    std::cout << "╠══════════════════════════════════════════════════════════════╣\n";
    std::cout << "║                    APPLICATION BREAKDOWN                     ║\n";
    std::cout << "╠══════════════════════════════════════════════════════════════╣\n";
    
    // Sort by count
    std::vector<std::pair<AppType, uint64_t>> sorted_apps(app_stats.begin(), app_stats.end());
    std::sort(sorted_apps.begin(), sorted_apps.end(),
              [](const auto& a, const auto& b) { return a.second > b.second; });
    
    for (const auto& [app, count] : sorted_apps) {
        double pct = 100.0 * count / total_packets;
        int bar_len = static_cast<int>(pct / 5);
        std::string bar(bar_len, '#');
        
        std::cout << "║ " << std::setw(15) << std::left << appTypeToString(app)
                  << std::setw(8) << std::right << count
                  << " " << std::setw(5) << std::fixed << std::setprecision(1) << pct << "% "
                  << std::setw(20) << std::left << bar << "  ║\n";
    }
    
    std::cout << "╚══════════════════════════════════════════════════════════════╝\n";
    
    // List unique SNIs
    std::cout << "\n[Detected Applications/Domains]\n";
    std::unordered_map<std::string, AppType> unique_snis;
    for (const auto& [tuple, flow] : flows) {
        if (!flow.sni.empty()) {
            unique_snis[flow.sni] = flow.app_type;
        }
    }
    for (const auto& [sni, app] : unique_snis) {
        std::cout << "  - " << sni << " -> " << appTypeToString(app) << "\n";
    }
    
    std::cout << "\nOutput written to: " << output_file << "\n";
    
    return 0;
}

#include "fast_path.h"
#include <iostream>
#include <sstream>
#include <iomanip>

namespace DPI {

// ============================================================================
// FastPathProcessor Implementation
// ============================================================================

FastPathProcessor::FastPathProcessor(int fp_id,
                                     RuleManager* rule_manager,
                                     PacketOutputCallback output_callback)
    : fp_id_(fp_id),
      input_queue_(10000),
      conn_tracker_(fp_id),
      rule_manager_(rule_manager),
      output_callback_(std::move(output_callback)) {
}

FastPathProcessor::~FastPathProcessor() {
    stop();
}

void FastPathProcessor::start() {
    if (running_) return;
    
    running_ = true;
    thread_ = std::thread(&FastPathProcessor::run, this);
    
    std::cout << "[FP" << fp_id_ << "] Started\n";
}

void FastPathProcessor::stop() {
    if (!running_) return;
    
    running_ = false;
    input_queue_.shutdown();
    
    if (thread_.joinable()) {
        thread_.join();
    }
    
    std::cout << "[FP" << fp_id_ << "] Stopped (processed " 
              << packets_processed_ << " packets)\n";
}

void FastPathProcessor::run() {
    while (running_) {
        // Get packet from input queue
        auto job_opt = input_queue_.popWithTimeout(std::chrono::milliseconds(100));
        
        if (!job_opt) {
            // Periodically cleanup stale connections
            conn_tracker_.cleanupStale(std::chrono::seconds(300));
            continue;
        }
        
        packets_processed_++;
        
        // Process the packet
        PacketAction action = processPacket(*job_opt);
        
        // Call output callback
        if (output_callback_) {
            output_callback_(*job_opt, action);
        }
        
        // Update stats
        if (action == PacketAction::DROP) {
            packets_dropped_++;
        } else {
            packets_forwarded_++;
        }
    }
}

PacketAction FastPathProcessor::processPacket(PacketJob& job) {
    // Get or create connection
    Connection* conn = conn_tracker_.getOrCreateConnection(job.tuple);
    if (!conn) {
        // Should not happen, but handle gracefully
        return PacketAction::FORWARD;
    }
    
    // Update connection stats
    bool is_outbound = true;  // In this model, all packets from user are outbound
    conn_tracker_.updateConnection(conn, job.data.size(), is_outbound);
    
    // Update TCP state if applicable
    if (job.tuple.protocol == 6) {  // TCP
        updateTCPState(conn, job.tcp_flags);
    }
    
    // If connection is already blocked, drop immediately
    if (conn->state == ConnectionState::BLOCKED) {
        return PacketAction::DROP;
    }
    
    // If connection not yet classified, try to inspect payload
    if (conn->state != ConnectionState::CLASSIFIED && job.payload_length > 0) {
        inspectPayload(job, conn);
    }
    
    // Check rules (even for classified connections, as rules might change)
    return checkRules(job, conn);
}

void FastPathProcessor::inspectPayload(PacketJob& job, Connection* conn) {
    if (job.payload_length == 0 || job.payload_offset >= job.data.size()) {
        return;
    }
    
    const uint8_t* payload = job.data.data() + job.payload_offset;
    
    // Try TLS SNI extraction first (most common for HTTPS)
    if (tryExtractSNI(job, conn)) {
        return;
    }
    
    // Try HTTP Host header extraction
    if (tryExtractHTTPHost(job, conn)) {
        return;
    }
    
    // Check for DNS (port 53)
    if (job.tuple.dst_port == 53 || job.tuple.src_port == 53) {
        auto domain = DNSExtractor::extractQuery(payload, job.payload_length);
        if (domain) {
            conn_tracker_.classifyConnection(conn, AppType::DNS, *domain);
            return;
        }
    }
    
    // Basic port-based classification as fallback
    if (job.tuple.dst_port == 80) {
        conn_tracker_.classifyConnection(conn, AppType::HTTP, "");
    } else if (job.tuple.dst_port == 443) {
        conn_tracker_.classifyConnection(conn, AppType::HTTPS, "");
    }
}

bool FastPathProcessor::tryExtractSNI(const PacketJob& job, Connection* conn) {
    // Only for port 443 (HTTPS) or if it looks like TLS
    if (job.tuple.dst_port != 443 && job.payload_length < 50) {
        return false;
    }
    
    if (job.payload_offset >= job.data.size() || job.payload_length == 0) {
        return false;
    }
    
    const uint8_t* payload = job.data.data() + job.payload_offset;
    auto sni = SNIExtractor::extract(payload, job.payload_length);
    if (sni) {
        sni_extractions_++;
        
        // Map SNI to app type
        AppType app = sniToAppType(*sni);
        conn_tracker_.classifyConnection(conn, app, *sni);
        
        if (app != AppType::UNKNOWN && app != AppType::HTTPS) {
            classification_hits_++;
        }
        
        return true;
    }
    
    return false;
}

bool FastPathProcessor::tryExtractHTTPHost(const PacketJob& job, Connection* conn) {
    // Only for port 80 (HTTP)
    if (job.tuple.dst_port != 80) {
        return false;
    }
    
    if (job.payload_offset >= job.data.size() || job.payload_length == 0) {
        return false;
    }
    
    const uint8_t* payload = job.data.data() + job.payload_offset;
    auto host = HTTPHostExtractor::extract(payload, job.payload_length);
    if (host) {
        AppType app = sniToAppType(*host);
        conn_tracker_.classifyConnection(conn, app, *host);
        
        if (app != AppType::UNKNOWN && app != AppType::HTTP) {
            classification_hits_++;
        }
        
        return true;
    }
    
    return false;
}

PacketAction FastPathProcessor::checkRules(const PacketJob& job, Connection* conn) {
    if (!rule_manager_) {
        return PacketAction::FORWARD;
    }
    
    // Parse source IP from tuple
    uint32_t src_ip = job.tuple.src_ip;
    
    // Check blocking rules
    auto block_reason = rule_manager_->shouldBlock(
        src_ip,
        job.tuple.dst_port,
        conn->app_type,
        conn->sni
    );
    
    if (block_reason) {
        // Log the block
        std::ostringstream ss;
        ss << "[FP" << fp_id_ << "] BLOCKED packet: ";
        
        switch (block_reason->type) {
            case RuleManager::BlockReason::IP:
                ss << "IP " << block_reason->detail;
                break;
            case RuleManager::BlockReason::APP:
                ss << "App " << block_reason->detail;
                break;
            case RuleManager::BlockReason::DOMAIN:
                ss << "Domain " << block_reason->detail;
                break;
            case RuleManager::BlockReason::PORT:
                ss << "Port " << block_reason->detail;
                break;
        }
        
        std::cout << ss.str() << std::endl;
        
        // Mark connection as blocked
        conn_tracker_.blockConnection(conn);
        
        return PacketAction::DROP;
    }
    
    return PacketAction::FORWARD;
}

void FastPathProcessor::updateTCPState(Connection* conn, uint8_t tcp_flags) {
    constexpr uint8_t SYN = 0x02;
    constexpr uint8_t ACK = 0x10;
    constexpr uint8_t FIN = 0x01;
    constexpr uint8_t RST = 0x04;
    
    if (tcp_flags & SYN) {
        if (tcp_flags & ACK) {
            conn->syn_ack_seen = true;
        } else {
            conn->syn_seen = true;
        }
    }
    
    if (conn->syn_seen && conn->syn_ack_seen && (tcp_flags & ACK)) {
        if (conn->state == ConnectionState::NEW) {
            conn->state = ConnectionState::ESTABLISHED;
        }
    }
    
    if (tcp_flags & FIN) {
        conn->fin_seen = true;
    }
    
    if (tcp_flags & RST) {
        conn->state = ConnectionState::CLOSED;
    }
    
    if (conn->fin_seen && (tcp_flags & ACK)) {
        conn->state = ConnectionState::CLOSED;
    }
}

FastPathProcessor::FPStats FastPathProcessor::getStats() const {
    FPStats stats;
    stats.packets_processed = packets_processed_.load();
    stats.packets_forwarded = packets_forwarded_.load();
    stats.packets_dropped = packets_dropped_.load();
    stats.connections_tracked = conn_tracker_.getActiveCount();
    stats.sni_extractions = sni_extractions_.load();
    stats.classification_hits = classification_hits_.load();
    return stats;
}

// ============================================================================
// FPManager Implementation
// ============================================================================

FPManager::FPManager(int num_fps,
                     RuleManager* rule_manager,
                     PacketOutputCallback output_callback) {
    
    // Create FP processors (each has its own input queue)
    for (int i = 0; i < num_fps; i++) {
        auto fp = std::make_unique<FastPathProcessor>(i, rule_manager, output_callback);
        fps_.push_back(std::move(fp));
    }
    
    std::cout << "[FPManager] Created " << num_fps << " fast path processors\n";
}

FPManager::~FPManager() {
    stopAll();
}

void FPManager::startAll() {
    for (auto& fp : fps_) {
        fp->start();
    }
}

void FPManager::stopAll() {
    // Stop all FPs (they'll shutdown their own queues)
    for (auto& fp : fps_) {
        fp->stop();
    }
}

FPManager::AggregatedStats FPManager::getAggregatedStats() const {
    AggregatedStats stats = {0, 0, 0, 0};
    
    for (const auto& fp : fps_) {
        auto fp_stats = fp->getStats();
        stats.total_processed += fp_stats.packets_processed;
        stats.total_forwarded += fp_stats.packets_forwarded;
        stats.total_dropped += fp_stats.packets_dropped;
        stats.total_connections += fp_stats.connections_tracked;
    }
    
    return stats;
}

std::string FPManager::generateClassificationReport() const {
    // Aggregate app distribution across all FPs
    std::unordered_map<AppType, size_t> app_counts;
    std::unordered_map<std::string, size_t> domain_counts;
    size_t total_classified = 0;
    size_t total_unknown = 0;
    
    for (const auto& fp : fps_) {
        fp->getConnectionTracker().forEach([&](const Connection& conn) {
            app_counts[conn.app_type]++;
            
            if (conn.app_type == AppType::UNKNOWN) {
                total_unknown++;
            } else {
                total_classified++;
            }
            
            if (!conn.sni.empty()) {
                domain_counts[conn.sni]++;
            }
        });
    }
    
    std::ostringstream ss;
    ss << "\n╔══════════════════════════════════════════════════════════════╗\n";
    ss << "║                 APPLICATION CLASSIFICATION REPORT             ║\n";
    ss << "╠══════════════════════════════════════════════════════════════╣\n";
    
    size_t total = total_classified + total_unknown;
    double classified_pct = total > 0 ? (100.0 * total_classified / total) : 0;
    double unknown_pct = total > 0 ? (100.0 * total_unknown / total) : 0;
    
    ss << "║ Total Connections:    " << std::setw(10) << total << "                           ║\n";
    ss << "║ Classified:           " << std::setw(10) << total_classified 
       << " (" << std::fixed << std::setprecision(1) << classified_pct << "%)                  ║\n";
    ss << "║ Unidentified:         " << std::setw(10) << total_unknown
       << " (" << std::fixed << std::setprecision(1) << unknown_pct << "%)                  ║\n";
    
    ss << "╠══════════════════════════════════════════════════════════════╣\n";
    ss << "║                    APPLICATION DISTRIBUTION                   ║\n";
    ss << "╠══════════════════════════════════════════════════════════════╣\n";
    
    // Sort apps by count
    std::vector<std::pair<AppType, size_t>> sorted_apps(
        app_counts.begin(), app_counts.end());
    std::sort(sorted_apps.begin(), sorted_apps.end(),
              [](const auto& a, const auto& b) { return a.second > b.second; });
    
    for (const auto& pair : sorted_apps) {
        double pct = total > 0 ? (100.0 * pair.second / total) : 0;
        
        // Create a simple bar graph
        int bar_len = static_cast<int>(pct / 5);  // 20 chars max
        std::string bar(bar_len, '#');
        
        ss << "║ " << std::setw(15) << std::left << appTypeToString(pair.first)
           << std::setw(8) << std::right << pair.second
           << " " << std::setw(5) << std::fixed << std::setprecision(1) << pct << "% "
           << std::setw(20) << std::left << bar << "   ║\n";
    }
    
    ss << "╚══════════════════════════════════════════════════════════════╝\n";
    
    return ss.str();
}

} // namespace DPI

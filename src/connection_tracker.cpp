#include "connection_tracker.h"
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <mutex>

namespace DPI {

// ============================================================================
// ConnectionTracker Implementation
// ============================================================================

ConnectionTracker::ConnectionTracker(int fp_id, size_t max_connections)
    : fp_id_(fp_id), max_connections_(max_connections) {
}

Connection* ConnectionTracker::getOrCreateConnection(const FiveTuple& tuple) {
    auto it = connections_.find(tuple);
    
    if (it != connections_.end()) {
        return &it->second;
    }
    
    // Check if we need to evict old connections
    if (connections_.size() >= max_connections_) {
        evictOldest();
    }
    
    // Create new connection
    Connection conn;
    conn.tuple = tuple;
    conn.state = ConnectionState::NEW;
    conn.first_seen = std::chrono::steady_clock::now();
    conn.last_seen = conn.first_seen;
    
    auto result = connections_.emplace(tuple, std::move(conn));
    total_seen_++;
    
    return &result.first->second;
}

Connection* ConnectionTracker::getConnection(const FiveTuple& tuple) {
    auto it = connections_.find(tuple);
    if (it != connections_.end()) {
        return &it->second;
    }
    
    // Try reverse tuple (for bidirectional matching)
    auto rev = connections_.find(tuple.reverse());
    if (rev != connections_.end()) {
        return &rev->second;
    }
    
    return nullptr;
}

void ConnectionTracker::updateConnection(Connection* conn, size_t packet_size, bool is_outbound) {
    if (!conn) return;
    
    conn->last_seen = std::chrono::steady_clock::now();
    
    if (is_outbound) {
        conn->packets_out++;
        conn->bytes_out += packet_size;
    } else {
        conn->packets_in++;
        conn->bytes_in += packet_size;
    }
}

void ConnectionTracker::classifyConnection(Connection* conn, AppType app, const std::string& sni) {
    if (!conn) return;
    
    if (conn->state != ConnectionState::CLASSIFIED) {
        conn->app_type = app;
        conn->sni = sni;
        conn->state = ConnectionState::CLASSIFIED;
        classified_count_++;
    }
}

void ConnectionTracker::blockConnection(Connection* conn) {
    if (!conn) return;
    
    conn->state = ConnectionState::BLOCKED;
    conn->action = PacketAction::DROP;
    blocked_count_++;
}

void ConnectionTracker::closeConnection(const FiveTuple& tuple) {
    auto it = connections_.find(tuple);
    if (it != connections_.end()) {
        it->second.state = ConnectionState::CLOSED;
    }
}

size_t ConnectionTracker::cleanupStale(std::chrono::seconds timeout) {
    auto now = std::chrono::steady_clock::now();
    size_t removed = 0;
    
    for (auto it = connections_.begin(); it != connections_.end(); ) {
        auto age = std::chrono::duration_cast<std::chrono::seconds>(
            now - it->second.last_seen);
        
        if (age > timeout || it->second.state == ConnectionState::CLOSED) {
            it = connections_.erase(it);
            removed++;
        } else {
            ++it;
        }
    }
    
    return removed;
}

std::vector<Connection> ConnectionTracker::getAllConnections() const {
    std::vector<Connection> result;
    result.reserve(connections_.size());
    
    for (const auto& pair : connections_) {
        result.push_back(pair.second);
    }
    
    return result;
}

size_t ConnectionTracker::getActiveCount() const {
    return connections_.size();
}

ConnectionTracker::TrackerStats ConnectionTracker::getStats() const {
    TrackerStats stats;
    stats.active_connections = connections_.size();
    stats.total_connections_seen = total_seen_;
    stats.classified_connections = classified_count_;
    stats.blocked_connections = blocked_count_;
    return stats;
}

void ConnectionTracker::clear() {
    connections_.clear();
}

void ConnectionTracker::forEach(std::function<void(const Connection&)> callback) const {
    for (const auto& pair : connections_) {
        callback(pair.second);
    }
}

void ConnectionTracker::evictOldest() {
    if (connections_.empty()) return;
    
    // Find oldest connection
    auto oldest = connections_.begin();
    for (auto it = connections_.begin(); it != connections_.end(); ++it) {
        if (it->second.last_seen < oldest->second.last_seen) {
            oldest = it;
        }
    }
    
    connections_.erase(oldest);
}

// ============================================================================
// GlobalConnectionTable Implementation
// ============================================================================

GlobalConnectionTable::GlobalConnectionTable(size_t num_fps) {
    trackers_.resize(num_fps, nullptr);
}

void GlobalConnectionTable::registerTracker(int fp_id, ConnectionTracker* tracker) {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    if (fp_id < static_cast<int>(trackers_.size())) {
        trackers_[fp_id] = tracker;
    }
}

GlobalConnectionTable::GlobalStats GlobalConnectionTable::getGlobalStats() const {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    
    GlobalStats stats;
    stats.total_active_connections = 0;
    stats.total_connections_seen = 0;
    
    std::unordered_map<std::string, size_t> domain_counts;
    
    for (const auto* tracker : trackers_) {
        if (!tracker) continue;
        
        auto tracker_stats = tracker->getStats();
        stats.total_active_connections += tracker_stats.active_connections;
        stats.total_connections_seen += tracker_stats.total_connections_seen;
        
        // Collect app distribution
        tracker->forEach([&](const Connection& conn) {
            stats.app_distribution[conn.app_type]++;
            if (!conn.sni.empty()) {
                domain_counts[conn.sni]++;
            }
        });
    }
    
    // Get top domains
    std::vector<std::pair<std::string, size_t>> domain_vec(
        domain_counts.begin(), domain_counts.end());
    
    std::sort(domain_vec.begin(), domain_vec.end(),
              [](const auto& a, const auto& b) { return a.second > b.second; });
    
    // Take top 20
    size_t count = std::min(domain_vec.size(), static_cast<size_t>(20));
    stats.top_domains.assign(domain_vec.begin(), domain_vec.begin() + count);
    
    return stats;
}

std::string GlobalConnectionTable::generateReport() const {
    auto stats = getGlobalStats();
    
    std::ostringstream ss;
    ss << "\n╔══════════════════════════════════════════════════════════════╗\n";
    ss << "║               CONNECTION STATISTICS REPORT                    ║\n";
    ss << "╠══════════════════════════════════════════════════════════════╣\n";
    
    ss << "║ Active Connections:     " << std::setw(10) << stats.total_active_connections << "                          ║\n";
    ss << "║ Total Connections Seen: " << std::setw(10) << stats.total_connections_seen << "                          ║\n";
    
    ss << "╠══════════════════════════════════════════════════════════════╣\n";
    ss << "║                    APPLICATION BREAKDOWN                      ║\n";
    ss << "╠══════════════════════════════════════════════════════════════╣\n";
    
    // Calculate total for percentages
    size_t total = 0;
    for (const auto& pair : stats.app_distribution) {
        total += pair.second;
    }
    
    // Sort by count
    std::vector<std::pair<AppType, size_t>> sorted_apps(
        stats.app_distribution.begin(), stats.app_distribution.end());
    std::sort(sorted_apps.begin(), sorted_apps.end(),
              [](const auto& a, const auto& b) { return a.second > b.second; });
    
    for (const auto& pair : sorted_apps) {
        double pct = total > 0 ? (100.0 * pair.second / total) : 0;
        ss << "║ " << std::setw(20) << std::left << appTypeToString(pair.first)
           << std::setw(10) << std::right << pair.second
           << " (" << std::fixed << std::setprecision(1) << std::setw(5) << pct << "%)           ║\n";
    }
    
    if (!stats.top_domains.empty()) {
        ss << "╠══════════════════════════════════════════════════════════════╣\n";
        ss << "║                      TOP DOMAINS                             ║\n";
        ss << "╠══════════════════════════════════════════════════════════════╣\n";
        
        for (const auto& pair : stats.top_domains) {
            std::string domain = pair.first;
            if (domain.length() > 35) {
                domain = domain.substr(0, 32) + "...";
            }
            ss << "║ " << std::setw(40) << std::left << domain
               << std::setw(10) << std::right << pair.second << "           ║\n";
        }
    }
    
    ss << "╚══════════════════════════════════════════════════════════════╝\n";
    
    return ss.str();
}

} // namespace DPI

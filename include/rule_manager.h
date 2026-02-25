#ifndef RULE_MANAGER_H
#define RULE_MANAGER_H

#include "types.h"
#include <string>
#include <unordered_set>
#include <unordered_map>
#include <shared_mutex>
#include <mutex>
#include <optional>
#include <vector>
#include <fstream>

namespace DPI {

// ============================================================================
// Rule Manager - Manages blocking/filtering rules
// ============================================================================
// 
// Rules can be:
// 1. IP-based: Block specific source IPs
// 2. App-based: Block specific applications (detected via SNI)
// 3. Domain-based: Block specific domains
// 4. Port-based: Block specific destination ports
//
// Rules are thread-safe for concurrent access from FP threads
// ============================================================================

class RuleManager {
public:
    RuleManager() = default;
    
    // ========== IP Blocking ==========
    
    // Block a specific source IP
    void blockIP(uint32_t ip);
    void blockIP(const std::string& ip);
    
    // Unblock an IP
    void unblockIP(uint32_t ip);
    void unblockIP(const std::string& ip);
    
    // Check if IP is blocked
    bool isIPBlocked(uint32_t ip) const;
    
    // Get list of blocked IPs (for display)
    std::vector<std::string> getBlockedIPs() const;
    
    // ========== Application Blocking ==========
    
    // Block a specific application type
    void blockApp(AppType app);
    
    // Unblock an application
    void unblockApp(AppType app);
    
    // Check if app is blocked
    bool isAppBlocked(AppType app) const;
    
    // Get list of blocked apps
    std::vector<AppType> getBlockedApps() const;
    
    // ========== Domain Blocking ==========
    
    // Block a specific domain (or pattern)
    // Supports wildcards: *.facebook.com blocks all facebook subdomains
    void blockDomain(const std::string& domain);
    
    // Unblock a domain
    void unblockDomain(const std::string& domain);
    
    // Check if domain matches any block rule
    bool isDomainBlocked(const std::string& domain) const;
    
    // Get list of blocked domains
    std::vector<std::string> getBlockedDomains() const;
    
    // ========== Port Blocking ==========
    
    // Block a specific destination port
    void blockPort(uint16_t port);
    
    // Unblock a port
    void unblockPort(uint16_t port);
    
    // Check if port is blocked
    bool isPortBlocked(uint16_t port) const;
    
    // ========== Combined Check ==========
    
    // Check if a packet/connection should be blocked based on all rules
    // Returns the reason if blocked, nullopt if allowed
    struct BlockReason {
        enum Type { IP, APP, DOMAIN, PORT } type;
        std::string detail;
    };
    
    std::optional<BlockReason> shouldBlock(
        uint32_t src_ip,
        uint16_t dst_port,
        AppType app,
        const std::string& domain) const;
    
    // ========== Rule Persistence ==========
    
    // Save rules to file
    bool saveRules(const std::string& filename) const;
    
    // Load rules from file
    bool loadRules(const std::string& filename);
    
    // Clear all rules
    void clearAll();
    
    // ========== Statistics ==========
    
    struct RuleStats {
        size_t blocked_ips;
        size_t blocked_apps;
        size_t blocked_domains;
        size_t blocked_ports;
    };
    
    RuleStats getStats() const;

private:
    // Thread-safe containers with read-write locks
    mutable std::shared_mutex ip_mutex_;
    std::unordered_set<uint32_t> blocked_ips_;
    
    mutable std::shared_mutex app_mutex_;
    std::unordered_set<AppType> blocked_apps_;
    
    mutable std::shared_mutex domain_mutex_;
    std::unordered_set<std::string> blocked_domains_;
    std::vector<std::string> domain_patterns_;  // For wildcard matching
    
    mutable std::shared_mutex port_mutex_;
    std::unordered_set<uint16_t> blocked_ports_;
    
    // Helper: Convert IP string to uint32
    static uint32_t parseIP(const std::string& ip);
    
    // Helper: Convert uint32 to IP string
    static std::string ipToString(uint32_t ip);
    
    // Helper: Check if domain matches pattern (supports wildcards)
    static bool domainMatchesPattern(const std::string& domain, const std::string& pattern);
};

} // namespace DPI

#endif // RULE_MANAGER_H

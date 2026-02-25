#include "rule_manager.h"
#include <sstream>
#include <iostream>
#include <algorithm>
#include <mutex>

namespace DPI {

// ============================================================================
// IP Blocking
// ============================================================================

uint32_t RuleManager::parseIP(const std::string& ip) {
    uint32_t result = 0;
    int octet = 0;
    int shift = 0;
    
    for (char c : ip) {
        if (c == '.') {
            result |= (octet << shift);
            shift += 8;
            octet = 0;
        } else if (c >= '0' && c <= '9') {
            octet = octet * 10 + (c - '0');
        }
    }
    result |= (octet << shift);
    
    return result;
}

std::string RuleManager::ipToString(uint32_t ip) {
    std::ostringstream ss;
    ss << ((ip >> 0) & 0xFF) << "."
       << ((ip >> 8) & 0xFF) << "."
       << ((ip >> 16) & 0xFF) << "."
       << ((ip >> 24) & 0xFF);
    return ss.str();
}

void RuleManager::blockIP(uint32_t ip) {
    std::unique_lock<std::shared_mutex> lock(ip_mutex_);
    blocked_ips_.insert(ip);
    std::cout << "[RuleManager] Blocked IP: " << ipToString(ip) << std::endl;
}

void RuleManager::blockIP(const std::string& ip) {
    blockIP(parseIP(ip));
}

void RuleManager::unblockIP(uint32_t ip) {
    std::unique_lock<std::shared_mutex> lock(ip_mutex_);
    blocked_ips_.erase(ip);
    std::cout << "[RuleManager] Unblocked IP: " << ipToString(ip) << std::endl;
}

void RuleManager::unblockIP(const std::string& ip) {
    unblockIP(parseIP(ip));
}

bool RuleManager::isIPBlocked(uint32_t ip) const {
    std::shared_lock<std::shared_mutex> lock(ip_mutex_);
    return blocked_ips_.count(ip) > 0;
}

std::vector<std::string> RuleManager::getBlockedIPs() const {
    std::shared_lock<std::shared_mutex> lock(ip_mutex_);
    std::vector<std::string> result;
    for (uint32_t ip : blocked_ips_) {
        result.push_back(ipToString(ip));
    }
    return result;
}

// ============================================================================
// Application Blocking
// ============================================================================

void RuleManager::blockApp(AppType app) {
    std::unique_lock<std::shared_mutex> lock(app_mutex_);
    blocked_apps_.insert(app);
    std::cout << "[RuleManager] Blocked app: " << appTypeToString(app) << std::endl;
}

void RuleManager::unblockApp(AppType app) {
    std::unique_lock<std::shared_mutex> lock(app_mutex_);
    blocked_apps_.erase(app);
    std::cout << "[RuleManager] Unblocked app: " << appTypeToString(app) << std::endl;
}

bool RuleManager::isAppBlocked(AppType app) const {
    std::shared_lock<std::shared_mutex> lock(app_mutex_);
    return blocked_apps_.count(app) > 0;
}

std::vector<AppType> RuleManager::getBlockedApps() const {
    std::shared_lock<std::shared_mutex> lock(app_mutex_);
    return std::vector<AppType>(blocked_apps_.begin(), blocked_apps_.end());
}

// ============================================================================
// Domain Blocking
// ============================================================================

void RuleManager::blockDomain(const std::string& domain) {
    std::unique_lock<std::shared_mutex> lock(domain_mutex_);
    
    if (domain.find('*') != std::string::npos) {
        domain_patterns_.push_back(domain);
    } else {
        blocked_domains_.insert(domain);
    }
    
    std::cout << "[RuleManager] Blocked domain: " << domain << std::endl;
}

void RuleManager::unblockDomain(const std::string& domain) {
    std::unique_lock<std::shared_mutex> lock(domain_mutex_);
    
    if (domain.find('*') != std::string::npos) {
        auto it = std::find(domain_patterns_.begin(), domain_patterns_.end(), domain);
        if (it != domain_patterns_.end()) {
            domain_patterns_.erase(it);
        }
    } else {
        blocked_domains_.erase(domain);
    }
    
    std::cout << "[RuleManager] Unblocked domain: " << domain << std::endl;
}

bool RuleManager::domainMatchesPattern(const std::string& domain, const std::string& pattern) {
    // Handle *.example.com pattern
    if (pattern.size() >= 2 && pattern[0] == '*' && pattern[1] == '.') {
        std::string suffix = pattern.substr(1);  // .example.com
        
        // Check if domain ends with the pattern
        if (domain.size() >= suffix.size() &&
            domain.compare(domain.size() - suffix.size(), suffix.size(), suffix) == 0) {
            return true;
        }
        
        // Also match the bare domain (example.com matches *.example.com)
        if (domain == pattern.substr(2)) {
            return true;
        }
    }
    
    return false;
}

bool RuleManager::isDomainBlocked(const std::string& domain) const {
    std::shared_lock<std::shared_mutex> lock(domain_mutex_);
    
    // Check exact match
    if (blocked_domains_.count(domain) > 0) {
        return true;
    }
    
    // Check patterns
    std::string lower_domain = domain;
    std::transform(lower_domain.begin(), lower_domain.end(), lower_domain.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    
    for (const auto& pattern : domain_patterns_) {
        std::string lower_pattern = pattern;
        std::transform(lower_pattern.begin(), lower_pattern.end(), lower_pattern.begin(),
                       [](unsigned char c) { return std::tolower(c); });
        
        if (domainMatchesPattern(lower_domain, lower_pattern)) {
            return true;
        }
    }
    
    return false;
}

std::vector<std::string> RuleManager::getBlockedDomains() const {
    std::shared_lock<std::shared_mutex> lock(domain_mutex_);
    std::vector<std::string> result(blocked_domains_.begin(), blocked_domains_.end());
    result.insert(result.end(), domain_patterns_.begin(), domain_patterns_.end());
    return result;
}

// ============================================================================
// Port Blocking
// ============================================================================

void RuleManager::blockPort(uint16_t port) {
    std::unique_lock<std::shared_mutex> lock(port_mutex_);
    blocked_ports_.insert(port);
    std::cout << "[RuleManager] Blocked port: " << port << std::endl;
}

void RuleManager::unblockPort(uint16_t port) {
    std::unique_lock<std::shared_mutex> lock(port_mutex_);
    blocked_ports_.erase(port);
}

bool RuleManager::isPortBlocked(uint16_t port) const {
    std::shared_lock<std::shared_mutex> lock(port_mutex_);
    return blocked_ports_.count(port) > 0;
}

// ============================================================================
// Combined Check
// ============================================================================

std::optional<RuleManager::BlockReason> RuleManager::shouldBlock(
    uint32_t src_ip,
    uint16_t dst_port,
    AppType app,
    const std::string& domain) const {
    
    // Check IP first (most specific)
    if (isIPBlocked(src_ip)) {
        return BlockReason{BlockReason::IP, ipToString(src_ip)};
    }
    
    // Check port
    if (isPortBlocked(dst_port)) {
        return BlockReason{BlockReason::PORT, std::to_string(dst_port)};
    }
    
    // Check app
    if (isAppBlocked(app)) {
        return BlockReason{BlockReason::APP, appTypeToString(app)};
    }
    
    // Check domain
    if (!domain.empty() && isDomainBlocked(domain)) {
        return BlockReason{BlockReason::DOMAIN, domain};
    }
    
    return std::nullopt;
}

// ============================================================================
// Persistence
// ============================================================================

bool RuleManager::saveRules(const std::string& filename) const {
    std::ofstream file(filename);
    if (!file.is_open()) {
        return false;
    }
    
    // Save blocked IPs
    file << "[BLOCKED_IPS]\n";
    for (const auto& ip : getBlockedIPs()) {
        file << ip << "\n";
    }
    
    // Save blocked apps
    file << "\n[BLOCKED_APPS]\n";
    for (const auto& app : getBlockedApps()) {
        file << appTypeToString(app) << "\n";
    }
    
    // Save blocked domains
    file << "\n[BLOCKED_DOMAINS]\n";
    for (const auto& domain : getBlockedDomains()) {
        file << domain << "\n";
    }
    
    // Save blocked ports
    file << "\n[BLOCKED_PORTS]\n";
    {
        std::shared_lock<std::shared_mutex> lock(port_mutex_);
        for (uint16_t port : blocked_ports_) {
            file << port << "\n";
        }
    }
    
    file.close();
    std::cout << "[RuleManager] Rules saved to: " << filename << std::endl;
    return true;
}

bool RuleManager::loadRules(const std::string& filename) {
    std::ifstream file(filename);
    if (!file.is_open()) {
        return false;
    }
    
    std::string line;
    std::string current_section;
    
    while (std::getline(file, line)) {
        // Skip empty lines
        if (line.empty()) continue;
        
        // Check for section headers
        if (line[0] == '[') {
            current_section = line;
            continue;
        }
        
        // Process based on section
        if (current_section == "[BLOCKED_IPS]") {
            blockIP(line);
        } else if (current_section == "[BLOCKED_APPS]") {
            // Convert string back to AppType
            for (int i = 0; i < static_cast<int>(AppType::APP_COUNT); i++) {
                if (appTypeToString(static_cast<AppType>(i)) == line) {
                    blockApp(static_cast<AppType>(i));
                    break;
                }
            }
        } else if (current_section == "[BLOCKED_DOMAINS]") {
            blockDomain(line);
        } else if (current_section == "[BLOCKED_PORTS]") {
            blockPort(static_cast<uint16_t>(std::stoi(line)));
        }
    }
    
    file.close();
    std::cout << "[RuleManager] Rules loaded from: " << filename << std::endl;
    return true;
}

void RuleManager::clearAll() {
    {
        std::unique_lock<std::shared_mutex> lock(ip_mutex_);
        blocked_ips_.clear();
    }
    {
        std::unique_lock<std::shared_mutex> lock(app_mutex_);
        blocked_apps_.clear();
    }
    {
        std::unique_lock<std::shared_mutex> lock(domain_mutex_);
        blocked_domains_.clear();
        domain_patterns_.clear();
    }
    {
        std::unique_lock<std::shared_mutex> lock(port_mutex_);
        blocked_ports_.clear();
    }
    std::cout << "[RuleManager] All rules cleared" << std::endl;
}

RuleManager::RuleStats RuleManager::getStats() const {
    RuleStats stats;
    
    {
        std::shared_lock<std::shared_mutex> lock(ip_mutex_);
        stats.blocked_ips = blocked_ips_.size();
    }
    {
        std::shared_lock<std::shared_mutex> lock(app_mutex_);
        stats.blocked_apps = blocked_apps_.size();
    }
    {
        std::shared_lock<std::shared_mutex> lock(domain_mutex_);
        stats.blocked_domains = blocked_domains_.size() + domain_patterns_.size();
    }
    {
        std::shared_lock<std::shared_mutex> lock(port_mutex_);
        stats.blocked_ports = blocked_ports_.size();
    }
    
    return stats;
}

} // namespace DPI

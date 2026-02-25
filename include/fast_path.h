#ifndef FAST_PATH_H
#define FAST_PATH_H

#include "types.h"
#include "thread_safe_queue.h"
#include "connection_tracker.h"
#include "rule_manager.h"
#include "sni_extractor.h"
#include <thread>
#include <atomic>
#include <memory>
#include <functional>

namespace DPI {

// ============================================================================
// Fast Path Processor Thread
// ============================================================================
//
// Each FP thread is responsible for:
// 1. Receiving packets from its input queue (fed by LB)
// 2. Connection tracking (maintaining flow state)
// 3. Deep Packet Inspection (SNI extraction, protocol detection)
// 4. Rule matching (blocking decisions)
// 5. Forwarding or dropping packets
//
// FP threads are the workhorses of the DPI engine. They do the heavy lifting
// of actually inspecting packet contents and making decisions.
//
// ============================================================================

// Callback type for packet output (forwarding)
using PacketOutputCallback = std::function<void(const PacketJob&, PacketAction)>;

class FastPathProcessor {
public:
    // Constructor
    // fp_id: ID of this FP (0, 1, 2, ...)
    // rule_manager: Shared rule manager (read-only from FP perspective)
    // output_callback: Called when packet should be forwarded
    FastPathProcessor(int fp_id,
                      RuleManager* rule_manager,
                      PacketOutputCallback output_callback);
    
    ~FastPathProcessor();
    
    // Start the FP thread
    void start();
    
    // Stop the FP thread
    void stop();
    
    // Get input queue (for LB to push packets)
    ThreadSafeQueue<PacketJob>& getInputQueue() { return input_queue_; }
    
    // Get connection tracker (for reporting)
    ConnectionTracker& getConnectionTracker() { return conn_tracker_; }
    
    // Get statistics
    struct FPStats {
        uint64_t packets_processed;
        uint64_t packets_forwarded;
        uint64_t packets_dropped;
        uint64_t connections_tracked;
        uint64_t sni_extractions;
        uint64_t classification_hits;
    };
    
    FPStats getStats() const;
    
    // Get FP ID
    int getId() const { return fp_id_; }
    
    // Check if running
    bool isRunning() const { return running_; }

private:
    int fp_id_;
    
    // Input queue from LB
    ThreadSafeQueue<PacketJob> input_queue_;
    
    // Connection tracker (per-FP, no sharing needed)
    ConnectionTracker conn_tracker_;
    
    // Rule manager (shared, read-only)
    RuleManager* rule_manager_;
    
    // Output callback
    PacketOutputCallback output_callback_;
    
    // Statistics
    std::atomic<uint64_t> packets_processed_{0};
    std::atomic<uint64_t> packets_forwarded_{0};
    std::atomic<uint64_t> packets_dropped_{0};
    std::atomic<uint64_t> sni_extractions_{0};
    std::atomic<uint64_t> classification_hits_{0};
    
    // Thread control
    std::atomic<bool> running_{false};
    std::thread thread_;
    
    // Main processing loop
    void run();
    
    // Process a single packet
    PacketAction processPacket(PacketJob& job);
    
    // Inspect packet payload for classification
    void inspectPayload(PacketJob& job, Connection* conn);
    
    // Extract SNI from TLS Client Hello
    bool tryExtractSNI(const PacketJob& job, Connection* conn);
    
    // Extract Host from HTTP request
    bool tryExtractHTTPHost(const PacketJob& job, Connection* conn);
    
    // Check if packet matches any blocking rules
    PacketAction checkRules(const PacketJob& job, Connection* conn);
    
    // Update TCP connection state
    void updateTCPState(Connection* conn, uint8_t tcp_flags);
};

// ============================================================================
// FP Manager - Creates and manages multiple FP threads
// ============================================================================
class FPManager {
public:
    // Create FP manager
    // num_fps: Number of FP threads
    // rule_manager: Shared rule manager
    // output_callback: Shared output callback
    FPManager(int num_fps,
              RuleManager* rule_manager,
              PacketOutputCallback output_callback);
    
    ~FPManager();
    
    // Start all FP threads
    void startAll();
    
    // Stop all FP threads
    void stopAll();
    
    // Get specific FP
    FastPathProcessor& getFP(int id) { return *fps_[id]; }
    
    // Get FP input queue
    ThreadSafeQueue<PacketJob>& getFPQueue(int id) { return fps_[id]->getInputQueue(); }
    
    // Get all FP queues as raw pointers (for LB manager)
    std::vector<ThreadSafeQueue<PacketJob>*> getQueuePtrs() {
        std::vector<ThreadSafeQueue<PacketJob>*> ptrs;
        for (auto& fp : fps_) {
            ptrs.push_back(&fp->getInputQueue());
        }
        return ptrs;
    }
    
    // Get number of FPs
    int getNumFPs() const { return fps_.size(); }
    
    // Get aggregated stats
    struct AggregatedStats {
        uint64_t total_processed;
        uint64_t total_forwarded;
        uint64_t total_dropped;
        uint64_t total_connections;
    };
    
    AggregatedStats getAggregatedStats() const;
    
    // Generate classification report
    std::string generateClassificationReport() const;

private:
    std::vector<std::unique_ptr<FastPathProcessor>> fps_;
};

} // namespace DPI

#endif // FAST_PATH_H

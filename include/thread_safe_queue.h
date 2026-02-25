#ifndef THREAD_SAFE_QUEUE_H
#define THREAD_SAFE_QUEUE_H

#include <queue>
#include <mutex>
#include <condition_variable>
#include <optional>
#include <chrono>

namespace DPI {

// ============================================================================
// Thread-safe queue for passing packets between threads
// Used for: Reader -> LB -> FP communication
// ============================================================================
template<typename T>
class ThreadSafeQueue {
public:
    ThreadSafeQueue(size_t max_size = 10000) : max_size_(max_size) {}
    
    // Push item to queue (blocks if full)
    void push(T item) {
        std::unique_lock<std::mutex> lock(mutex_);
        not_full_.wait(lock, [this] { return queue_.size() < max_size_ || shutdown_; });
        
        if (shutdown_) return;
        
        queue_.push(std::move(item));
        not_empty_.notify_one();
    }
    
    // Try to push without blocking
    bool tryPush(T item) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (queue_.size() >= max_size_ || shutdown_) {
            return false;
        }
        queue_.push(std::move(item));
        not_empty_.notify_one();
        return true;
    }
    
    // Pop item from queue (blocks if empty)
    std::optional<T> pop() {
        std::unique_lock<std::mutex> lock(mutex_);
        not_empty_.wait(lock, [this] { return !queue_.empty() || shutdown_; });
        
        if (queue_.empty()) return std::nullopt;
        
        T item = std::move(queue_.front());
        queue_.pop();
        not_full_.notify_one();
        return item;
    }
    
    // Pop with timeout
    std::optional<T> popWithTimeout(std::chrono::milliseconds timeout) {
        std::unique_lock<std::mutex> lock(mutex_);
        
        if (!not_empty_.wait_for(lock, timeout, [this] { return !queue_.empty() || shutdown_; })) {
            return std::nullopt;  // Timeout
        }
        
        if (queue_.empty()) return std::nullopt;
        
        T item = std::move(queue_.front());
        queue_.pop();
        not_full_.notify_one();
        return item;
    }
    
    // Check if empty
    bool empty() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return queue_.empty();
    }
    
    // Get current size
    size_t size() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return queue_.size();
    }
    
    // Signal shutdown (wake up all waiting threads)
    void shutdown() {
        std::lock_guard<std::mutex> lock(mutex_);
        shutdown_ = true;
        not_empty_.notify_all();
        not_full_.notify_all();
    }
    
    bool isShutdown() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return shutdown_;
    }

private:
    std::queue<T> queue_;
    mutable std::mutex mutex_;
    std::condition_variable not_empty_;
    std::condition_variable not_full_;
    size_t max_size_;
    bool shutdown_ = false;
};

} // namespace DPI

#endif // THREAD_SAFE_QUEUE_H

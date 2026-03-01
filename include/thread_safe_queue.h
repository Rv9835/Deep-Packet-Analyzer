#ifndef THREAD_SAFE_QUEUE_H
#define THREAD_SAFE_QUEUE_H

#include <queue>
#include <mutex>
#include <condition_variable>

// Simple thread-safe queue template

template<typename T>
class ThreadSafeQueue {
public:
    void push(const T &item) {
        std::lock_guard<std::mutex> lock(mutex_);
        queue_.push(item);
        cond_.notify_one();
    }
    bool pop(T &item) {
        std::unique_lock<std::mutex> lock(mutex_);
        cond_.wait(lock, [this]{ return !queue_.empty(); });
        item = queue_.front();
        queue_.pop();
        return true;
    }
private:
    std::queue<T> queue_;
    std::mutex mutex_;
    std::condition_variable cond_;
};

#endif // THREAD_SAFE_QUEUE_H

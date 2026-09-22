#pragma once

#include <atomic>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <span>
#include <thread>
#include <vector>

namespace utils {
    class ThreadPool {
    public:
        ThreadPool(size_t threadCount = std::thread::hardware_concurrency());
        ~ThreadPool();

        ThreadPool(ThreadPool const&) = delete;
        ThreadPool& operator=(ThreadPool const&) = delete;

        void enqueue(std::move_only_function<void()> task);
        void waitAll();

        [[nodiscard]] bool isRunning() const;

    private:
        std::vector<std::thread> m_workers;
        std::vector<std::move_only_function<void()>> m_tasks;

        mutable std::mutex m_queueMutex;
        std::condition_variable m_condition;
        std::condition_variable m_waitCondition;
        std::atomic<bool> m_stop{false};
        std::atomic<size_t> m_activeTasks{0};

        void workerThread();
    };
} // namespace utils
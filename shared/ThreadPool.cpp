#include "ThreadPool.hpp"

utils::ThreadPool::ThreadPool(size_t threadCount) {
    m_workers.reserve(threadCount);
    for (size_t i = 0; i < threadCount; ++i) {
        m_workers.emplace_back(&ThreadPool::workerThread, this);
    }
}

utils::ThreadPool::~ThreadPool() {
    {
        std::unique_lock lock(m_queueMutex);
        m_stop = true;
    }
    m_condition.notify_all();
    for (auto& worker : m_workers) {
        if (worker.joinable()) {
            worker.join();
        }
    }
}

void utils::ThreadPool::enqueue(std::move_only_function<void()> task) {
    {
        std::unique_lock lock(m_queueMutex);
        m_tasks.emplace_back(std::move(task));
    }
    m_condition.notify_one();
}

void utils::ThreadPool::waitAll() {
    std::unique_lock lock(m_queueMutex);
    m_waitCondition.wait(lock, [this] {
        return m_tasks.empty() && m_activeTasks.load(std::memory_order_acquire) == 0;
    });
}

bool utils::ThreadPool::isRunning() const {
    std::unique_lock lock(m_queueMutex);
    return !m_tasks.empty() || m_activeTasks.load() > 0;
}

void utils::ThreadPool::workerThread() {
    while (true) {
        std::move_only_function<void()> task;
        {
            std::unique_lock lock(m_queueMutex);
            m_condition.wait(lock, [this] { return m_stop.load() || !m_tasks.empty(); });
            if (m_stop.load() && m_tasks.empty()) {
                return;
            }
            task = std::move(m_tasks.front());
            m_tasks.erase(m_tasks.begin());
            ++m_activeTasks;
        }
        task();
        size_t remaining = --m_activeTasks;
        if (remaining == 0) {
            std::unique_lock lock(m_queueMutex);
            if (m_tasks.empty()) {
                m_waitCondition.notify_all();
            }
        }
    }
}

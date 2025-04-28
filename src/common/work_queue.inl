// Copyright (c) 2025, The Monero Project
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#pragma once

//paired header
#include "work_queue.h"

//local headers
#include "misc_log_ex.h"

//third party headers

//standard headers

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "work_queue"

namespace tools
{

template <typename ResultT>
work_queue<ResultT>::work_queue(threadpool &tpool):
    m_tpool(tpool),
    m_waiter(tpool),
    m_stopped(false)
{}

template <typename ResultT>
void work_queue<ResultT>::push(std::function<ResultT()> &&job)
{
    {
        std::lock_guard lock(m_mutex);
        if (m_stopped)
            throw work_queue_stopped("work queue stopped: cannot push");
    }

    // Passing leaf=true to threadpool::submit() has the effect that jobs
    // execution is always deferred; in other words threadpool::submit() won't
    // ever block, but just add the job to it's internal queue to be ran by some
    // other thread. By contrast, if leaf=false, then sometimes the works skips
    // the queue and is run directly inside threadpool::submit(). We use
    // leaf=true because usually with a work queue you want to "stack" work.
    const bool leaf = true;

    m_tpool.submit(&m_waiter, [this, job = std::move(job)](){
        // quick out before expensive operation
        {
            std::lock_guard lock(this->m_mutex);
            if (this->m_stopped)
                return;
        }

        try
        {
            ResultT result = job();
            std::lock_guard lock(this->m_mutex);
            this->m_results.emplace_back(std::move(result));
            this->m_did_work_condition.notify_one();
        }
        catch (const std::exception &e)
        {
            MERROR("Exception in work queue, discarding result: " << e.what());
        }
        catch (...)
        {
            MERROR("Generic exception in work queue, discarding result");
        }
    },
    leaf);
}

template <typename ResultT>
void work_queue<ResultT>::push_value(ResultT &&val)
{
    std::lock_guard lock(m_mutex);
    m_results.emplace_back(std::forward<ResultT>(val));
    m_did_work_condition.notify_one();
}

template <typename ResultT>
ResultT work_queue<ResultT>::pull()
{
    std::unique_lock lock(m_mutex);
    while (m_results.empty())
    {
        if (m_stopped) // always check for m_stopped with mutex held, before waiting
            throw work_queue_stopped("work queue stopped: cannot pull");
        m_did_work_condition.wait(lock);
    }
    ResultT val = std::move(m_results.front());
    m_results.pop_front();
    m_did_work_condition.notify_one(); // let another guy pull
    return val;
}

template <typename ResultT>
std::optional<ResultT> work_queue<ResultT>::try_pull_non_blocking()
{
    // We don't check for m_stopped, which is fine because we immediately either
    // grab a value or exit.

    std::lock_guard lock(m_mutex);
    if (m_results.empty())
    {
        return std::nullopt;
    }
    else
    {
        ResultT val = std::move(m_results.front());
        m_results.pop_front();
        m_did_work_condition.notify_one(); // let another guy pull
        return val;
    }
}

template <typename ResultT>
void work_queue<ResultT>::stop()
{
    std::lock_guard lock(m_mutex);
    m_stopped = true;
    m_did_work_condition.notify_all();
}

template <typename ResultT>
bool work_queue<ResultT>::stopped()
{
    std::lock_guard lock(m_mutex);
    return m_stopped;
}

template <typename ResultT>
work_queue<ResultT>::~work_queue()
{
    try
    {
        // signal stop, wait for worker completion, and swallow exceptions
        stop();
        m_waiter.wait();
    }
    catch(...) {}
}

} //namespace tools

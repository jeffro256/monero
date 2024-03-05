// Copyright (c) 2024, The Monero Project
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

#include "gtest/gtest.h"

#include <condition_variable>
#include <cstdlib>
#include <mutex>
#include <shared_mutex>
#include <thread>

#include "common/recursive_shared_mutex.h"

TEST(recursive_shared_mutex, writer_starve_25_thread_90_duty)
{
    tools::recursive_shared_mutex rw_mutex;

    std::atomic<bool> run_workers{true};
    std::atomic<bool> writer_ran{false};
    std::condition_variable timeout_condition;

    std::vector<std::thread> workers;

    // 25 "reader" threads
    for (int i = 0; i < 25; ++i)
    {
        const double initial_wait_seconds = static_cast<double>(i) / 25;
        workers.push_back(std::thread([&rw_mutex, &run_workers, initial_wait_seconds](){
            // sleep a staggered amount of time to try to reduce open gaps in holding pattern
            std::this_thread::sleep_for(std::chrono::duration<double>(initial_wait_seconds));

            while (run_workers)
            {
                {
                    // shared lock held 90% of the time
                    std::shared_lock<tools::recursive_shared_mutex> sl(rw_mutex);
                    std::this_thread::sleep_for(std::chrono::duration<double>(0.9));
                }

                // shared lock unheld 10% of the time
                std::this_thread::sleep_for(std::chrono::duration<double>(0.1));
            }
        }));
    }

    // 1 "writer" thread
    workers.push_back(std::thread([&rw_mutex, &writer_ran, &timeout_condition](){
        // sleep for 2 seconds to give readers time to stagger
        std::this_thread::sleep_for(std::chrono::duration<double>(2.0f));

        // acquire exclusive ownership of the lock, set writer_ran, and wake main thread
        std::lock_guard<tools::recursive_shared_mutex> lg(rw_mutex);
        writer_ran = true;
        timeout_condition.notify_all();
    }));

    {
        std::mutex timeout_mutex;
        std::unique_lock<std::mutex> timeout_lock(timeout_mutex);
        timeout_condition.wait_for(timeout_lock, std::chrono::duration<double>(45.0f));
    }

    const bool res = writer_ran.load();

    run_workers = false;
    for (auto &w : workers)
        w.join();

    EXPECT_TRUE(res);
}

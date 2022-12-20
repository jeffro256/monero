// Copyright (c) 2022, The Monero Project
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

#include <cstdint>
#include <mutex>
#include <shared_mutex>

// Forward b/c rpc/core_rpc_server_commands_defs.h is a heavy header
namespace cryptonote { struct rpc_access_response_base; }

namespace tools
{
    class RpcPaymentState
    {
    public:
        using resp_base_t = cryptonote::rpc_access_response_base;

        class ticket_guard
        {
            ticket_guard(const ticket_guard&) = delete;

            RpcPaymentState& m_state_target;
            ticket_info m_ticket_info;
            std::shared_lock<std::shared_timed_mutex> m_shared_call_lock;

            friend class RpcPaymentState;

        public:
            ~ticket_guard();
        }; // class ticket_guard

        class payment_guard
        {
            payment_guard(const payment_guard&) = delete;

            RpcPaymentState& m_state_target;
            payment_info m_payment_info;
            std::unique_lock<std::shared_timed_mutex> m_exclusive_call_lock;

            friend class RpcPaymentState;

        public:
            ~payment_guard();
        }; // class payment_guard

        RpcPaymentState();

        ticket_guard start_rpc_call(const std::string& name, const uint64_t exp_cost);
        void end_rpc_call(const ticket_guard& tg, const resp_base_t& res);

        void update_expected_cost(const ticket_guard& tg, uint64_t new_exp_cost);

        payment_guard start_rpc_payment(const uint64_t exp_payment);
        int64_t end_rpc_payment(const payment_guard& pg, const resp_base_t& res);

        uint64_t credits() const;
        uint64_t discrepancy() const;
        void credit_report(uint64_t &expected_spent, uint64_t &discrepancy) const;

        bool stale() const;
        void set_fresh();

        void reset();

    private:
        struct ticket_info
        {
            std::string name;
            uint64_t expected_cost;
        };

        struct payment_info
        {
            uint64_t expected_payment;
        };

        void drop_ticket(const ticket_guard& tg);

        void check_for_discrepancies();

        bool update_from_response_info(const resp_base_t& res);

        void assert_exclusive_access();

        uint64_t m_last_settled_credits;
        uint64_t m_cumulative_discrepancy;
        uint64_t m_cumulative_expected_spent;

        uint64_t m_num_open_tickets;
        std::vector<ticket_info> m_unsettled_tickets;

        uint64_t m_last_reported_credits;
        std::string m_top_hash;
        bool m_stale;
        
        mutable std::mutex m_data_mutex;
        mutable std::shared_timed_mutex m_call_mutex;

        friend class ticket_guard;
    }; // class RpcPaymentState
} // namespace tools

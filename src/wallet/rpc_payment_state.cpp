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

#include "rpc_payment_state.h"
#include "rpc/core_rpc_server_commands_defs.h"

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "wallet.wallet2.rpc_payments" // same as wallet_rpc_payments.cpp

#ifdef __GNUC__
#define DBG_PREFIX __PRETTY_FUNCTION__
#else
#define DBG_PREFIX __func__
#endif

#define UPDATE_VAL_DBG(lval, newval) update_val_debug(DBG_PREFIX, #lval, lval, newval)
#define VAL_DBG(prefix, val) MDEBUG(DBG_PREFIX ": " #val "' = " << val)
#define UPDATE_VAL_DBG_INC(prefix, lval) update_val_debug(DBG_PREFIX, #lval, lval, lval + 1)
#define UPDATE_VAL_DBG_DEC_ASSERT_POS(lval)                                                     \
    do {                                                                                        \
        CHECK_AND_ASSERT_THROW_MES(lval, DBG_PREFIX " internal bug: " #lval "-- would be neg"); \
        update_val_debug(DBG_PREFIX, #lval, lval, lval - 1);                                    \
    } while (0);                                                                                \

#define DATA_CRIT_SECTION() const std::lock_guard<std::mutex> ll(m_data_mutex);
#define MOVE_ACTIVE_LOCK_INTO_SCOPE(l)                                                   \
    CHECK_AND_ASSERT_THROW_MES                                                           \
    (                                                                                    \
        l.owns(),                                                                        \
        DBG_PREFIX " incorrect usage or internal bug: <" << #l << "> does not own mutex" \
    );                                                                                   \
    decltype(l) moved_lock = std::move(l);                                               \

namespace
{
    // The number of concurrent tickets = number open tickets + number unsettled tickets.
    // This limit is arbitrary `\_(0_o)_/`
    static constexpr const size_t MAX_NUM_CONCURRENT_TICKETS = 256;

    static std::string build_suspect_list_str(const std::vector<tools::ticket_info>& ticket_infos)
    {
        std::string suspect_list = "[";
        bool first_suspect = true;
        for (const auto& ti : ticket_infos)
        {
            if (!first_suspect)
            {
                suspect_list += ", ";
            }
            suspect_list += "('" + ti.name + "' @ " + std::to_string(ti.expected_cost) + ")";
            first_suspect = false;
        }
        suspect_list += "]";
        return suspect_list;
    }

    template <typename T>
    void update_val_debug(const char* prefix, const char* l_val_str, T& l_val, const T& new_val)
    {
        if (l_val != new_val)
        {
            MDEBUG(prefix << ": updated '" << l_val_str << "' from " << l_val << " to " << new_val);
            l_val = new_val;
        }    
    }
}

namespace tools
{
    RpcPaymentState::RpcPaymentState()
    {
        reset();
    }

    ticket_guard RpcPaymentState::start_rpc_call(const std::string& name, const uint64_t exp_cost)
    {
        std::shared_lock<std::shared_timed_mutex> shared_call_lock(m_call_mutex);
        DATA_CRIT_SECTION()

        const size_t num_concurrent_tickets = m_num_open_tickets + m_unsettled_tickets.size();
        CHECK_AND_ASSERT_THROW_MES
        (
            num_concurrent_tickets <= MAX_NUM_CONCURRENT_TICKETS,
            "There are too many concurrent tickets right now"
        );

        UPDATE_VAL_DBG_INC(m_num_open_tickets);

        MDEBUG(DBG_PREFIX ": new call " << name << "' " << exp_cost);
        MDEBUG
        (
            "RpcPaymentState: " << m_num_open_tickets << " open tickets " <<
            m_unsetlled_tickets.size() << " unsettled tickets"
        );

        return {*this, {name, exp_cost}, std::move(shared_call_lock)};
    }

    void RpcPaymentState::end_rpc_call(const ticket_guard& tg, const resp_base_t& res)
    {
        DATA_CRIT_SECTION()
        MOVE_ACTIVE_LOCK_INTO_SCOPE(tg.m_shared_call_lock)

        UPDATE_VAL_DBG_DEC_ASSERT_POS(m_num_open_tickets);

        const bool successful_call = update_from_response_info(res);
        if (successful_call)
        {
            m_unsettled_tickets.push_back(std::move(tg.m_ticket_info));
        }

        check_for_discrepancies();
    }

    payment_guard RpcPaymentState::start_rpc_payment(const uint64_t exp_payment)
    {
        std::unique_lock<std::shared_timed_mutex> exc_call_lock(m_call_mutex);
        DATA_CRIT_SECTION()

        assert_exclusive_access();

        return {*this, {exp_payment}, std::move(exc_call_lock)};
    }

    int64_t RpcPaymentState::end_rpc_payment(const payment_guard& pg, const resp_base_t& res)
    {
        DATA_CRIT_SECTION()
        MOVE_ACTIVE_LOCK_INTO_SCOPE(tg.m_exclusive_call_lock)

        assert_exclusive_access();

        const uint64_t prepayment_credits = m_last_reported_credits;
        VAL_DBG(prepayment_credits);

        const bool successful_call = update_from_response_info(res);
        VAL_DBG(successful_call);
        if (!successful_call)
        {
            MWARNING("RPC call to make payment did not succeed, CPU cycles / funds may be wasted");
            return 0;
        }

        CHECK_AND_ASSERT_THROW_MES
        (
            m_last_reported_credits == res.credits,
            "internal bug: m_last_reported_credits did not update after successful RPC call"
        );

        UPDATE_VAL_DBG(m_last_settled_credits, m_last_reported_credits);

        const bool balanced_dropped = m_last_reported_credits < prepayment_credits;
        VAL_DBG(balance_dropped);
        if (balance_dropped)
        {
            const int64_t balance_drop = prepayment_credits - m_last_reported_credits;
            MWARNING(DBG_PREFIX ": credits decliend by " << balance_drop << " during RPC payment");
            return -balance_drop;
        }

        const uint64_t expected_payment = pg.m_ticket_info.expected_payment;
        VAL_DBG(expected_payment);

        const uint64_t actual_payment = m_last_reported_credits - prepayment_credits;
        VAL_DBG(actual_payment);

        const uint64_t min_expected_credits = prepayment_credits + expected_payment;
        VAL_DBG(min_expected_credits);

        const bool discrepancy_found = m_last_reported_credits < min_expected_credits;
        VAL_DBG(discrepancy_found);
        if (discrepancy_found)
        {
            const uint64_t discrepancy = min_expected_credits - m_last_reported_credits;

            CHECK_AND_ASSERT_THROW_MES
            (
                discrepancy == expected_payment - actual_payment,
                "internal bug: payment discrepancy == " << discrepancy <<
                " vs expected - actual payment == " << (expected_payment - actual_payment)
            );

            MWARNING(DBG_PREFIX ": payment discrepancy found. Expected payment " << expected_payment
            << " vs actual payment " << actual_payment << " for a discrepancy of " << discrepancy);

            UPDATE_VAL_DBG(m_cumulative_discrepancy, m_cumulative_discrepancy + discrepancy);
        }

        return actual_payment;
    }

    void RpcPaymentState::update_expected_cost(const ticket_guard& tg, const uint64_t new_exp_cost)
    {
        tg.m_ticket_info.expected_cost = new_exp_cost;
    }

    uint64_t RpcPaymentState::credits() const
    {
        DATA_CRIT_SECTION()
        return m_last_reported_credits;
    }

    uint64_t RpcPaymentState::discrepancy() const
    {
        DATA_CRIT_SECTION()
        return m_cumulative_discrepancy;
    }

    void RpcPaymentState::credit_report(uint64_t &expected_spent, uint64_t &discrepancy) const
    {
        DATA_CRIT_SECTION()
        expected_spent = m_cumulative_expected_spent;
        discrepancy = m_cumulative_discrepancy;
    }

    bool RpcPaymentState::stale() const
    {
        DATA_CRIT_SECTION()
        return m_stale;
    }

    void RpcPaymentState::set_fresh()
    {
        DATA_CRIT_SECTION()
        m_stale = false;
    }

    void RpcPaymentState::reset()
    {
        // First wait until no payments are being made and all tickets are settled
        std::unique_lock<std::shared_timed_mutex> exclusive_lock(m_call_mutex);

        DATA_CRIT_SECTION()

        assert_exclusive_access();

        m_last_settled_credits = 0;
        m_cumulative_discrepancy = 0;
        m_cumulative_expected_spent = 0;

        m_num_open_tickets = 0;
        m_unsettled_tickets.clear();

        m_last_reported_credits = 0;
        m_top_hash = "";
        m_stale = true;
    }

    void RpcPaymentState::drop_ticket(const ticket_guard& tg)
    {
        DATA_CRIT_SECTION()

        if (!tg.m_shared_call_lock.owns())
        {
            // end_rpc_call was already called on this guard: good
            return;
        }

        UPDATE_VAL_DBG_DEC_ASSERT_POS("drop_ticket", m_num_open_tickets);

        const std::string& name = tg.m_ticket_info.name;
        MWARNING("Incorrect usage of start/end_rpc_call: '" << name << "' has no closer");

        check_for_discrepancies();
    }

    void RpcPaymentState::check_for_discrepancies()
    {
        if (m_num_open_tickets)
        {
            MDEBUG(DBG_PREFIX ": there are still open tickets, ending check...");
            return;
        }

        MDEBUG(DBG_PREFIX ": there are no open tickets, checking for discrepancies.");

        uint64_t cumul_exp_cost = 0;
        for (const ticket_info& ti : m_unsettled_tickets)
        {
            cumul_exp_cost += ti.expected_cost;
        }

        VAL_DBG(cumul_exp_cost);

        const uint64_t new_cumul_exp_spent = m_cumulative_expected_spent + cumul_exp_cost;
        UPDATE_VAL_DBG(m_cumulative_expected_spent, new_cumul_exp_spent);

        const bool overdrawn = cumul_exp_cost > m_last_settled_credits;
        const uint64_t min_exp_credits = overdrawn ? 0 : m_last_settled_credits - cumul_exp_cost;
        VAL_DBG(overdrawn);
        VAL_DBG(min_exp_credits);

        const bool discrep_exists = m_last_reported_credits < min_exp_credits;
        if (discrep_exists)
        {
            const uint64_t discrep = min_exp_credits - m_last_reported_credits;

            MWARNING(DBG_PREFIX ": discrepancy was found. Expected " << min_exp_credits
                << " vs actual " << m_last_reported_credits << ". discrep = " << discrep);

            const bool had_unsettled_tickets = !m_unsettled_tickets.empty();
            if (had_unsettled_tickets)
            {
                const std::string suspect_list_str = build_suspect_list_str(m_unsettled_tickets);
                MWARNING(DBG_PREFIX ": overcharging suspect(s) are one/some of "
                    << suspect_list_str);
            }
            else
            {
                MWARNING(DBG_PREFIX ": overcharge occurred with 0 unsettled tickets.");
            }

            const uint64_t new_cumul_discrep = m_cumulative_discrepancy + discrep;
            UPDATE_VAL_DBG(m_cumulative_discrepancy, new_cumul_discrep);
        }
        else
        {
            MDEBUG(DBG_PREFIX ": no discrepancy found. Yay!");
        }

        UPDATE_VAL_DBG(m_last_settled_credits, m_last_reported_credits);
        m_unsettled_tickets.clear();
    }

    bool RpcPaymentState::update_from_response_info(const resp_base_t& res)
    {
        const bool successful_call = res.status == CORE_RPC_STATUS_OK;
        if (successful_call || res.status == CORE_RPC_STATUS_PAYMENT_REQUIRED)
        {
            UPDATE_VAL_DBG(m_last_reported_credits, res.credits);
        }

        if (res.top_hash && res.top_hash != m_top_hash)
        {
            UPDATE_VAL_DBG(m_top_hash, res.top_hash);
            UPDATE_VAL_DBG(m_stale, true);
        }

        return successful_call;
    }

    void RpcPaymentState::assert_exclusive_access()
    {
        CHECK_AND_ASSERT_THROW_MES
        (
            m_num_open_tickets == 0,
            "internal bug: there are " << m_num_open_tickets << " tickets open during payment"
        );

        CHECK_AND_ASSERT_THROW_MES
        (
            m_unsettled_tickets.empty(),
            "internal bug:" << m_unsettled_tickets.size() << " tickets are unsettled during payment"
        );
    }
} // namespace rpc

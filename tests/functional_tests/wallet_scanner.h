// Copyright (c) 2014-2024, The Monero Project
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
// 
// Parts of this file are originally copyright (c) 2012-2013 The Cryptonote developers

//local headers
#include "async/mutex.h"
#include "common/rpc_client.h"
#include "crypto/hash.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "seraphis_main/scan_machine_types.h"
#include "seraphis_mocks/mock_http_client_pool.h"
#include "seraphis_mocks/scan_context_async_mock.h"
#include "wallet/wallet2.h"

//third party headers
#include <boost/multiprecision/cpp_int.hpp>

//standard headers
#include <memory>
#include <string>
#include <thread>

//forward declarations
namespace test { class ConnectionPoolWrapper; };


namespace test
{
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
struct ExpectedScanResults final
{
    std::uint64_t sendr_expected_balance;
    std::uint64_t recvr_expected_balance;
    crypto::hash  tx_hash;
    std::uint64_t transfer_amount;
};
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
struct SpTestScanConfig final
{
    sp::scanning::ScanMachineConfig                   scan_machine_config;
    sp::scanning::mocks::AsyncScanContextLegacyConfig scan_context_config;
};
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
class WalletScannerTest final
{
    friend class ConnectionPoolWrapper;
public:
//constructor
    WalletScannerTest(const std::string &daemon_addr);

    /// disable copy/move (this is a scoped manager [reference wrapper])
    WalletScannerTest& operator=(WalletScannerTest&&) = delete;

    /// Run the suite of wallet scanner tests
    bool run();
private:
//tests
    void check_normal_transfer();
    void check_sweep_single();
    void check_subaddress_transfer();
    void check_multiple_subaddresses_transfer();

//test helpers
    ExpectedScanResults init_normal_transfer_test();
    ExpectedScanResults init_sweep_single_test();
    ExpectedScanResults init_subaddress_transfer_test();
    ExpectedScanResults init_multiple_subaddresses_test();

    /// Make sure the wallet2 scanner yields expected results
    void check_wallet2_scan(const ExpectedScanResults &res);

    /// Make sure the Seraphis scanner yields expected results
    void check_seraphis_scan(const ExpectedScanResults &res);

    /// Use the Seraphis lib to scan the chain and return wallet balance
    boost::multiprecision::uint128_t sp_scan_chain(const std::size_t wallet_idx, const SpTestScanConfig &config);

//utility helper functions
    void reset();
    void mine(const std::size_t wallet_idx, const std::uint64_t num_blocks);
    std::uint64_t mine_tx(const crypto::hash &tx_hash, const std::string &miner_addr_str);
    void transfer(const std::size_t wallet_idx,
        const cryptonote::account_public_address &dest_addr,
        const bool is_subaddress,
        const std::uint64_t amount_to_transfer,
        cryptonote::transaction &tx_out);

//accessors to resources
    std::unique_ptr<tools::t_daemon_rpc_client> &daemon()
    {
        CHECK_AND_ASSERT_THROW_MES(m_daemon_mutex.thread_owns_lock(), "thread does not own daemon mutex");
        return m_daemon;
    };

    std::unique_ptr<tools::wallet2> &wallet(const std::size_t idx)
    {
        CHECK_AND_ASSERT_THROW_MES(m_wallets_mutex.thread_owns_lock(), "thread does not own wallets mutex");
        CHECK_AND_ASSERT_THROW_MES(idx <= m_wallets.size(), "too high wallet idx");
        return m_wallets[idx];
    };

    std::unique_ptr<sp::mocks::ClientConnectionPool> &conn_pool(const std::thread::id thread_id)
    {
        CHECK_AND_ASSERT_THROW_MES(m_conn_pool_mutex.thread_owns_lock(thread_id),
            "thread does not own connection pool mutex");
        return m_conn_pool;
    };

private:
//member variables
    const std::string &m_daemon_addr;

    // Resources that are expected to be accessed through the accessor functions above
    std::unique_ptr<tools::t_daemon_rpc_client>      m_daemon;
    std::vector<std::unique_ptr<tools::wallet2>>     m_wallets;
    std::unique_ptr<sp::mocks::ClientConnectionPool> m_conn_pool;

    // Mutexes for resources
    async::Mutex m_wallets_mutex;
    async::Mutex m_daemon_mutex;
    async::Mutex m_conn_pool_mutex;
};
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
class ConnectionPoolWrapper final
{
public:
    ConnectionPoolWrapper(WalletScannerTest &wst):
        m_wst(wst),
        m_thread_owner_id(std::this_thread::get_id())
    {
        m_wst.m_conn_pool_mutex.lock();
    };

    /// disable copy/move (this is a scoped manager [reference wrapper])
    ConnectionPoolWrapper& operator=(ConnectionPoolWrapper&&) = delete;

    ~ConnectionPoolWrapper()
    {
        // Close all open connections but 1, so that we keep a connection open for future RPC calls
        m_wst.conn_pool(m_thread_owner_id)->close_connections(1);
        m_wst.m_conn_pool_mutex.unlock();
    };

    std::unique_ptr<sp::mocks::ClientConnectionPool> &conn_pool()
    {
        return m_wst.conn_pool(m_thread_owner_id);
    };
private:
    WalletScannerTest &m_wst;
    const std::thread::id m_thread_owner_id;
};
//-------------------------------------------------------------------------------------------------------------------
}; // test

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

// NOT FOR PRODUCTION
// TODO for production-ready:
// 1. Implement close_connections.
// 2. Require the pool respect max_connections.

#pragma once

//local headers
#include "misc_language.h"
#include "net/http.h"
#include "net/http_client.h"
#include "rpc/core_rpc_server_commands_defs.h"
#include "storages/http_abstract_invoke.h"

//third party headers

//standard headers
#include <mutex>
#include <string>
#include <vector>

//forward declarations


namespace sp
{
namespace mocks
{
////
// ClientConnectionPool
// - wraps a pool of network client connections to enable concurrent requests
///
class ClientConnectionPool
{
public:
//constructors
    ClientConnectionPool(
        const std::string &daemon_address,
        const boost::optional<epee::net_utils::http::login> daemon_login = boost::none,
        const epee::net_utils::ssl_options_t ssl_support = epee::net_utils::ssl_support_t::e_ssl_support_autodetect,
        const std::string &proxy = "",
        const std::size_t max_connections = 20):
            m_daemon_address{daemon_address},
            m_daemon_login{daemon_login},
            m_ssl_support(ssl_support),
            m_proxy{proxy},
            m_max_connections{max_connections}
    {
        m_http_client_pool.reserve(max_connections);
    }

    ~ClientConnectionPool()
    {
        this->close_connections();
    }

//member functions
    enum http_mode { JSON, BIN, JSON_RPC };

    /// Use an http client from the pool to make an RPC request to the daemon
    template <typename COMMAND_TYPE>
    bool rpc_command(const http_mode &mode,
        const std::string &command_name,
        const typename COMMAND_TYPE::request &req,
        typename COMMAND_TYPE::response &res)
    {
        // Acquire an http client from the connection pool
        std::size_t http_client_index = this->acquire_unused_http_client();
        CHECK_AND_ASSERT_THROW_MES(m_http_client_pool.size() > http_client_index, "http client index is too high");
        auto scope_exit_handler = epee::misc_utils::create_scope_leave_handler([this, http_client_index]{
            this->release_http_client(http_client_index);
        });

        // Do the RPC command
        LOG_PRINT_L2("Invoking " << command_name << " with http client " << http_client_index);
        pool_http_client_t &http_client = m_http_client_pool[http_client_index];
        switch (mode)
        {
            case BIN: return epee::net_utils::invoke_http_bin(command_name, req, res, *http_client.http_client);
            case JSON: return epee::net_utils::invoke_http_json(command_name, req, res, *http_client.http_client);
            case JSON_RPC: return epee::net_utils::invoke_http_json_rpc("/json_rpc", command_name, req, res, *http_client.http_client);
            default: { MERROR("Unknown http_mode: " << mode); return false; }
        }
    }

    /**
    * brief: *close_connections* - close connections except num specified
    * param: max_keep_alive - the max number of connections to keep alive (0 means close all)
    */
    // TODO: implement
    void close_connections(const std::size_t max_keep_alive = 0) { /* no-op */ };

private:
    /// If an http client is available, acquires it. If none are available, initializes a new http client.
    std::size_t acquire_unused_http_client();

    /// Make http client available for use again.
    void release_http_client(std::size_t http_client_index);

//member variables
private:
    const std::string m_daemon_address;
    const boost::optional<epee::net_utils::http::login> m_daemon_login;
    const epee::net_utils::ssl_options_t m_ssl_support;
    const std::string m_proxy;

    const std::size_t m_max_connections;

    struct pool_http_client_t {
        bool in_use;
        std::unique_ptr<epee::net_utils::http::abstract_http_client> http_client;
    };

    // TODO: investigate possibility of removing the need for this internal mutex and avoid lock contention
    mutable std::mutex m_http_client_pool_mutex;
    mutable std::vector<pool_http_client_t> m_http_client_pool;
};
} //namespace mocks
} //namespace sp

// Copyright (c) 2023, The Monero Project
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

#include "http.h"

#define MULTIHOST_PUNISHMENT_TIMEOUT 10
#define MULTIHOST_PUNISHMENT_RESOLVE_FAIL 15
#define MULTIHOST_PUNISHMENT_NO_ENDPOINTS 50

namespace net
{
namespace http
{
struct multihost_peer_entry
{
    std::string host;
    std::string port;
    std::string ssl_fingerprint;

    bool operator==(const multihost_peer_entry&) const;
};

class multihost_client : public client
{
public:
    using host_switch_cb_t = std::function<void()>;

    multihost_client(const std::vector<multihost_peer_entry>& root_peers);

    bool set_proxy(const std::string& address) override;

    void set_server
    (
        std::string host,
        std::string port,
        boost::optional<epee::net_utils::http::login> user, 
        epee::net_utils::ssl_options_t ssl_options = epee::net_utils::ssl_support_t::e_ssl_support_autodetect,
        const std::string& virtual_host = {}
    ) override;

    bool invoke
    (
        const boost::string_ref uri,
        const boost::string_ref method,
        const boost::string_ref body,
        std::chrono::milliseconds timeout,
        const epee::net_utils::http::http_response_info** ppresponse_info = NULL,
        const epee::net_utils::http::fields_list& additional_params = epee::net_utils::http::fields_list()
    ) override;

    void set_host_switch_callback(std::unique_ptr<host_switch_cb_t>&& cb);

    void punish_last_endpoint(int64_t punishment);

private:
    struct peer_entry_sortable: public multihost_peer_entry
    {
        int64_t punishment_received;
        int weak_randomness; // doesn't need to be secure, just random enough for load balancing
        epee::net_utils::ssl_options_t ssl_options;

        peer_entry_sortable(const multihost_peer_entry&);

        bool operator<(const peer_entry_sortable& rhs) const;
    };

    struct root_peer_entry: public peer_entry_sortable
    {
        std::multiset<peer_entry_sortable> endpoints;
        std::chrono::steady_clock::time_point last_fetch_time;
        int64_t cached_punishment;

        root_peer_entry(const multihost_peer_entry&);

        bool operator<(const root_peer_entry& rhs) const;
    };

    bool find_next_potential_endpoint(size_t invoke_attempt);

    std::multiset<root_peer_entry> m_root_peers;

    std::unique_ptr<host_switch_cb_t> m_host_switch_cb;

    std::string m_last_host;
    std::string m_last_port;

    client m_auxilliary_internal_client;
};
} // namespace http
} // namespace net

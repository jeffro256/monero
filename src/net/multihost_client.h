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

#include <boost/multi_index_container.hpp>
#include <boost/multi_index/identity.hpp>
#include <boost/multi_index/ordered_index.hpp>
#include <boost/multi_index/tag.hpp>

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

    bool operator==(const multihost_peer_entry& rhs) const;
};

////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////

namespace detail
{
struct by_address
{
    bool operator()(const multihost_peer_entry&, const multihost_peer_entry&) const;
};

struct peer_entry_sortable: public multihost_peer_entry
{
    int64_t punishment_received;
    int weak_randomness; // doesn't need to be secure, just random enough for load balancing
    epee::net_utils::ssl_options_t ssl_options;

    peer_entry_sortable(const multihost_peer_entry&);

    bool operator==(const peer_entry_sortable& rhs) const;
};

struct endpoint_peer_entry: public peer_entry_sortable
{
    // These fields help enforce that 2+ roots do not vouch for one endpoint
    std::string root_owner_host;
    std::string root_owner_port;

    endpoint_peer_entry(const multihost_peer_entry&, const std::string&, const std::string&);
};

struct by_endpoint_punishment_nd // non-deterministic, takes weak randomness into account
{
    bool operator()(const endpoint_peer_entry&, const ebdpoint_peer_entry&) const;
};

// Container which can lookup endpoint information by address or by punishment received
typedef boost::multi_index_container
<
    endpoint_peer_entry,
    boost::multi_index::indexed_by
    <
        boost::multi_index::ordered_unique
        <
            boost::multi_index::tag<by_address>,
            boost::multi_index::identity<endpoint_peer_entry>,
            by_address
        >,
        boost::multi_index::ordered_non_unique
        <
            boost::multi_index::tag<by_endpoint_punishment_nd>,
            boost::multi_index::identity<endpoint_peer_entry>,
            by_endpoint_punishment_nd
        >
    >
> endpoint_cont_t;

struct root_peer_entry: public peer_entry_sortable
{
    std::multiset<peer_entry_sortable> endpoints;
    std::chrono::steady_clock::time_point last_fetch_time;
    int64_t cached_punishment;

    root_peer_entry(const multihost_peer_entry&);

    bool are_endpoints_stale() const;
};

struct by_root_punishment_nd // non-deterministic, takes weak randomness into account
{
    bool operator()(const root_peer_entry&, const root_peer_entry&) const;
};

typedef std::multiset<root_peer_entry, by_root_punishment_nd> root_cont_t;
} // namespace detail

////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////

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
        epee::net_utils::ssl_options_t ssl_options = epee::net_utils::ssl_support_t::e_ssl_support_autodetect
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
    const peer_entry_sortable* find_next_potential_endpoint(size_t invoke_attempt);

    detail::root_cont_t m_roots;
    detail::endpoint_cont_t m_endpoints;

    multihost_peer_entry m_last_endpoint;
    std::unique_ptr<host_switch_cb_t> m_host_switch_cb;

    client m_auxilliary_internal_client;
};
} // namespace http
} // namespace net

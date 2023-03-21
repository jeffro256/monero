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

#include "common/dns_utils.h"
#include "common/expect.h"
#include "error.h"
#include "multihost_client.h"
#include "parse.h"
#include "rpc/core_rpc_server_commands_defs.h"

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "net.http"

#define MULTIHOST_PUNISHMENT_UNSET 1
#define MULTIHOST_PUNISHMENT_FRESH 0

using epee::net_utils::ssl_options_t;
using epee::net_utils::ssl_support_t;
using std::chrono::steady_clock::duration;
using std::chrono::steady_clock::time_point;

namespace
{
static constexpr size_t MAX_INVOKE_ATTEMPTS = 10;
static constexpr size_t MAX_ENDPOINTS_PER_ROOT = 100;
static constexpr time_point NEVER_REFRESHED = std::numeric_limits<time_point::rep>::min();
static constexpr duration ENDPOINT_REFRESH_DELAY = std::chrono::minutes(30);

ssl_options_t ssl_options_from_fingerprint(const std::string& ssl_fingerprint)
{
    if (ssl_fingerprint.empty())
    {
        return ssl_options_t(ssl_support_t::e_ssl_support_enabled);
    }
    else
    {
        std::vector<std::uint8_t> fp_bytes(32, 0);
        const bool dcoded = epee::from_hex::to_buffer(epee::to_mut_span(fp_bytes), ssl_fingerprint);
        CHECK_AND_ASSERT_THROW_MES(dcoded, "Failed to decode SSL cert SHA-256 fingerprint as hex");
        return ssl_options_t({fp_bytes}, {});
    }
}
} // anonymous namespace

namespace net
{
namespace http
{
multihost_client::multihost_client(const std::vector<multihost_peer_entry>& root_peers)
    : m_root_peers()
    , m_host_switch_cb()
    , m_last_host()
    , m_last_port()
    , m_auxilliary_internal_client()
{
    CHECK_AND_ASSERT_THROW_MES(root_peers.size(), "Invalid argument: root_peers must be non-empty");

    // Seed the C pseudo-random number generator
    const unsigned int randval = static_cast<unsigned int>(std::rand());
    const auto steady_elap = std::chrono::steady_clock::now().time_since_epoch();
    using target_duration_t = std::chrono::duration<unsigned int, std::milli>;
    const auto steady_millis = std::chrono::duration_cast<target_duration_t>(steady_elap).count();
    std::srand(randval + steady_millis);

    // Construct root peer set
    for (const multihost_peer_entry& peer_entry: root_peers)
    {
        m_root_peers.emplace(peer_entry);
    }
}

bool multihost_client::set_proxy(const std::string& address)
{
    // Proxy should be attempted to be set for both ourself and internal client even if other fails
    const bool this_set_proxy = client::set_proxy(address);
    const bool internal_set_proxy = m_auxilliary_internal_client.set_proxy(address);
    return this_set_proxy && internal_set_proxy;
}

void multihost_client::set_server
(
    std::string host,
    std::string port,
    boost::optional<epee::net_utils::http::login> user, 
    epee::net_utils::ssl_options_t ssl_options/* = ssl_support_t::e_ssl_support_autodetect*/
)
{
    throw std::logic_error("multihost_client ignores set_server()");
}

bool multihost_client::invoke
(
    const boost::string_ref uri,
    const boost::string_ref method,
    const boost::string_ref body,
    std::chrono::milliseconds timeout,
    const epee::net_utils::http::http_response_info** ppresp/* = NULL*/,
    const epee::net_utils::http::fields_list& add_params/* = fields_list()*/
)
{
    for (size_t i = 0; i < MAX_INVOKE_ATTEMPTS; ++i)
    {
        const peer_entry_sortable* next_endpoint = nullptr;
        if (nullptr == (next_endpoint = find_next_potential_endpoint(i)))
        {
            MERROR("Zero multihost endpoints were available. Try checking network connection...");
            return false;
        }

        const std::string& virt_host = next_endpoint->host;
        const std::string& port = next_endpoint->port;
        const ssl_options_t& ssl_options = next_endpoint->ssl_options;

        client::set_server(virt_host, port, boost::none, ssl_options);

        // Invoke
        const bool inv_success = client::invoke(uri, method, body, timeout, ppresp, add_params);
        if (!inv_success)
        {
            punish_last_endpoint(MULTIHOST_PUNISHMENT_TIMEOUT);
            continue;
        }

        // Call host switch callback and update m_last_* fields if address changed
        const bool changed = m_last_host != virt_host || m_last_port != port;
        if (changed)
        {
            m_last_host = virt_host;
            m_last_port = port;

            if (m_host_switch_cb)
            {
                MDEBUG("Calling host switch callback");
                (*m_host_switch_cb)();
            }
        }

        return true;
    }

    MERROR("Could not perform multihost invoke after " << MAX_INVOKE_ATTEMPTS << " attempts");
    return false;
}

const multihost_client::peer_entry_sortable* multihost_client::find_next_potential_endpoint
(
    size_t invoke_attempt
)
{
    const auto root_begin  
    for (const auto& root_peer : m_root_peers)
    {
        
    }

    return nullptr;
}

multihost_client::peer_entry_sortable::peer_entry_sortable(const multihost_peer_entry& pe)
    : multihost_peer_entry(pe)
    , punishment_received(MULTIHOST_PUNISHMENT_UNSET)
    , weak_randomness(std::rand())
    , ssl_options(ssl_options_from_fingerprint(ssl_fingerprint))
{}

bool multihost_client::peer_entry_sortable::operator<(const peer_entry_sortable& rhs) const
{
    return punishment_received < rhs.punishment_received || weak_randomness < rhs.weak_randomness;
}

multihost_client::root_peer_entry::root_peer_entry(const multihost_peer_entry& pe)
    : peer_entry_sortable(pe)
    , endpoints()
    , last_fetch_time()
    , cached_punishment(MULTIHOST_PUNISHMENT_UNSET)
{}

bool multihost_client::root_peer_entry::operator<(const root_peer_entry& rhs) const
{
    return cached_punishment < rhs.cached_punishment || weak_randomness < rhs.weak_randomness;
}

bool multihost_client::root_peer_entry::are_endpoints_stale() const
{
    const auto time_since_fetch = std::chrono::steady_clock::now() - last_fetch_time;
    return time_since_fetch > ENDPOINT_REFRESH_DELAY;
}
} // namespace http
} // namespace net

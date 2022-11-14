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

namespace
{
static constexpr const size_t MAX_INVOKE_ATTEMPTS = 10; 

expect<std::string> secure_resolve_anything(const std::string& virt_host)
{
    // Return quickly if provided raw IPv4 / IPv6 / Tor / i2p address
    if (net::get_network_address(virt_host, 0))
    {
        return {virt_host};
    }
    
    tools::DNSResolver& resolver = tools::DNSResolver::instance();

    // Attempt IPv6 resolution first
    bool dnssec_avail_6 = false;
    bool dnssec_valid_6 = false;        
    std::vector<std::string> ips_6 = resolver.get_ipv6(virt_host, dnssec_avail_6, dnssec_valid_6);
    if (ips_6.size() && dnssec_avail_6 && dnssec_valid_6)
    {
        return {ips_6[0]};
    }

    // Attempt IPv4 resolution next
    bool dnssec_avail_4 = false;
    bool dnssec_valid_4 = false;        
    std::vector<std::string> ips_4 = resolver.get_ipv6(virt_host, dnssec_avail_4, dnssec_valid_4);
    if (ips_4.size() && dnssec_avail_4 && dnssec_valid_4)
    {
        return {ips_4[0]};
    }

    // Log descriptive messages about failure
    if (ips_6.size())
    {
        if (!dnssec_avail_6)
        {
            MERROR("Error resolving address '" << virt_host << "': IPv6 DNSSEC unavailable");
        }
        else if (!dnssec_valid_6)
        {
            MERROR("Error resolving address '" << virt_host << "': IPv6 DNSSEC invalid");
        }
    }
    else if (ips_4.size())
    {
        if (!dnssec_avail_6)
        {
            MERROR("Error resolving address '" << virt_host << "': IPv4 DNSSEC unavailable");
        }
        else if (!dnssec_valid_6)
        {
            MERROR("Error resolving address '" << virt_host << "': IPv4 DNSSEC invalid");
        }
    }
    else
    {
        MERROR("Error resolving address '" << virt_host << "': no records available");
    }
    
    return make_error_code(net::error::dns_query_failure);
}
} // anonymous namespace

namespace net
{
namespace http
{
bool multihost_peer_entry::operator==(const multihost_peer_entry& rhs) const
{
    return host == rhs.host && port == rhs.port && ssl_fingerprint == rhs.ssl_fingerprint;
}

multihost_client::multihost_client(const std::vector<multihost_peer_entry>& root_peers)
    : m_root_peers()
    , m_host_switch_cb()
    , m_last_host()
    , m_last_port()
    , m_auxilliary_internal_client()
{
    // Seed the C pseudo-random number generator
    const unsigned int randval = static_cast<unsigned int>(std::rand());
    const auto steady_ep_time = std::chrono::steady_clock::now().time_since_epoch();
    const auto steady_millis = std::chrono::duration_cast<unsigned int, std::milli>(steady_ep_time);
    std::srand(randval + steady_millis.count());

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
    epee::net_utils::ssl_options_t ssl_options/* = ssl_support_t::e_ssl_support_autodetect*/,
    const std::string& virtual_host/* = {}*/
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
    const epee::net_utils::http::http_response_info** ppresponse_info/* = NULL*/,
    const epee::net_utils::http::fields_list& additional_params/* = fields_list()*/
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
        const epee::net_utils::ssl_options_t& ssl_options = next_endpoint->ssl_options;

        // Resolve virtual host
        const auto resolved_host = secure_resolve_anything(virt_host);
        if (!resolved_host)
        {
            MDEBUG("Resolving host '" << virt_host << "' failed, continuing multihost invoke...");
            punish_last_endpoint(MULTIHOST_PUNISHMENT_RESOLVE_FAIL);
            continue;
        }

        client::set_server(*resolved_host, port, boost::none, ssl_options, virt_host);

        // Invoke
        const bool inv_success = client::invoke(uri, method, body, timeout, ppresponse_info, additional_params);
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

multihost_client::peer_entry_sortable::peer_entry_sortable(const multihost_peer_entry& pe)
    : multihost_peer_entry(pe)
    , punishment_received(0)
    , weak_randomness(std::rand())
{}

bool multihost_client::peer_entry_sortable::operator<(const peer_entry_sortable& rhs) const
{
    return punishment_received < rhs.punishment_received || weak_randomness < rhs.weak_randomness;
}

multihost_client::root_peer_entry::root_peer_entry(const multihost_peer_entry& pe)
    : peer_entry_sortable(pe)
    , endpoints()
    , last_fetch_time(0)
    , cached_punishment()
{}

bool multihost_client::root_peer_entry::operator<(const root_peer_entry& rhs) const
{
    return cached_punishment < rhs.cached_punishment || weak_randomness < rhs.weak_randomness;
}
} // namespace http
} // namespace net

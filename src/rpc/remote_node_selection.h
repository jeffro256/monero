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

#include <limits>
#include <mutex>
#include <set>

#include "net/http_client.h"
#include "net/net_utils_base.h"
#include "net/net_ssl.h"

namespace rpc
{
namespace remote_selection
{
using ssl_context_ptr_t = std::shared_ptr<boost::asio::ssl::context>;

static constexpr size_t const MAX_NUM_ROOTS = 256;
static constexpr size_t const MAX_NUM_FRIENDS_PER_ROOT = 2048;

struct AbstractNodeGroup
{
    using network_address_t = epee::net_utils::network_address;
    using punishment_t = long;
    using node_id_t = uint32_t;

    enum class Punishment: punishment_t
    {
        White = 0,
        Gray = 10,
        Timeout = 11,
        None = std::numeric_limits<punishment_t>::max(),
    };

    struct connection_info
    {
        node_id_t node_id;
        network_address_t addr;
        std::unique_ptr<epee::net_utils::http::login> credentials;
        ssl_context_ptr_t ssl_ctx;
    };

    virtual ~AbstractNodeGroup() = default;

    virtual node_id_t id() const noexcept = 0;

    virtual punishment_t average_punishments() const noexcept = 0;
    virtual void punish(node_id_t punishee, Punishment punishment) = 0;

    virtual connection_info yield_address(bool allow_resolve, bool resolve_ipv6) = 0;

    static bool compare_punishment(const AbstractNodeGroup& lhs, const AbstractNodeGroup& rhs) noexcept;
    bool has_punishment() const noexcept;
    bool operator<(const AbstractNodeGroup& rhs) const;
};

struct node_blueprint
{
    const std::string template_address;
    const AbstractNodeGroup::node_id_t node_id;
};

class AliveNode: public node_blueprint, public AbstractNodeGroup
{
    epee::net_utils::network_address m_resolved_address;
    uint64_t m_last_resolve_time;
    punishment_t m_punish_score;

public:
    AliveNode(const node_blueprint& blueprint);

    node_id_t id() const noexcept override final;
    punishment_t average_punishments() const noexcept override final;
    void punish(node_id_t punishee, Punishment punishment) override final;
    connection_info yield_address(bool allow_resolve, bool resolve_ipv6) override final;
};

class NodeFamily: AbstractNodeGroup
{
    AliveNode m_root;
    std::multiset<AliveNode> m_relatives;
    uint64_t m_last_relatives_fetch_time;

public:
    NodeFamily(const AliveNode& root);

    AbstractNodeGroup::node_id_t family_id() const;

    node_id_t id() const noexcept override final;
    punishment_t average_punishments() const noexcept override final;
    void punish(node_id_t punishee, Punishment punishment) override final;
    connection_info yield_address(bool allow_resolve, bool resolve_ipv6) override final;
};

class NodeSelector: AbstractNodeGroup
{
    std::multiset<std::unique_ptr<AbstractNodeGroup>> m_groups;

public:
    node_id_t id() const noexcept override final;
    punishment_t average_punishments() const noexcept override final;
    void punish(node_id_t punishee, Punishment punishment) override final;
    connection_info yield_address(bool allow_resolve, bool resolve_ipv6) override final;
};

template <class BaseANG>
class LockedAbstractNodeGroup: public BaseANG
{
    std::mutex m_mutex; // warning: not recursive!

    static_assert(std::is_base_of<AbstractNodeGroup, BaseANG>(), "Base class not AbstractNodeGroup");

public:
    node_id_t id() const noexcept override final;
    punishment_t average_punishments() const noexcept override final;
    void punish(node_id_t punishee, Punishment punishment) override final;
    connection_info yield_address(bool allow_resolve, bool resolve_ipv6) override final;
};

} // namespace remote_selection
} // namespace rpc

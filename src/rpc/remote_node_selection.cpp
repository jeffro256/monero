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

#include "community_node.h"

namespace
{
    using namespace rpc::remote_selection;

    AbstractNodeGroup::punishment_t pconv(AbstractNodeGroup::Punishment punishment)
    {
        return static_cast<AbstractNodeGroup::punishment_t>(punishment);
    }
} // anonymous namespace

namespace rpc
{
namespace remote_selection
{
    AliveNode::AliveNode(const node_blueprint& blueprint):
        node_blueprint(blueprint), m_resolved_address(), m_last_resolve_time(0),
        m_punish_score(pconv(Punishment::None))
    {}

    AliveNode::punishment_t AliveNode::average_punishments() const noexcept
    {
        return m_punish_score;
    }

    void AliveNode::punish(node_id_t _id_ignored, Punishment punishment)
    {
        m_punish_score += pconv(punishment);
    }
} // namespace community
} // namespace rpc

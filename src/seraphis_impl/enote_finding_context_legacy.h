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

// Dependency injectors for the find-received step of enote scanning. Intended to be stateless.

#pragma once

//local headers
#include "async/threadpool.h"
#include "crypto/crypto.h"
#include "cryptonote_basic/subaddress_index.h"
#include "ringct/rctTypes.h"
#include "seraphis_main/enote_finding_context.h"
#include "seraphis_main/scan_core_types.h"

//third party headers

//standard headers
#include <memory>
#include <unordered_map>

//forward declarations


namespace sp
{

////
// EnoteFindingContextLegacySimple
// - find owned enotes from legacy view scanning using actual chain data
// - scans each tx in a chunk of blocks serially in order
///
class EnoteFindingContextLegacySimple final : public sp::EnoteFindingContextLegacy
{
public:
//constructors
    EnoteFindingContextLegacySimple(const rct::key &legacy_base_spend_pubkey,
        const std::unordered_map<rct::key, cryptonote::subaddress_index> &legacy_subaddress_map,
        const crypto::secret_key &legacy_view_privkey) :
            m_legacy_base_spend_pubkey{legacy_base_spend_pubkey},
            m_legacy_subaddress_map{legacy_subaddress_map},
            m_legacy_view_privkey{legacy_view_privkey}
    {
    }

//overloaded operators
    /// disable copy/move (this is a scoped manager [reference wrapper])
    EnoteFindingContextLegacySimple& operator=(sp::EnoteFindingContextLegacy&&) = delete;

//member functions
    /// scans a chunk of blocks to find basic enote records
    void view_scan_chunk(const LegacyUnscannedChunk &legacy_unscanned_chunk,
        sp::scanning::ChunkData &chunk_data_out) const override;

//member variables
private:
    const rct::key &m_legacy_base_spend_pubkey;
    // TODO: implement subaddress lookahead
    const std::unordered_map<rct::key, cryptonote::subaddress_index> &m_legacy_subaddress_map;
    const crypto::secret_key &m_legacy_view_privkey;
};

////
// EnoteFindingContextLegacyMultithreaded
// - find owned enotes from legacy view scanning using actual chain data
// - scanning each individual tx is a task that gets submitted to threadpool
///
class EnoteFindingContextLegacyMultithreaded final : public sp::EnoteFindingContextLegacy
{
public:
//constructors
    EnoteFindingContextLegacyMultithreaded(const rct::key &legacy_base_spend_pubkey,
        const std::unordered_map<rct::key, cryptonote::subaddress_index> &legacy_subaddress_map,
        const crypto::secret_key &legacy_view_privkey,
        async::Threadpool &threadpool) :
            m_legacy_base_spend_pubkey{legacy_base_spend_pubkey},
            m_legacy_subaddress_map{legacy_subaddress_map},
            m_legacy_view_privkey{legacy_view_privkey},
            m_threadpool(threadpool)
    {
    }

//overloaded operators
    /// disable copy/move (this is a scoped manager [reference wrapper])
    EnoteFindingContextLegacyMultithreaded& operator=(EnoteFindingContextLegacyMultithreaded&&) = delete;

//member functions
    /// scans a chunk of blocks to find basic enote records
    void view_scan_chunk(const LegacyUnscannedChunk &legacy_unscanned_chunk,
        sp::scanning::ChunkData &chunk_data_out) const override;

//member variables
private:
    const rct::key &m_legacy_base_spend_pubkey;
    // TODO: implement subaddress lookahead
    const std::unordered_map<rct::key, cryptonote::subaddress_index> &m_legacy_subaddress_map;
    const crypto::secret_key &m_legacy_view_privkey;

    async::Threadpool &m_threadpool;
};

} //namespace sp

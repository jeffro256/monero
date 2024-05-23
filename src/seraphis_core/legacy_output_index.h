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

// Convenience type for indexing legacy enotes in (ledger amount, index in amount) form.

#pragma once

//local headers

//third party headers

//standard headers
#include <cstdint>    // std::uint64_t
#include <functional> // std::hash

//forward declarations
namespace rct { typedef uint64_t xmr_amount; }

namespace sp
{
////
// legacy_output_index_t
// - used to index legacy enotes the same way cryptonote inputs do: (ledger amount, index in amount)
//
struct legacy_output_index_t
{
    /// the public ledger amount used to index the enote, 0 for everything post RingCT (even coinbase)
    rct::xmr_amount ledger_indexing_amount;
    /// the nth position of this enote in the chain for the given amount
    std::uint64_t index;
};

inline bool operator==(const legacy_output_index_t &a, const legacy_output_index_t &b)
{
    return a.ledger_indexing_amount == b.ledger_indexing_amount && a.index == b.index;
}

inline bool operator!=(const legacy_output_index_t &a, const legacy_output_index_t &b)
{
    return !(a == b);
}

/// the only purpose of this total ordering is consistency, it can't tell which came first on-chain
inline bool operator<(const legacy_output_index_t &a, const legacy_output_index_t &b)
{
    if (a.ledger_indexing_amount < b.ledger_indexing_amount) return true;
    else if (a.ledger_indexing_amount > b.ledger_indexing_amount) return false;
    else if (a.index < b.index) return true;
    else return false;
}

inline bool operator>(const legacy_output_index_t &a, const legacy_output_index_t &b)
{
    if (a.ledger_indexing_amount > b.ledger_indexing_amount) return true;
    else if (a.ledger_indexing_amount < b.ledger_indexing_amount) return false;
    else if (a.index > b.index) return true;
    else return false;
}
} // namespace sp

namespace std
{
template <>
struct hash<sp::legacy_output_index_t>
{
    size_t operator()(const sp::legacy_output_index_t x) const
    {
        const std::size_t h1{hash<rct::xmr_amount>{}(x.ledger_indexing_amount)};
        const std::size_t h2{hash<std::uint64_t>{}(x.index)};
        return h2 ^ (h1 + 0x9e3779b9 + (h2 << 6) + (h2 >> 2)); // see boost::hash_combine
    }
};
} // namespace std


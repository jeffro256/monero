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

//paired header
#include "legacy_decoy_selector_flat.h"

//local headers
#include "crypto/crypto.h"
#include "misc_log_ex.h"

//third party headers

//standard headers
#include <algorithm>
#include <vector>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis"

namespace sp
{
//-------------------------------------------------------------------------------------------------------------------
LegacyDecoySelectorFlat::LegacyDecoySelectorFlat(index_bounds_by_amount_t index_bounds_by_amount) :
    m_index_bounds_by_amount(std::move(index_bounds_by_amount))
{
    // checks
    for (const auto &p : m_index_bounds_by_amount)
    {
        const std::uint64_t min_ind{p.second.first};
        const std::uint64_t max_ind{p.second.second};
        CHECK_AND_ASSERT_THROW_MES(max_ind >= min_ind, "legacy decoy selector (flat): min > max index.");
    }
}
//-------------------------------------------------------------------------------------------------------------------
void LegacyDecoySelectorFlat::get_ring_members(const legacy_output_index_t real_ring_member_index,
        const std::uint64_t num_ring_members,
        std::set<legacy_output_index_t> &ring_members_out,
        std::uint64_t &real_ring_member_index_in_ref_set_out) const
{
    const rct::xmr_amount amount{real_ring_member_index.ledger_indexing_amount};
    const std::uint64_t min_index{this->get_min_index(amount)};
    const std::uint64_t max_index{this->get_max_index(amount)};

    CHECK_AND_ASSERT_THROW_MES(real_ring_member_index.index >= min_index,
        "legacy decoy selector (flat): real ring member index below available index range.");
    CHECK_AND_ASSERT_THROW_MES(real_ring_member_index.index <= max_index,
        "legacy decoy selector (flat): real ring member index above available index range.");
    CHECK_AND_ASSERT_THROW_MES(num_ring_members <= max_index - min_index + 1,
        "legacy decoy selector (flat): insufficient available legacy enotes to have unique ring members.");

    // fill in ring members
    ring_members_out.clear();
    ring_members_out.insert(real_ring_member_index);

    while (ring_members_out.size() < num_ring_members)
    {
        // select a new ring member from indices in the specified range with uniform distribution
        const std::uint64_t new_ring_member_index{crypto::rand_range<std::uint64_t>(min_index, max_index)};
        // add to set (only unique values will remain)
        ring_members_out.insert({amount, new_ring_member_index});
    }

    // find location in reference set where the real reference sits
    // note: the reference set does not contain duplicates, so we don't have to handle the case of multiple real references
    // note2: `ring_members_out` is a `std::set`, which contains ordered keys, so the index selected will be correct.
    real_ring_member_index_in_ref_set_out = 0;

    for (const legacy_output_index_t reference : ring_members_out)
    {
        if (reference == real_ring_member_index)
            return;

        ++real_ring_member_index_in_ref_set_out;
    }
}
//-------------------------------------------------------------------------------------------------------------------
std::uint64_t LegacyDecoySelectorFlat::get_min_index(const rct::xmr_amount amount) const
{
    return m_index_bounds_by_amount.at(amount).first;
}
//-------------------------------------------------------------------------------------------------------------------
std::uint64_t LegacyDecoySelectorFlat::get_max_index(const rct::xmr_amount amount) const
{
    return m_index_bounds_by_amount.at(amount).second;
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace sp

// Copyright (c) 2025, The Monero Project
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
#include "branch_blinds_cache.h"

//local headers
#include "common/container_helpers.h"
#include "cryptonote_config.h"
#include "misc_log_ex.h"
#include "prove.h"

//third party headers

//standard headers

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "fcmp_pp.bb_cache"

namespace fcmp_pp
{
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static constexpr std::size_t max_blind_prep_target = 10000;
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
BranchBlindsCacheBase::BranchBlindsCacheBase():
    m_num_prepped(0),
    m_prep_target(0),
    m_work_queue(tools::threadpool::getInstanceForCompute())
{
    std::lock_guard lock(m_mutex);
    fill();
}
//-------------------------------------------------------------------------------------------------------------------
void BranchBlindsCacheBase::increment_num_prepped(std::size_t count) noexcept
{
    std::lock_guard lock(m_mutex);
    count = std::min(count, max_blind_prep_target);
    m_prep_target = std::min(m_prep_target + count, max_blind_prep_target);
    fill();
}
//-------------------------------------------------------------------------------------------------------------------
void BranchBlindsCacheBase::decrement_num_prepped(const std::size_t count) noexcept
{
    std::lock_guard lock(m_mutex);
    m_prep_target -= std::min(count, m_prep_target);
}
//-------------------------------------------------------------------------------------------------------------------
blind_unique_ptr_t BranchBlindsCacheBase::wait_pull_blind(const bool decrement)
{
    blind_unique_ptr_t blind = m_work_queue.pull();

    {
        std::lock_guard lock(m_mutex);
        if (m_num_prepped)
            --m_num_prepped;
        if (decrement && m_prep_target)
            --m_prep_target;
        fill();
    }

    return blind;
}
//-------------------------------------------------------------------------------------------------------------------
blind_unique_ptr_t BranchBlindsCacheBase::try_pull_blind_non_blocking(const bool decrement)
{
    std::optional<blind_unique_ptr_t> blind_opt = m_work_queue.try_pull_non_blocking();
    if (!blind_opt)
        return blind_unique_ptr_t(nullptr, &std::free);

    {
        std::lock_guard lock(m_mutex);
        if (m_num_prepped)
            --m_num_prepped;
        if (decrement && m_prep_target)
            --m_prep_target;
        fill();
    }

    return std::move(*blind_opt);
}
//-------------------------------------------------------------------------------------------------------------------
void BranchBlindsCacheBase::add_blind(blind_unique_ptr_t &&blind)
{
    m_work_queue.push_value(std::move(blind));
    std::lock_guard lock(m_mutex);
    ++m_num_prepped;
}
//-------------------------------------------------------------------------------------------------------------------
void BranchBlindsCacheBase::fill()
{
    const std::size_t actual_prep_target = std::min(m_prep_target + FCMP_PLUS_PLUS_MAX_LAYERS, max_blind_prep_target);
    if (m_num_prepped >= actual_prep_target)
        return;
    const std::size_t num_new_jobs = actual_prep_target - m_num_prepped;
    for (std::size_t i = 0; i < num_new_jobs; ++i)
        m_work_queue.push([this](){ return blind_unique_ptr_t(this->calculate_blind(), &std::free); });
    m_num_prepped = actual_prep_target;
}
//-------------------------------------------------------------------------------------------------------------------
BranchBlindsCacheHold::BranchBlindsCacheHold(BranchBlindsCacheBase &cache):
    m_count(0), m_cache(cache)
{}
//-------------------------------------------------------------------------------------------------------------------
void BranchBlindsCacheHold::set_prep_target(const std::size_t n_inputs, const std::size_t n_tree_layers)
{
    CHECK_AND_ASSERT_THROW_MES(n_inputs <= FCMP_PLUS_PLUS_MAX_INPUTS,
        "BranchBlindsCacheHold::set_prep_target: invalid argument: n_inputs too high");
    CHECK_AND_ASSERT_THROW_MES(n_tree_layers <= FCMP_PLUS_PLUS_MAX_LAYERS,
        "BranchBlindsCacheHold::set_prep_target: invalid argument: n_tree_layers too high");
    const std::size_t new_count = n_inputs * m_cache.get_num_blinds(n_tree_layers);
    if (new_count > m_count)
    {
        m_cache.increment_num_prepped(new_count - m_count);
    }
    else if (new_count < m_count)
    {
        m_cache.decrement_num_prepped(m_count - new_count);
    }
    m_count = new_count;
}
//-------------------------------------------------------------------------------------------------------------------
std::vector<blind_unique_ptr_t> BranchBlindsCacheHold::get_blinds(const std::size_t n_inputs,
    const std::size_t n_tree_layers)
{
    CHECK_AND_ASSERT_THROW_MES(n_inputs <= FCMP_PLUS_PLUS_MAX_INPUTS,
        "BranchBlindsCacheHold::get_blinds: invalid argument: n_inputs too high");
    CHECK_AND_ASSERT_THROW_MES(n_tree_layers <= FCMP_PLUS_PLUS_MAX_LAYERS,
        "BranchBlindsCacheHold::get_blinds: invalid argument: n_tree_layers too high");
    const std::size_t pull_count = n_inputs * m_cache.get_num_blinds(n_tree_layers);
    std::vector<blind_unique_ptr_t> blinds;
    blinds.reserve(pull_count);
    for (std::size_t i = 0; i < pull_count; ++i)
    {
        blinds.push_back(m_cache.wait_pull_blind(m_count));
        if (m_count) --m_count;
        CHECK_AND_ASSERT_THROW_MES(blinds.back(),
            "BranchBlindsCacheHold::get_blinds: pulled invalid nullptr for blind");
    }
    return blinds;
}
//-------------------------------------------------------------------------------------------------------------------
BranchBlindsCacheHold::~BranchBlindsCacheHold()
{
    m_cache.decrement_num_prepped(m_count);
    m_count = 0;
}
//-------------------------------------------------------------------------------------------------------------------
std::size_t SeleneBranchBlindsCache::get_num_blinds(std::size_t n_tree_layers) const
{
    return n_tree_layers / 2;
}
//-------------------------------------------------------------------------------------------------------------------
uint8_t *SeleneBranchBlindsCache::calculate_blind() const
{
    return selene_branch_blind();
}
//-------------------------------------------------------------------------------------------------------------------
std::size_t HeliosBranchBlindsCache::get_num_blinds(std::size_t n_tree_layers) const
{
    return n_tree_layers ? ((n_tree_layers - 1) / 2) : 0;
}
//-------------------------------------------------------------------------------------------------------------------
uint8_t *HeliosBranchBlindsCache::calculate_blind() const
{
    return helios_branch_blind();
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace fcmp_pp

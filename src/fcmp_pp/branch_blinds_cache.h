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

#pragma once

//local headers
#include "common/work_queue.h"

//third party headers

//standard headers
#include <cstddef>
#include <memory>

//forward declarations

namespace fcmp_pp
{
using blind_unique_ptr_t = std::unique_ptr<uint8_t, decltype(&std::free)>;

class BranchBlindsCacheBase
{
public:
    BranchBlindsCacheBase();
    BranchBlindsCacheBase(const BranchBlindsCacheBase&) = delete;
    BranchBlindsCacheBase(BranchBlindsCacheBase&&) = delete;

    void increment_num_prepped(std::size_t count) noexcept;
    void decrement_num_prepped(std::size_t count) noexcept;
    blind_unique_ptr_t wait_pull_blind(bool decrement);
    blind_unique_ptr_t try_pull_blind_non_blocking(bool decrement);
    void add_blind(blind_unique_ptr_t &&blind);

    virtual std::size_t get_num_blinds(std::size_t n_tree_layers) const = 0;

    virtual ~BranchBlindsCacheBase() = default;

protected:
    virtual uint8_t *calculate_blind() const = 0;

private:
    /// schedules new jobs to match prep target, assumes m_mutex is held by calling thread
    void fill();

    std::mutex m_mutex;
    std::size_t m_num_prepped;
    std::size_t m_prep_target;
    tools::work_queue<blind_unique_ptr_t> m_work_queue;
};

class BranchBlindsCacheHold
{
public:
    BranchBlindsCacheHold(BranchBlindsCacheBase &cache);
    BranchBlindsCacheHold(const BranchBlindsCacheHold&) = delete;
    BranchBlindsCacheHold(BranchBlindsCacheHold&&) = delete;

    void set_prep_target(std::size_t n_inputs, std::size_t n_tree_layers);

    std::vector<blind_unique_ptr_t> get_blinds(std::size_t n_inputs, std::size_t n_tree_layers);

    ~BranchBlindsCacheHold();

private:
    std::size_t m_count;
    BranchBlindsCacheBase &m_cache;
};

class SeleneBranchBlindsCache: public BranchBlindsCacheBase
{
public:
    std::size_t get_num_blinds(std::size_t n_tree_layers) const override;
protected:
    uint8_t *calculate_blind() const override;
};

class HeliosBranchBlindsCache: public BranchBlindsCacheBase
{
public:
    std::size_t get_num_blinds(std::size_t n_tree_layers) const override;
protected:
    uint8_t *calculate_blind() const override;
};

} //namespace fcmp_pp

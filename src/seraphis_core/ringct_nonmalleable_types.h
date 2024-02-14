// Copyright (c) 2024, The Monero Project
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

/// Types to represent RingCT information in a non-malleable manner as they were serialized in
/// Monero RingCT transactions. The only malleable aspects of these component types should be the
/// lengths of the containers in relation to each other. For example, the length
/// `rct::n_bulletproof_plus_amounts(RingCTBodyBulletproofPlus::bulletproofs_plus)` might differ
/// from the length of the container `RingCTBodyBulletproofPlus::vout`. We don't enforce those here.

#pragma once

//local headers
#include "common/variant.h"
#include "ringct/rctTypes.h"
#include "seraphis_core/legacy_enote_types.h"

//third party headers

//standard headers

//forward declarations

namespace sp
{
struct RingCTMlsag final
{
    std::vector<rct::key> ss;
    rct::key cc;
};

struct RingCTClsag final
{
    rct::keyV s;
    rct::key c1;
    rct::key D;
};

struct RingCTBulletproof final
{
    rct::key A, S, T1, T2;
    rct::key taux, mu;
    rct::keyV L, R;
    rct::key a, b, t;
};

struct RingCTBulletproofPlus final
{
    rct::key A, A1, B;
    rct::key r1, s1, d1;
    rct::keyV L, R;
};

struct RingCTBodyFull final
{
    static constexpr const std::uint8_t rct_type = rct::RCTTypeFull;

    std::vector<LegacyEnoteV2> vout;
    RingCTMlsag mlsag_full;
    std::vector<rct::rangeSig> range_sigs;
};

struct RingCTBodySimple final
{
    static constexpr const std::uint8_t rct_type = rct::RCTTypeSimple;

    std::vector<LegacyEnoteV2> vout;
    rct::keyV pseudo_commitments;
    std::vector<RingCTMlsag> mlsags_simple;
    std::vector<rct::rangeSig> range_sigs;
};

struct RingCTBodyBulletproof final
{
    static constexpr const std::uint8_t rct_type = rct::RCTTypeBulletproof;

    std::vector<LegacyEnoteV2> vout;
    rct::keyV pseudo_commitments;
    std::vector<RingCTMlsag> mlsags_simple;
    std::vector<RingCTBulletproof> bulletproofs;
};

struct RingCTBodyBulletproofCompact final
{
    static constexpr const std::uint8_t rct_type = rct::RCTTypeBulletproof2;

    std::vector<LegacyEnoteV3> vout;
    rct::keyV pseudo_commitments;
    std::vector<RingCTMlsag> mlsags_simple;
    std::vector<RingCTBulletproof> bulletproofs;
};

struct RingCTBodyClsag final
{
    static constexpr const std::uint8_t rct_type = rct::RCTTypeCLSAG;

    std::vector<LegacyEnoteV3> vout;
    rct::keyV pseudo_commitments;
    std::vector<RingCTClsag> clsags;
    std::vector<RingCTBulletproof> bulletproofs;
};

struct RingCTBodyBulletproofPlus final
{
    static constexpr const std::uint8_t rct_type = rct::RCTTypeBulletproofPlus;

    std::vector<LegacyEnoteV5> vout;
    rct::keyV pseudo_commitments;
    std::vector<RingCTClsag> clsags;
    std::vector<RingCTBulletproofPlus> bulletproofs_plus;
};

using RingCTBodyVariant = tools::variant<
    RingCTBodyFull,
    RingCTBodySimple,
    RingCTBodyBulletproof,
    RingCTBodyBulletproofCompact,
    RingCTBodyClsag,
    RingCTBodyBulletproofPlus>;

inline std::uint8_t ringct_type(const RingCTBodyVariant &rv)
{ return rv.index() + 1; }

static_assert(RingCTBodyVariant::type_index_of<RingCTBodyFull>() + 1
    == rct::RCTTypeFull,            "bad ringct body variant index");
static_assert(RingCTBodyVariant::type_index_of<RingCTBodySimple>() + 1
    == rct::RCTTypeSimple,          "bad ringct body variant index");
static_assert(RingCTBodyVariant::type_index_of<RingCTBodyBulletproof>() + 1
    == rct::RCTTypeBulletproof,     "bad ringct body variant index");
static_assert(RingCTBodyVariant::type_index_of<RingCTBodyBulletproofCompact>() + 1
    == rct::RCTTypeBulletproof2,    "bad ringct body variant index");
static_assert(RingCTBodyVariant::type_index_of<RingCTBodyClsag>() + 1
    == rct::RCTTypeCLSAG,           "bad ringct body variant index");
static_assert(RingCTBodyVariant::type_index_of<RingCTBodyBulletproofPlus>() + 1
    == rct::RCTTypeBulletproofPlus, "bad ringct body variant index");
} // namespace sp

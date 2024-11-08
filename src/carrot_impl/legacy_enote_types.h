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

// Seraphis core types.

#pragma once

//local headers
#include "carrot_core/core_types.h"
#include "crypto/crypto.h"
#include "ringct/rctTypes.h"

//third party headers

//standard headers

//forward declarations


namespace carrot
{

////
// LegacyEnoteV1 (all pre-RingCT enotes, then post-RingCT pre-viewtag coinbase)
// - onetime address
// - cleartext amount
///
struct LegacyEnoteV1 final
{
    /// Ko
    crypto::public_key onetime_address;
    /// a
    rct::xmr_amount amount;
    /// the enote's ephemeral pubkey
    crypto::public_key enote_ephemeral_pubkey;
    /// t: the enote's index in its transaction
    std::uint64_t tx_output_index;
};

////
// LegacyEnoteV2
// - onetime address
// - amount commitment
// - encrypted amount commitment mask
// - encrypted amount (version 1: 32 bytes)
///
struct LegacyEnoteV2 final
{
    /// Ko
    crypto::public_key onetime_address;
    /// C
    rct::key amount_commitment;
    /// enc(x)
    rct::key encrypted_amount_blinding_factor;
    /// enc(a)
    rct::key encrypted_amount;
    /// the enote's ephemeral pubkey
    crypto::public_key enote_ephemeral_pubkey;
    /// t: the enote's index in its transaction
    std::uint64_t tx_output_index;
};

////
// LegacyEnoteV3
// - onetime address
// - amount commitment
// - encrypted amount (version 2: 8 bytes)
///
struct LegacyEnoteV3 final
{
    /// Ko
    crypto::public_key onetime_address;
    /// C
    rct::key amount_commitment;
    /// enc(a)
    encrypted_amount_t encrypted_amount;
    /// the enote's ephemeral pubkey
    crypto::public_key enote_ephemeral_pubkey;
    /// t: the enote's index in its transaction
    std::uint64_t tx_output_index;
};

////
// LegacyEnoteV4 (post-viewtag coinbase, also post-viewtag v1 unmixable dust txs)
// - onetime address
// - cleartext amount
// - view tag
///
struct LegacyEnoteV4 final
{
    /// Ko
    crypto::public_key onetime_address;
    /// a
    rct::xmr_amount amount;
    /// view_tag
    crypto::view_tag view_tag;
    /// the enote's ephemeral pubkey
    crypto::public_key enote_ephemeral_pubkey;
    /// t: the enote's index in its transaction
    std::uint64_t tx_output_index;
};

////
// LegacyEnoteV5
// - onetime address
// - amount commitment
// - encrypted amount (version 2: 8 bytes)
// - view tag
///
struct LegacyEnoteV5 final
{
    /// Ko
    crypto::public_key onetime_address;
    /// C
    rct::key amount_commitment;
    /// enc(a)
    encrypted_amount_t encrypted_amount;
    /// view_tag
    crypto::view_tag view_tag;
    /// the enote's ephemeral pubkey
    crypto::public_key enote_ephemeral_pubkey;
    /// t: the enote's index in its transaction
    std::uint64_t tx_output_index;
};

/**
* brief: gen_legacy_enote_v1() - generate a legacy v1 enote (all random)
*/
LegacyEnoteV1 gen_legacy_enote_v1();
/**
* brief: gen_legacy_enote_v2() - generate a legacy v2 enote (all random)
*/
LegacyEnoteV2 gen_legacy_enote_v2();
/**
* brief: gen_legacy_enote_v3() - generate a legacy v3 enote (all random)
*/
LegacyEnoteV3 gen_legacy_enote_v3();
/**
* brief: gen_legacy_enote_v4() - generate a legacy v4 enote (all random)
*/
LegacyEnoteV4 gen_legacy_enote_v4();
/**
* brief: gen_legacy_enote_v5() - generate a legacy v5 enote (all random)
*/
LegacyEnoteV5 gen_legacy_enote_v5();

} //namespace carrot

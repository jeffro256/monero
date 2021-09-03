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

// NOT FOR PRODUCTION

////
// Mock jamtis keys
//
// reference: https://gist.github.com/tevador/50160d160d24cfc6c52ae02eb3d17024
///

#pragma once

//local headers
#include "crypto/crypto.h"
#include "crypto/x25519.h"
#include "ringct/rctTypes.h"
#include "seraphis_core/jamtis_destination.h"

//third party headers

//standard headers
#include <vector>

//forward declarations


namespace sp
{
namespace jamtis
{
namespace mocks
{

////
// A set of jamtis keys for mock-ups/unit testing
///
struct jamtis_mock_keys
{
    JamtisOnetimeAddressFormat onetime_address_format;  //onetime address format
    crypto::secret_key s_m;                             //master
    crypto::secret_key s_vb;                            //view-balance
    crypto::secret_key k_ps;                            //prove-spend
    crypto::secret_key k_gi;                            //generate-image
    crypto::x25519_secret_key d_ur;                     //unlock-received
    crypto::x25519_secret_key d_ir;                     //identify-received
    crypto::x25519_secret_key d_fa;                     //filter-assist
    crypto::secret_key s_ga;                            //generate-address
    crypto::secret_key s_ct;                            //cipher-tag
    rct::key K_s_base;                                  //jamtis spend base        = k_gi X + k_ps U
    crypto::x25519_pubkey D_base;                       //exchange-base pubkey     = d_ur xG
    crypto::x25519_pubkey D_ir;                         //identify-received pubkey = d_ir D_base
    crypto::x25519_pubkey D_fa;                         //filter-assist pubkey     = d_fa D_base
};

/// make a set of mock jamtis keys (for mock-ups/unit testing)
void make_jamtis_mock_keys(const JamtisOnetimeAddressFormat onetime_address_format,
    jamtis_mock_keys &keys_out);
/// make a jamtis address for the given privkeys and address index
void make_address_for_user(const jamtis_mock_keys &user_keys,
    const address_index_t &j,
    JamtisDestinationV1 &user_address_out);
/// make a random jamtis address for the given privkeys
void make_random_address_for_user(const jamtis_mock_keys &user_keys,
    JamtisDestinationV1 &user_address_out);

} //namespace mocks
} //namespace jamtis
} //namespace sp

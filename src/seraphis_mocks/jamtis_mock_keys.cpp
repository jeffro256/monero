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

//paired header
#include "jamtis_mock_keys.h"

//local headers
#include "crypto/crypto.h"
#include "crypto/x25519.h"
#include "ringct/rctOps.h"
#include "seraphis_core/jamtis_account_secrets.h"
#include "seraphis_core/sp_core_enote_utils.h"

//third party headers

//standard headers


#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis_mocks"

namespace sp
{
namespace jamtis
{
namespace mocks
{
//-------------------------------------------------------------------------------------------------------------------
void make_jamtis_mock_keys(const JamtisOnetimeAddressFormat onetime_address_format,
    jamtis_mock_keys &keys_out)
{
    keys_out.onetime_address_format = onetime_address_format;
    keys_out.s_m  = rct::rct2sk(rct::skGen());
    keys_out.s_vb = rct::rct2sk(rct::skGen());
    make_jamtis_provespend_key(keys_out.s_m, keys_out.k_ps);
    make_jamtis_generateimage_key(keys_out.s_vb, keys_out.k_gi);
    make_jamtis_unlockreceived_key(keys_out.s_vb, keys_out.d_ur);
    make_jamtis_identifyreceived_key(keys_out.s_vb, keys_out.d_ir);
    make_jamtis_filterassist_key(keys_out.s_vb, keys_out.d_fa);
    make_jamtis_generateaddress_secret(keys_out.s_vb, keys_out.s_ga);
    make_jamtis_ciphertag_secret(keys_out.s_ga, keys_out.s_ct);
    if (onetime_address_format == JamtisOnetimeAddressFormat::SERAPHIS)
        make_seraphis_spendkey(keys_out.k_gi, keys_out.k_ps, keys_out.K_s_base);
    else // RINGCTv2 onetime address format
        make_rct_spendkey(keys_out.k_gi, keys_out.k_ps, keys_out.K_s_base);
    make_jamtis_exchangebase_pubkey(keys_out.d_ur, keys_out.D_base);
    make_jamtis_identifyreceived_pubkey(keys_out.d_ir, keys_out.D_base, keys_out.D_ir);
    make_jamtis_filterassist_pubkey(keys_out.d_fa, keys_out.D_base, keys_out.D_fa);
}
//-------------------------------------------------------------------------------------------------------------------
void make_address_for_user(const jamtis_mock_keys &user_keys,
    const address_index_t &j,
    JamtisDestinationV1 &user_address_out)
{
    make_jamtis_destination_v1(user_keys.onetime_address_format,
        user_keys.K_s_base,
        user_keys.D_fa,
        user_keys.D_ir,
        user_keys.D_base,
        user_keys.s_ga,
        j,
        user_address_out);
}
//-------------------------------------------------------------------------------------------------------------------
void make_random_address_for_user(const jamtis_mock_keys &user_keys, JamtisDestinationV1 &user_address_out)
{
    const address_index_t random_j = gen_address_index();

    make_address_for_user(user_keys, random_j, user_address_out);
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace mocks
} //namespace jamtis
} //namespace sp

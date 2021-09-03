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
#include "jamtis_account_secrets.h"

//local headers
#include "crypto/crypto.h"
#include "crypto/x25519.h"
#include "cryptonote_config.h"
#include "ringct/rctOps.h"
#include "seraphis_crypto/sp_crypto_utils.h"
#include "seraphis_crypto/sp_hash_functions.h"
#include "seraphis_crypto/sp_transcript.h"
#include "sp_core_enote_utils.h"

//third party headers

//standard headers


#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis"

namespace sp
{
namespace jamtis
{
void make_jamtis_viewbalance_key(const crypto::secret_key &k_master,
    crypto::secret_key &k_view_balance_out)
{
    // k_vb = H_n[k_m]()
    SpKDFTranscript transcript{config::HASH_KEY_JAMTIS_VIEWBALANCE_KEY, 0};
    sp_derive_key(to_bytes(k_master), transcript.data(), transcript.size(), to_bytes(k_view_balance_out));
}
//-------------------------------------------------------------------------------------------------------------------
void make_jamtis_viewreceived_key(const crypto::secret_key &k_view_balance,
    crypto::x25519_secret_key &d_view_received_out)
{
    // d_vr = H_n_x25519[k_vb]()
    SpKDFTranscript transcript{config::HASH_KEY_JAMTIS_VIEWRECEIVED_KEY, 0};
    sp_derive_x25519_key(to_bytes(k_view_balance), transcript.data(), transcript.size(), d_view_received_out.data);
}
//-------------------------------------------------------------------------------------------------------------------
void make_jamtis_exchangebase_pubkey(const crypto::x25519_secret_key &d_view_received,
    crypto::x25519_pubkey &exchangebase_pubkey_out)
{
    // D_base = d_vr * xG
    x25519_scmul_base(d_view_received, exchangebase_pubkey_out);
}
//-------------------------------------------------------------------------------------------------------------------
void make_jamtis_viewreceived_pubkey(const crypto::x25519_secret_key &d_view_received,
    const crypto::x25519_pubkey &exchangebase_pubkey,
    crypto::x25519_pubkey &viewreceived_pubkey_out)
{
    // D_vr = d_vr * D_base
    x25519_scmul_key(d_view_received, exchangebase_pubkey, viewreceived_pubkey_out);
}
//-------------------------------------------------------------------------------------------------------------------
void make_jamtis_filterassist_key(const crypto::x25519_secret_key &d_view_received,
    crypto::x25519_secret_key &d_filter_assist_out)
{
    // d_fa = H_n_x25519[d_vr]()
    SpKDFTranscript transcript{config::HASH_KEY_JAMTIS_FILTERASSIST_KEY, 0};
    sp_derive_x25519_key(to_bytes(d_view_received), transcript.data(), transcript.size(), d_filter_assist_out.data);
}
//-------------------------------------------------------------------------------------------------------------------
void make_jamtis_filterassist_pubkey(const crypto::x25519_secret_key &d_filter_assist,
    const crypto::x25519_pubkey &exchangebase_pubkey,
    crypto::x25519_pubkey &filterassist_pubkey_out)
{
    // D_fa = d_fa * D_base
    x25519_scmul_key(d_filter_assist, exchangebase_pubkey, filterassist_pubkey_out);
}
//-------------------------------------------------------------------------------------------------------------------
void make_jamtis_generateaddress_secret(const crypto::x25519_secret_key &d_view_received,
    crypto::secret_key &s_generate_address_out)
{
    // s_ga = H_32[d_vr]()
    SpKDFTranscript transcript{config::HASH_KEY_JAMTIS_GENERATEADDRESS_SECRET, 0};
    sp_derive_secret(to_bytes(d_view_received), transcript.data(), transcript.size(), to_bytes(s_generate_address_out));
}
//-------------------------------------------------------------------------------------------------------------------
void make_jamtis_ciphertag_secret(const crypto::secret_key &s_generate_address,
    crypto::secret_key &s_cipher_tag_out)
{
    // s_ct = H_32[s_ga]()
    SpKDFTranscript transcript{config::HASH_KEY_JAMTIS_CIPHERTAG_SECRET, 0};
    sp_derive_secret(to_bytes(s_generate_address), transcript.data(), transcript.size(), to_bytes(s_cipher_tag_out));
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace jamtis
} //namespace sp

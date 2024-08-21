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
#include "crypto/generators.h"
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
//-------------------------------------------------------------------------------------------------------------------
void make_jamtis_provespend_key(const crypto::secret_key &s_master,
    crypto::secret_key &k_prove_spend_out)
{
    // k_ps = H_n[s_m]()
    SpKDFTranscript transcript{config::HASH_KEY_JAMTIS_PROVESPEND_KEY, 0};
    sp_derive_key(to_bytes(s_master), transcript.data(), transcript.size(), to_bytes(k_prove_spend_out));
}
//-------------------------------------------------------------------------------------------------------------------
void make_jamtis_viewbalance_secret(const crypto::secret_key &s_master,
    crypto::secret_key &s_view_balance_out)
{
    // s_vb = H_32[s_m]()
    SpKDFTranscript transcript{config::HASH_KEY_JAMTIS_VIEWBALANCE_SECRET, 0};
    sp_derive_secret(to_bytes(s_master), transcript.data(), transcript.size(), to_bytes(s_view_balance_out));
}
//-------------------------------------------------------------------------------------------------------------------
void make_jamtis_generateimage_key(const crypto::secret_key &s_view_balance,
    crypto::secret_key &k_generate_image_out)
{
    // k_gi = H_n[s_vb]()
    SpKDFTranscript transcript{config::HASH_KEY_JAMTIS_GENERATEIMAGE_KEY, 0};
    sp_derive_key(to_bytes(s_view_balance), transcript.data(), transcript.size(), to_bytes(k_generate_image_out));
}
//-------------------------------------------------------------------------------------------------------------------
void make_jamtis_unlockreceived_key(const crypto::secret_key &s_view_balance,
    crypto::x25519_secret_key &d_unlock_received_out)
{
    // d_ur = H_n_x25519[s_vb]()
    SpKDFTranscript transcript{config::HASH_KEY_JAMTIS_UNLOCKRECEIVED_KEY, 0};
    sp_derive_x25519_key(to_bytes(s_view_balance), transcript.data(), transcript.size(), d_unlock_received_out.data);
}
//-------------------------------------------------------------------------------------------------------------------
void make_jamtis_exchangebase_pubkey(const crypto::x25519_secret_key &d_unlock_received,
    crypto::x25519_pubkey &exchangebase_pubkey_out)
{
    // D_base = d_ur * xG
    crypto::x25519_scmul_base(d_unlock_received, exchangebase_pubkey_out);
}
//-------------------------------------------------------------------------------------------------------------------
void make_jamtis_identifyreceived_key(const crypto::secret_key &s_view_balance,
    crypto::x25519_secret_key &d_identify_received_out)
{
    // d_ir = H_n_x25519[s_vb]()
    SpKDFTranscript transcript{config::HASH_KEY_JAMTIS_IDENTIFYRECEIVED_KEY, 0};
    sp_derive_x25519_key(to_bytes(s_view_balance), transcript.data(), transcript.size(), d_identify_received_out.data);
}
//-------------------------------------------------------------------------------------------------------------------
void make_jamtis_identifyreceived_pubkey(const crypto::x25519_secret_key &d_identify_received,
    const crypto::x25519_pubkey &exchangebase_pubkey,
    crypto::x25519_pubkey &identifyreceived_pubkey_out)
{
    // D_ir = d_ir * D_base
    crypto::x25519_scmul_key(d_identify_received, exchangebase_pubkey, identifyreceived_pubkey_out);
}
//-------------------------------------------------------------------------------------------------------------------
void make_jamtis_filterassist_key(const crypto::secret_key &s_view_balance,
    crypto::x25519_secret_key &d_filter_assist_out)
{
    // d_fa = H_n_x25519[s_vb]()
    SpKDFTranscript transcript{config::HASH_KEY_JAMTIS_FILTERASSIST_KEY, 0};
    sp_derive_x25519_key(to_bytes(s_view_balance), transcript.data(), transcript.size(), d_filter_assist_out.data);
}
//-------------------------------------------------------------------------------------------------------------------
void make_jamtis_filterassist_pubkey(const crypto::x25519_secret_key &d_filter_assist,
    const crypto::x25519_pubkey &exchangebase_pubkey,
    crypto::x25519_pubkey &filterassist_pubkey_out)
{
    // D_fa = d_fa * D_base
    crypto::x25519_scmul_key(d_filter_assist, exchangebase_pubkey, filterassist_pubkey_out);
}
//-------------------------------------------------------------------------------------------------------------------
void make_jamtis_generateaddress_secret(const crypto::secret_key &s_view_balance,
    crypto::secret_key &s_generate_address_out)
{
    // s_ga = H_32[s_vb]()
    SpKDFTranscript transcript{config::HASH_KEY_JAMTIS_GENERATEADDRESS_SECRET, 0};
    sp_derive_secret(to_bytes(s_view_balance), transcript.data(), transcript.size(), to_bytes(s_generate_address_out));
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
void make_rct_spendkey(const crypto::secret_key &k_generate_image,
    const crypto::secret_key &k_prove_spend,
    rct::key &spend_pubkey_out)
{
    // k_ps U
    rct::key U_term;
    rct::scalarmultKey(U_term, rct::pk2rct(crypto::get_U()), rct::sk2rct(k_prove_spend));

    // K_s = k_gi G + k_ps U
    rct::addKeys1(spend_pubkey_out, rct::sk2rct(k_generate_image), U_term);
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace jamtis
} //namespace sp

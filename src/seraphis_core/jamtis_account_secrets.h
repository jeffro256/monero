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

////
// Core implementation details for making Jamtis privkeys, secrets, and pubkeys.
// - Jamtis is a specification for Seraphis/FCMP-RingCT compatible addresses
//
// references:
// * https://gist.github.com/tevador/50160d160d24cfc6c52ae02eb3d17024
// * https://gist.github.com/tevador/d3656a217c0177c160b9b6219d9ebb96
///

#pragma once

//local headers
#include "crypto/crypto.h"
#include "crypto/x25519.h"

//third party headers

//standard headers

//forward declarations
namespace rct { struct key; }


namespace sp
{
namespace jamtis
{

/**
* brief: make_jamtis_provespend_key - prove-spend key, for signing input proofs to spend enotes
*   k_ps = H_n[s_m]()
* param: s_master - s_m
* outparam: k_prove_spend_out - k_ps
*/
void make_jamtis_provespend_key(const crypto::secret_key &s_master,
    crypto::secret_key &k_prove_spend_out);
/**
* brief: make_jamtis_viewbalance_secret - view-balance secret, for viewing all balance information
*   s_vb = H_n[s_m]()
* param: s_master - s_m
* outparam: s_view_balance_out - s_vb
*/
void make_jamtis_viewbalance_secret(const crypto::secret_key &s_master,
    crypto::secret_key &s_view_balance_out);
/**
* brief: make_jamtis_generateimage_key - generate-image key, for identifying enote spends
*   k_gi = H_n[s_vb]()
* param: s_view_balance - s_vb
* outparam: k_generate_image_out - k_gi
*/
void make_jamtis_generateimage_key(const crypto::secret_key &s_view_balance,
    crypto::secret_key &k_generate_image_out);
/**
* brief: make_jamtis_unlockreceived_key - unlock-received key, for Janus and (some) ECDLP protection
*   d_ur = H_n_x25519[s_vb]()
* param: s_view_balance - s_vb
* outparam: d_unlock_received_out - d_ur
*/
void make_jamtis_unlockreceived_key(const crypto::secret_key &s_view_balance,
    crypto::x25519_secret_key &d_unlock_received_out);
/**
 * brief make_jamtis_exchangebase_pubkey - D_base
 *   D_base = d_ur * xG
 * param: d_unlock_received - d_ur
 * outparam: exchangebase_pubkey_out
 */
void make_jamtis_exchangebase_pubkey(const crypto::x25519_secret_key &d_unlock_received,
    crypto::x25519_pubkey &exchangebase_pubkey_out);
/**
* brief: make_jamtis_identifyreceived_key - identify-received key, for calculating secondary view tags
*   d_ir = H_n_x25519[s_vb]()
* param: s_view_balance - s_vb
* outparam: d_identify_received_out - d_ir
*/
void make_jamtis_identifyreceived_key(const crypto::secret_key &s_view_balance,
    crypto::x25519_secret_key &d_identify_received_out);
/**
* brief: make_jamtis_identifyreceived_pubkey - D_ir
*   D_ir = d_ir * D_base
* param: d_identify_received - d_ir
* param: exchangebase_pubkey - D_base
* outparam: identifyreceived_pubkey_out - D_ir
*/
void make_jamtis_identifyreceived_pubkey(const crypto::x25519_secret_key &d_identify_received,
    const crypto::x25519_pubkey &exchangebase_pubkey,
    crypto::x25519_pubkey &identifyreceived_pubkey_out);
/**
* brief: make_jamtis_filterassist_key - filter-assist key, for calculating primary view tags
*   d_fa = H_n_x25519[s_vb]()
* param: s_view_balance - s_vb
* outparam: d_filter_assist_out - d_fa
*/
void make_jamtis_filterassist_key(const crypto::secret_key &s_view_balance,
    crypto::x25519_secret_key &d_filter_assist_out);
/**
* brief: make_jamtis_filterassist_pubkey - D_fa
*   D_fa = d_fa * D_base
* param: d_filter_assist - d_fa
* param: exchangebase_pubkey - D_base
* outparam: filterassist_pubkey_out - D_fa
*/
void make_jamtis_filterassist_pubkey(const crypto::x25519_secret_key &d_filter_assist,
    const crypto::x25519_pubkey &exchangebase_pubkey,
    crypto::x25519_pubkey &filterassist_pubkey_out);
/**
* brief: make_jamtis_generateaddress_secret - generate-address secret, for generating addresses
*   s_ga = H_32[s_vb]()
* param: s_view_balance - s_vb
* outparam: s_generate_address_out - s_ga
*/
void make_jamtis_generateaddress_secret(const crypto::secret_key &s_view_balance,
    crypto::secret_key &s_generate_address_out);
/**
* brief: make_jamtis_ciphertag_secret - cipher-tag secret, for ciphering address indices to/from address tags
*   s_ct = H_32[s_ga]()
* param: s_generate_address - s_ga
* outparam: s_cipher_tag_out - s_ct
*/
void make_jamtis_ciphertag_secret(const crypto::secret_key &s_generate_address,
    crypto::secret_key &s_cipher_tag_out);
/**
 * brief: make_rct_spendkey - base public spendkey for RingCTv2
 *   K_s = k_gi G + k_ps U
 * param: k_generate_image - k_gi
 * param: k_prove_spend - k_ps
 * outparam: spend_pubkey_out - K_s
*/
void make_rct_spendkey(const crypto::secret_key &k_generate_image,
    const crypto::secret_key &k_prove_spend,
    rct::key &spend_pubkey_out);
/**
 * brief: make_carrot_secret_change_spend_extension_g - spend pubkey extension for Janus-protected change (G)
 *   k^change_g = H_n[k_v]("G" || K_s)
 * param: k_view - k_v
 * outparam: k_secret_change_spend_extension_g_out - k^change_g
 */
void make_carrot_secret_change_spend_extension_g(const crypto::secret_key &k_view,
    const crypto::public_key &primary_address_spend_pubkey,
    crypto::secret_key &k_secret_change_spend_extension_g_out);
/**
 * brief: make_carrot_secret_change_spend_extension_u - spend pubkey extension for Janus-protected change (U)
 *   k^change_u = H_n[k_v]("U" || K_s)
 * param: k_view - k_v
 * outparam: k_secret_change_spend_extension_g_out - k^change_u
 */
void make_carrot_secret_change_spend_extension_u(const crypto::secret_key &k_view,
    const crypto::public_key &primary_address_spend_pubkey,
    crypto::secret_key &k_secret_change_spend_extension_u_out);
/**
 * brief: make_carrot_secret_change_spend_pubkey - carrot spend pubkey for Janus-protected change
 *   K^change_s = K_s + k^change_g G + k^change_u U
 * param: primary_address_spend_pubkey - K_s
 * param: k_view - k_v
 * outparam: secret_change_spend_pubkey_out - K^change_s
 */
void make_carrot_secret_change_spend_pubkey(const crypto::public_key &primary_address_spend_pubkey,
    const crypto::secret_key &k_view,
    crypto::public_key &secret_change_spend_pubkey_out);
} //namespace jamtis
} //namespace sp

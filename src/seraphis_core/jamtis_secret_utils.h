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
// - Jamtis is a specification for Seraphis-compatible addresses
//
// reference: https://gist.github.com/tevador/50160d160d24cfc6c52ae02eb3d17024
///

#pragma once

//local headers
#include "crypto/crypto.h"
#include "crypto/x25519.h"
#include "ringct/rctTypes.h"

//third party headers

//standard headers

//forward declarations


namespace sp
{
namespace jamtis
{

/**
* brief: make_jamtis_unlockamounts_key - unlock-amounts key, for recovering amounts and reconstructing amount commitments
*   xk_ua = H_n_x25519[k_vb]()
* param: k_view_balance - k_vb
* outparam: xk_unlock_amounts_out - xk_ua
*/
void make_jamtis_unlockamounts_key(const crypto::secret_key &k_view_balance,
    crypto::x25519_secret_key &xk_unlock_amounts_out);
/**
* brief: make_jamtis_unlockamounts_pubkey - xK_ua
*   - xK_ua = xk_ua * xG
* param: xk_unlock_amounts - xk_ua
* outparam: unlockamounts_pubkey_out - xK_ua
*/
void make_jamtis_unlockamounts_pubkey(const crypto::x25519_secret_key &xk_unlock_amounts,
    crypto::x25519_pubkey &unlockamounts_pubkey_out);
/**
* brief: make_jamtis_denseview_key - dense-view key, for calculating dense view tags
*   xk_dv = H_n_x25519[k_vb]()
* param: k_view_balance - k_vb
* outparam: xk_dense_view_out - xk_dv
*/
void make_jamtis_denseview_key(const crypto::secret_key &k_view_balance,
    crypto::x25519_secret_key &xk_dense_view_out);
/**
* brief: make_jamtis_denseview_pubkey - xK_dv
*   - xK_dv = xk_dv * xK_ua
* param: xk_dense_view - xk_dv
* param: unlock_amounts_pubkey - xK_ua
* outparam: denseview_pubkey_out - xK_dv
*/
void make_jamtis_denseview_pubkey(const crypto::x25519_secret_key &xk_dense_view,
    const crypto::x25519_pubkey &unlock_amounts_pubkey,
    crypto::x25519_pubkey &denseview_pubkey_out);
/**
* brief: make_jamtis_sparseview_key - sparse-view key, for calculating sparse view tags
*   xk_sv = H_n_x25519[k_vb]()
* param: k_view_balance - k_vb
* outparam: xk_sparse_view_out - xk_sv
*/
void make_jamtis_sparseview_key(const crypto::secret_key &k_view_balance,
    crypto::x25519_secret_key &xk_sparse_view_out);
/**
* brief: make_jamtis_sparseview_pubkey - xK_sv
*   - xK_sv = xk_sv * xK_ua
* param: xk_sparse_view - xk_sv
* param: unlock_amounts_pubkey - xK_ua
* outparam: sparseview_pubkey_out - xK_sv
*/
void make_jamtis_sparseview_pubkey(const crypto::x25519_secret_key &xk_sparse_view,
    const crypto::x25519_pubkey &unlock_amounts_pubkey,
    crypto::x25519_pubkey &sparseview_pubkey_out);
/**
* brief: make_jamtis_generateaddress_secret - generate-address secret, for generating addresses
*   s_ga = H_32[k_vb]()
* param: k_view_balance - k_vb
* outparam: s_generate_address_out - s_ga
*/
void make_jamtis_generateaddress_secret(const crypto::secret_key &k_view_balance,
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
 * brief: make_extended_jamtis_pubkey - add G, X, & U key extensions to public (usually spend) key
 *     K_ext = k_g G + k_x X + k_u U + K_base
 * param: base_pubkey - K_base
 * param: ext_g - k_g
 * param: ext_x - k_x
 * param: ext_u - k_u
 * outparam: extended_pubkey_out - K_ext
 */
void make_extended_jamtis_pubkey(const rct::key &base_pubkey,
    const crypto::secret_key &ext_g,
    const crypto::secret_key &ext_x,
    const crypto::secret_key &ext_u,
    rct::key &extended_pubkey_out);
} //namespace jamtis
} //namespace sp

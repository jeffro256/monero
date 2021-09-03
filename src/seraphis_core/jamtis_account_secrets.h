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

//third party headers

//standard headers

//forward declarations


namespace sp
{
namespace jamtis
{

/**
* brief: make_jamtis_viewbalance_key - view-balance key, for viewing all balance information
*   k_vb = H_n[k_m]()
* param: k_master - k_m
* outparam: k_view_balance_out - k_vb
*/
void make_jamtis_viewbalance_key(const crypto::secret_key &k_master,
    crypto::secret_key &k_view_balance_out);
/**
* brief: make_jamtis_viewreceived_key - view-received key, for locating and viewing amounts of normal enotes
*   d_vr = H_n_x25519[k_vb]()
* param: k_view_balance - k_vb
* outparam: d_view_received_out - d_vr
*/
void make_jamtis_viewreceived_key(const crypto::secret_key &k_view_balance,
    crypto::x25519_secret_key &d_view_received_out);
/**
 * brief make_jamtis_exchangebase_pubkey - D_base
 * D_base = d_vr * xG
 * param: d_view_received - d_vr
 * outparam: exchangebase_pubkey_out
 */
void make_jamtis_exchangebase_pubkey(const crypto::x25519_secret_key &d_view_received,
    crypto::x25519_pubkey &exchangebase_pubkey_out);
/**
* brief: make_jamtis_viewreceived_pubkey - D_vr
*   - D_vr = D_vr * D_base
* param: d_view_received - d_vr
* param: exchangebase_pubkey - D_base
* outparam: viewreceived_pubkey_out - D_vr
*/
void make_jamtis_viewreceived_pubkey(const crypto::x25519_secret_key &d_view_received,
    const crypto::x25519_pubkey &exchangebase_pubkey,
    crypto::x25519_pubkey &viewreceived_pubkey_out);
/**
* brief: make_jamtis_filterassist_key - filter-assist key, for calculating primary view tags
*   d_fa = H_n_x25519[d_vr]()
* param: d_view_received - d_vr
* outparam: d_filter_assist_out - d_fa
*/
void make_jamtis_filterassist_key(const crypto::x25519_secret_key &d_view_received,
    crypto::x25519_secret_key &d_filter_assist_out);
/**
* brief: make_jamtis_filterassist_pubkey - D_fa
*   - D_fa = d_fa * D_base
* param: d_filter_assist - d_fa
* param: exchangebase_pubkey - D_base
* outparam: filterassist_pubky_out - D_fa
*/
void make_jamtis_filterassist_pubkey(const crypto::x25519_secret_key &d_filter_assist,
    const crypto::x25519_pubkey &exchangebase_pubkey,
    crypto::x25519_pubkey &filterassist_pubkey_out);
/**
* brief: make_jamtis_generateaddress_secret - generate-address secret, for generating addresses
*   s_ga = H_32[d_vr]()
* param: d_view_received - d_vr
* outparam: s_generate_address_out - s_ga
*/
void make_jamtis_generateaddress_secret(const crypto::x25519_secret_key &d_view_received,
    crypto::secret_key &s_generate_address_out);
/**
* brief: make_jamtis_ciphertag_secret - cipher-tag secret, for ciphering address indices to/from address tags
*   s_ct = H_32[s_ga]()
* param: s_generate_address - s_ga
* outparam: s_cipher_tag_out - s_ct
*/
void make_jamtis_ciphertag_secret(const crypto::secret_key &s_generate_address,
    crypto::secret_key &s_cipher_tag_out);

} //namespace jamtis
} //namespace sp

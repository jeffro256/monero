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

// @file Utilities for making and handling enotes with jamtis.

#pragma once

//local headers
#include "crypto/crypto.h"
#include "crypto/x25519.h"
#include "jamtis_support_types.h"
#include "ringct/rctTypes.h"

//third party headers

//standard headers
#include <unordered_map>

//forward declarations
namespace cryptonote { struct subaddress_index; }

namespace sp
{
namespace jamtis
{

/**
* There are three addressing protocol dependent core secrets per enote used to recover all other
* information about that enote:
*     - Filter-assist secret (X_fa): used to calculate the primary view tag
*     - Identify-received secret (X_ir): used to calculate the secondary view tag
*     - Unlock-received secret (X_ur): used to calculate the sender-receiver secret
*
* These values are derived differently depending on A) whether you are sending or receiving, B) which address type you
* use, and C) whether you are trying external vs internal (self-send) Jamtis transfers. Below, we provide a table for
* how X_fa, X_ir, and X_ur should be derived for a given type of enote scanning / construction.
*
* +-------------------------------+-------------------------------------------+-------------+--------------------------+
* |                               |                   X_fa                    |    X_ir     |           X_ur           |
* +-------------------------------+-------------------------------------------+-------------+--------------------------+
* |  Jamtis, external, sender     |                 xr D^j_fa                 |  xr D^j_ir  |           xr G           |
* +-------------------------------+-------------------------------------------+-------------+--------------------------+
* |  Jamtis, external, recipient  |                 d_fa D_e                  |  d_ir D_e   |  1 / (d_ir * d^j_a) D_e  |
* +-------------------------------+-------------------------------------------+-------------+--------------------------+
* |  Jamtis, internal/self-send   |          d_fa D_e  =  xr D^j_fa           |    s_vb     |            ""            |
* +-------------------------------+-------------------------------------------+-------------+--------------------------+
* |  Cryptonote, sender           |  ConvertPubKey1(xr ConvertPubKey2(8 K2))  |     ""      |            ""            |
* +-------------------------------+-------------------------------------------+-------------+--------------------------+
* |  Cryptonote, recipient        |   NormalizeX(8 k_v ConvertPubKey1(D_e))   |     ""      |            ""            | 
* +-------------------------------+-------------------------------------------+-------------+--------------------------+
*/

/**
 * brief: secret256_ptr_t - tiny type for generic pointer to 32 byte secret buffer
 *   note: used to pass X_fa, X_ir, and X_ur
*/
using secret256_ptr_t = const unsigned char*;

/**
* brief: make_jamtis_enote_ephemeral_pubkey - enote ephemeral pubkey D_e
*   D_e = xr D^j_base
* param: enote_ephemeral_privkey - xr
* param: addr_Dbase - D^j_base
* outparam: enote_ephemeral_pubkey_out - D_e
*/
void make_jamtis_enote_ephemeral_pubkey(const crypto::x25519_secret_key &enote_ephemeral_privkey,
    const crypto::x25519_pubkey &addr_Dbase,
    crypto::x25519_pubkey &enote_ephemeral_pubkey_out);
/**
 * brief: make_carrot_enote_ephemeral_privkey - enote ephemeral privkey k_e for Carrot enotes
 *   k_e = (H_64(anchor, b, K^j_s, K^j_v, pid)) mod l
 * param: anchor - anchor
 * param: amount - b
 * param: address_spend_pubkey - K^j_s
 * param: address_view_pubkey - K^j_v
 * param: payment_id - pid
 * outparam: enote_ephemeral_privkey_out - k_e
 */
void make_carrot_enote_ephemeral_privkey(const carrot_anchor_t &anchor,
    const rct::xmr_amount &amount,
    const crypto::public_key &address_spend_pubkey,
    const crypto::public_key &address_view_pubkey,
    const payment_id_t payment_id,
    crypto::secret_key &enote_ephemeral_privkey_out);
/**
 * brief: make_carrot_enote_ephemeral_pubkey - make enote ephemeral pubkey D_e from privkey and destination address
 *   D_e = ConvertPubkey2(k_e ([subaddress: K^j_s] [primary address: G])
 * param: enote_ephemeral_privkey - k_e
 * param: address_spend_pubkey - K^j_s
 * param: is_subaddress - is destination address a subaddress?
 * outparam: enote_ephemeral_pubkey_out - D_e
 */
void make_carrot_enote_ephemeral_pubkey(const crypto::secret_key &enote_ephemeral_privkey,
    const crypto::public_key &address_spend_pubkey,
    const bool is_subaddress,
    crypto::x25519_pubkey &enote_ephemeral_pubkey_out);
/**
 * brief: make_carrot_x_all_recipient - perform the recipient-side ECDH exchange for Carrot enotes
 *   X_fa = X_ir = X_ur = NormalizeX(8 * k_v * ConvertPubkey1(D_e))
 * param: k_view - k_v
 * param: enote_ephemeral_pubkey - D_e
 * outparam: x_all_out - X_fa = X_ir = X_ur
 * return: true if successful, false if a failure occured in point decompression
 */
bool make_carrot_x_all_recipient(const crypto::secret_key &k_view,
    const crypto::x25519_pubkey &enote_ephemeral_pubkey,
    crypto::public_key &x_all_out);
/**
* brief: make_jamtis_view_tag - used for optimized identification of enotes
*    view_tag = H_npbits(D^d_fa, Ko) || H_ncbits(s_svt, Ko)
* param: x_fa - X_fa
* param: x_ir - X_ir
* param: onetime_address - Ko
* param: num_primary_view_tag_bits - npbits
* outparam: view_tag_out - view_tag
*/
void make_jamtis_view_tag(const secret256_ptr_t x_fa,
    const secret256_ptr_t x_ir,
    const rct::key &onetime_address,
    const std::uint8_t num_primary_view_tag_bits,
    view_tag_t &view_tag_out);
/**
* brief: make_jamtis_input_context_coinbase - input context for a sender-receiver secret (coinbase txs)
*    input_context = H_32(block_height)
* param: block_height - block height of the coinbase tx
* outparam: input_context_out - H_32(block height)
*/
void make_jamtis_input_context_coinbase(const std::uint64_t block_height, rct::key &input_context_out);
/**
* brief: make_jamtis_input_context_standard - input context for a sender-receiver secret (standard txs)
*    input_context = H_32({legacy KI}, {seraphis KI})
* param: legacy_input_key_images - {KI} from the legacy inputs of a tx (sorted)
* param: sp_input_key_images - {KI} from the seraphis inputs of a tx (sorted)
* outparam: input_context_out - H_32({legacy KI}, {seraphis KI}})
*/
void make_jamtis_input_context_standard(const std::vector<crypto::key_image> &legacy_input_key_images,
    const std::vector<crypto::key_image> &sp_input_key_images,
    rct::key &input_context_out);
/**
* brief: make_jamtis_sender_receiver_secret - sender-receiver secret q
*    q = H_32(X_fa, X_ir, X_ur, D_e, input_context)
* param: x_fa - X_fa
* param: x_ir - X_ir
* param: x_ur - X_ur
* param: enote_ephemeral_pubkey - D_e
* param: input_context - [normal: H_32({legacy KI}, {seraphis KI})] [coinbase: H_32(block height)]
* outparam: sender_receiver_secret_out - q
*   - note: this is 'rct::key' instead of 'crypto::secret_key' for better performance in multithreaded environments
*/
void make_jamtis_sender_receiver_secret(const secret256_ptr_t x_fa,
    const secret256_ptr_t x_ir,
    const secret256_ptr_t x_ur,
    const crypto::x25519_pubkey &enote_ephemeral_pubkey,
    const rct::key &input_context,
    rct::key &sender_receiver_secret_out);
/**
* brief: make_jamtis_onetime_address_extension_g - extension for transforming a recipient spendkey into an
*        enote one-time address
*    k_{g, sender} = k^o_g = H_n("..g..", q, C)
* param: sender_receiver_secret - q
* param: amount_commitment - C
* outparam: sender_extension_out - k_{g, sender}
*/
void make_jamtis_onetime_address_extension_g(const rct::key &sender_receiver_secret,
    const rct::key &amount_commitment,
    crypto::secret_key &sender_extension_out);
/**
* brief: make_jamtis_onetime_address_extension_x - extension for transforming a recipient spendkey into an
*        enote one-time address
*    k_{x, sender} = k^o_x = H_n("..x..", q, C)
* param: sender_receiver_secret - q
* param: amount_commitment - C
* outparam: sender_extension_out - k_{x, sender}
*/
void make_jamtis_onetime_address_extension_x(const rct::key &sender_receiver_secret,
    const rct::key &amount_commitment,
    crypto::secret_key &sender_extension_out);
/**
* brief: make_jamtis_onetime_address_extension_u - extension for transforming a recipient spendkey into an
*        enote one-time address
*    k_{u, sender} = k^o_u = H_n("..u..", K^j_s, q, C)
* param: sender_receiver_secret - q
* param: amount_commitment - C
* outparam: sender_extension_out - k_{u, sender}
*/
void make_jamtis_onetime_address_extension_u(const rct::key &sender_receiver_secret,
    const rct::key &amount_commitment,
    crypto::secret_key &sender_extension_out);
/**
* brief: make_jamtis_onetime_address_extension_pubkey_sp - create a Seraphis onetime address extension pubkey
*    K^o_ext = k^o_g G + k^o_x X + k^o_u U
* param: sender_receiver_secret - q
* param: amount_commitment - C
* outparam: onetime_address_out - Ko
*/
void make_jamtis_onetime_address_extension_pubkey_sp(const rct::key &sender_receiver_secret,
    const rct::key &amount_commitment,
    rct::key &sender_extension_pubkey_out);
/**
* brief: make_jamtis_onetime_address_extension_pubkey_rct - create a RingCT onetime address extension pubkey
*    K^o_ext = k^o_g G + k^o_u U
* param: sender_receiver_secret - q
* param: amount_commitment - C
* outparam: onetime_address_out - Ko
*/
void make_jamtis_onetime_address_extension_pubkey_rct(const rct::key &sender_receiver_secret,
    const rct::key &amount_commitment,
    rct::key &sender_extension_pubkey_out);
/**
* brief: make_jamtis_onetime_address_sp - create a Seraphis onetime address
*    Ko = K^o_ext + K^j_s = (k^o_g G + k^o_x X + k^o_u U) + K^j_s
* param: recipient_address_spend_key - K^j_s
* param: sender_receiver_secret - q
* param: amount_commitment - C
* outparam: onetime_address_out - Ko
*/
void make_jamtis_onetime_address_sp(const rct::key &recipient_address_spend_key,
    const rct::key &sender_receiver_secret,
    const rct::key &amount_commitment,
    rct::key &onetime_address_out);
/**
* brief: make_jamtis_onetime_address_rct - create a RingCTv2 onetime address
*    Ko = K^o_ext + K^j_s = (k^o_g G + k^o_u U) + K^j_s
* param: recipient_address_spend_key - K^j_s
* param: sender_receiver_secret - q
* param: amount_commitment - C
* outparam: onetime_address_out - Ko
*/
void make_jamtis_onetime_address_rct(const rct::key &recipient_address_spend_key,
    const rct::key &sender_receiver_secret,
    const rct::key &amount_commitment,
    rct::key &onetime_address_out);
/**
* brief: make_jamtis_onetime_address - create a onetime address for given format
*    Ko = ... + K^j_s
* param: recipient_address_spend_key - K^j_s
* param: sender_receiver_secret - q
* param: amount_commitment - C
* outparam: onetime_address_out - Ko
*/
void make_jamtis_onetime_address(const JamtisOnetimeAddressFormat onetime_address_format,
    const rct::key &recipient_address_spend_key,
    const rct::key &sender_receiver_secret,
    const rct::key &amount_commitment,
    rct::key &onetime_address_out);
/**
* brief: make_jamtis_amount_blinding_factor - x for a normal enote's amount commitment C = y G + a H
*   y = H_n(q, enote_type)
* param: sender_receiver_secret - q
* param: enote_type -
* outparam: amount_blinding_factor_out - y
*/
void make_jamtis_amount_blinding_factor(const rct::key &sender_receiver_secret,
    const JamtisEnoteType enote_type,
    crypto::secret_key &amount_blinding_factor_out);
/**
* brief: encrypt_jamtis_address_tag - encrypt an address tag from an enote
*   addr_tag_enc = addr_tag XOR H_16(X_fa, X_ir, Ko)
* param: addr_tag -
* param: x_fa - X_fa
* param: x_ir - X_ir
* return: addr_tag_enc
*/
encrypted_address_tag_t encrypt_jamtis_address_tag(const address_tag_t &addr_tag,
    const secret256_ptr_t x_fa,
    const secret256_ptr_t x_ir,
    const rct::key &onetime_address);
/**
* brief: decrypt_jamtis_address_tag - decrypt an address tag from an enote
*   addr_tag = addr_tag_enc XOR H_16(X_fa, X_ir, Ko)
* param: enc_addr_tag -
* param: x_fa - X_fa
* param: x_ir - X_ir
* return: addr_tag
*/
address_tag_t decrypt_jamtis_address_tag(const encrypted_address_tag_t &enc_addr_tag,
    const secret256_ptr_t x_fa,
    const secret256_ptr_t x_ir,
    const rct::key &onetime_address);
/**
* brief: encrypt_jamtis_amount - encrypt an amount for an enote
*   a_enc = a XOR H_8(q, Ko)
* param: amount - a
* param: sender_receiver_secret - q
* param: onetime_address - Ko
* return: a_enc
*/
encrypted_amount_t encrypt_jamtis_amount(const rct::xmr_amount amount,
    const rct::key &sender_receiver_secret,
    const rct::key &onetime_address);
/**
* brief: decrypt_jamtis_amount - decrypt an amount from an enote
*   a = a_enc XOR H_8(q, Ko)
* param: encrypted_amount - a_enc
* param: sender_receiver_secret - q
* param: onetime_address - Ko
* return: a
*/
rct::xmr_amount decrypt_jamtis_amount(const encrypted_amount_t &encrypted_amount,
    const rct::key &sender_receiver_secret,
    const rct::key &onetime_address);
/**
* brief: encrypt_legacy_payment_id - encrypt a payment ID from an enote
*   pid_enc = pid XOR H_8(q, Ko)
* param: pid -
* param: sender_receiver_secret - q
* param: onetime_address - Ko
* return: pid_enc
*/
encrypted_payment_id_t encrypt_legacy_payment_id(const payment_id_t pid,
    const rct::key &sender_receiver_secret,
    const rct::key &onetime_address);
/**
* brief: decrypt_legacy_payment_id - decrypt a payment ID from an enote
*   pid = pid_enc XOR H_8(q, Ko)
* param: pid_enc -
* param: sender_receiver_secret - q
* param: onetime_address - Ko
* return: pid
*/
payment_id_t decrypt_legacy_payment_id(const encrypted_payment_id_t pid_enc,
    const rct::key &sender_receiver_secret,
    const rct::key &onetime_address);
/**
 * brief: make_carrot_janus_anchor_special - make a janus anchor for "special" enotes
 *   anchor_sp = H_16(q, Ko, k_v, K_s)
 * param: sender_receiver_secret - q
 * param: onetime_address - Ko
 * param: k_view - k_v
 * param: spend_pubkey - K_s
 * outparam: anchor_special_out - anchor_sp
 * note: only to be used for external selfsend enotes in 2-out txs
 */
void make_carrot_janus_anchor_special(const rct::key &sender_receiver_secret,
    const rct::key &onetime_address,
    const crypto::secret_key &k_view,
    const crypto::public_key &spend_pubkey,
    carrot_anchor_t &anchor_special_out);
/**
* brief: recover_recipient_address_spend_key - get the recipient spend key for which this Seraphis onetime address
*                                              can be reconstructed as 'owned' by
*   K^j_s = Ko - K^o_ext = Ko - (k^o_g G + k^o_x X + k^o_u U)
* param: sender_receiver_secret - q
* param: amount_commitment - amount commitment C
* param: onetime_address - Ko
* outparam: recipient_address_spend_key_out: - K^j_s
*/
void recover_recipient_address_spend_key_sp(const rct::key &sender_receiver_secret,
    const rct::key &amount_commitment,
    const rct::key &onetime_address,
    rct::key &recipient_address_spend_key_out);
/**
* brief: recover_recipient_address_spend_key - get the recipient spend key for which this RingCT onetime address
*                                              can be reconstructed as 'owned' by
*   K^j_s = Ko - K^o_ext = Ko - (k^o_g G + k^o_u U)
* param: sender_receiver_secret - q
* param: amount_commitment - amount commitment C
* param: onetime_address - Ko
* outparam: recipient_address_spend_key_out: - K^j_s
*/
void recover_recipient_address_spend_key_rct(const rct::key &sender_receiver_secret,
    const rct::key &amount_commitment,
    const rct::key &onetime_address,
    crypto::public_key &recipient_address_spend_key_out);
/**
* brief: test_jamtis_onetime_address_sp - see if a Seraphis onetime address can be reconstructed
* param: recipient_address_spend_key - recipient's address spendkey K^j_s
* param: sender_receiver_secret - q
* param: amount_commitment - C
* param: expected_onetime_address - onetime address to test Ko
* return: true if the expected onetime address can be reconstructed
*/
bool test_jamtis_onetime_address_sp(const rct::key &recipient_address_spend_key,
    const rct::key &sender_receiver_secret,
    const rct::key &amount_commitment,
    const rct::key &expected_onetime_address);
/**
* brief: test_jamtis_onetime_address_rct - see if a RingCT onetime address can be reconstructed
* param: recipient_address_spend_key - recipient's address spendkey K^j_s
* param: sender_receiver_secret - q
* param: amount_commitment - C
* param: expected_onetime_address - onetime address to test Ko
* return: true if the expected onetime address can be reconstructed
*/
bool test_jamtis_onetime_address_rct(const rct::key &recipient_address_spend_key,
    const rct::key &sender_receiver_secret,
    const rct::key &amount_commitment,
    const rct::key &expected_onetime_address);
/**
* brief: test_jamtis_onetime_address - see if a onetime address can be reconstructed for a given format
* param: onetime_address_format -
* param: recipient_address_spend_key - recipient's address spendkey K^j_s
* param: sender_receiver_secret - q
* param: amount_commitment - C
* param: expected_onetime_address - onetime address to test Ko
* return: true if the expected onetime address can be reconstructed
*/
bool test_jamtis_onetime_address(const jamtis::JamtisOnetimeAddressFormat onetime_address_format,
    const rct::key &recipient_address_spend_key,
    const rct::key &sender_receiver_secret,
    const rct::key &amount_commitment,
    const rct::key &expected_onetime_address);
/**
* brief: test_jamtis_primary_view_tag - test primary view tag
* param: x_fa - X_fa
* param: onetime_address - Ko
* param: view_tag - view_tag
* param: num_primary_view_tag_bits - npbits
* return: true if successfully recomputed the primary view tag
*/
bool test_jamtis_primary_view_tag(const secret256_ptr_t x_fa,
    const rct::key &onetime_address,
    const view_tag_t view_tag,
    const std::uint8_t num_primary_view_tag_bits);
/**
* brief: test_jamtis_primary_view_tag - test primary view tag
* param: d_filter_assist - d_fa
* param: enote_ephemeral_pubkey - D_e = xr D^j_base
* param: onetime_address - Ko
* param: view_tag - view_tag
* param: num_primary_view_tag_bits - npbits
* return: true if successfully recomputed the primary view tag
*/
bool test_jamtis_primary_view_tag(const crypto::x25519_secret_key &d_filter_assist,
    const crypto::x25519_pubkey &enote_ephemeral_pubkey,
    const rct::key &onetime_address,
    const view_tag_t view_tag,
    const std::uint8_t num_primary_view_tag_bits);
/**
* brief: test_jamtis_secondary_view_tag - test secondary view tag
* param: x_ir - X_ir
* param: onetime_address - Ko
* param: view_tag - view_tag
* param: num_primary_view_tag_bits - npbits
* outparam: matched_all_secondary_bits_out - true if all secondary view tag bits match for the entire view tag
* return: true if successfully recomputed the secondary view tag
*/
bool test_jamtis_secondary_view_tag(const secret256_ptr_t x_ir,
    const rct::key &onetime_address,
    const view_tag_t view_tag,
    const std::uint8_t num_primary_view_tag_bits,
    bool &matched_all_secondary_bits_out);
/**
* brief: try_get_jamtis_amount - test recreating the amount commitment; if it is recreate-able, return the amount
* param: sender_receiver_secret - q
* param: onetime_address - Ko
* param: enote_type -
* param: amount_commitment - C = y G + a H
* param: encrypted_amount - enc_a
* outparam: amount_out - a' = dec(enc_a)
* outparam: amount_blinding_factor_out - y'
* return: true if successfully recomputed the amount commitment (C' = y' G + a' H ?= C)
*/
bool try_get_jamtis_amount(const rct::key &sender_receiver_secret,
    const rct::key &onetime_address,
    const JamtisEnoteType enote_type,
    const rct::key &amount_commitment,
    const encrypted_amount_t &encrypted_amount,
    rct::xmr_amount &amount_out,
    crypto::secret_key &amount_blinding_factor_out);
/**
 * brief: verify_carrot_janus_protection - check whether a received Carrot enote is Janus protected
 * param: enote_ephemeral_pubkey - D_e
 * param: onetime_address - Ko
 * param: sender_receiver_secret - q
 * param: amount - a
 * param: nominal_address_spend_pubkey - K^j_s'
 * param: nominal_anchor - anchor'
 * param: nominal_payment_id - pid'
 * param: k_view - k_v
 * param: primary_address_spend_pubkey - K_s
 * outparam: nominal_payment_id_inout - pass possible pid, set to null if the sender didn't explicitly bind to that pid
 * return: true if this received enote is safe from Janus attacks
 */
bool verify_carrot_janus_protection(const crypto::x25519_pubkey &enote_ephemeral_pubkey,
    const rct::key onetime_address,
    const rct::key sender_receiver_secret,
    const rct::xmr_amount &amount,
    const crypto::public_key &nominal_address_spend_pubkey,
    const carrot_anchor_t &nominal_anchor,
    const crypto::secret_key &k_view,
    const crypto::public_key &primary_address_spend_pubkey,
    payment_id_t &nominal_payment_id_inout);

} //namespace jamtis
} //namespace sp

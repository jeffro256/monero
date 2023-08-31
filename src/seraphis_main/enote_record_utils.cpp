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
#include "enote_record_utils.h"

//local headers
#include "crypto/crypto.h"
#include "crypto/x25519.h"
extern "C"
{
#include "crypto/crypto-ops.h"
}
#include "enote_record_types.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "seraphis_core/jamtis_address_tag_utils.h"
#include "seraphis_core/jamtis_address_utils.h"
#include "seraphis_core/jamtis_enote_utils.h"
#include "seraphis_core/jamtis_secret_utils.h"
#include "seraphis_core/jamtis_support_types.h"
#include "seraphis_core/sp_core_enote_utils.h"
#include "seraphis_crypto/sp_crypto_utils.h"
#include "tx_component_types.h"

//third party headers

//standard headers


#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis"

namespace sp
{
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void make_enote_view_extension_g_helper(const rct::key &jamtis_spend_pubkey,
    const crypto::secret_key &s_generate_address,
    const jamtis::address_index_t &j,
    const rct::key &recipient_address_spendkey,  //K_1
    const rct::key &sender_receiver_secret,
    const rct::key &amount_commitment,
    crypto::secret_key &enote_view_extension_g_out)
{
    // enote view privkey extension on g: k_g = k^o_g + k^j_g
    crypto::secret_key spendkey_extension_g;  //k^j_g
    crypto::secret_key sender_extension_g;    //k^o_g
    jamtis::make_jamtis_spendkey_extension_g(jamtis_spend_pubkey, s_generate_address, j, spendkey_extension_g);
    jamtis::make_jamtis_onetime_address_extension_g(recipient_address_spendkey,
        sender_receiver_secret,
        amount_commitment,
        sender_extension_g);

    // k_g = k^o_g + k^j_g
    sc_add(to_bytes(enote_view_extension_g_out), to_bytes(sender_extension_g), to_bytes(spendkey_extension_g));
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void make_enote_view_extension_x_helper(const rct::key &jamtis_spend_pubkey,
    const crypto::secret_key &s_generate_address,
    const jamtis::address_index_t &j,
    const rct::key &recipient_address_spendkey,  //K_1
    const rct::key &sender_receiver_secret,
    const rct::key &amount_commitment,
    crypto::secret_key &enote_view_extension_x_out)
{
    // enote view privkey extension on x: k_x = k^o_x + k^j_x
    crypto::secret_key spendkey_extension_x;  //k^j_x
    crypto::secret_key sender_extension_x;    //k^o_x
    jamtis::make_jamtis_spendkey_extension_x(jamtis_spend_pubkey, s_generate_address, j, spendkey_extension_x);
    jamtis::make_jamtis_onetime_address_extension_x(recipient_address_spendkey,
        sender_receiver_secret,
        amount_commitment,
        sender_extension_x);

    // k_x = k^o_x + k^j_x
    sc_add(to_bytes(enote_view_extension_x_out), to_bytes(sender_extension_x), to_bytes(spendkey_extension_x));
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void make_enote_view_extension_u_helper(const rct::key &jamtis_spend_pubkey,
    const crypto::secret_key &s_generate_address,
    const jamtis::address_index_t &j,
    const rct::key &recipient_address_spendkey,  //K_1
    const rct::key &sender_receiver_secret,
    const rct::key &amount_commitment,
    crypto::secret_key &enote_view_extension_u_out)
{
    // enote view privkey extension on u: k_u = k^o_u + k^j_u
    crypto::secret_key spendkey_extension_u;  //k^j_u
    crypto::secret_key sender_extension_u;    //k^o_u
    jamtis::make_jamtis_spendkey_extension_u(jamtis_spend_pubkey, s_generate_address, j, spendkey_extension_u);
    jamtis::make_jamtis_onetime_address_extension_u(recipient_address_spendkey,
        sender_receiver_secret,
        amount_commitment,
        sender_extension_u);

    // k_u = k^o_u + k^j_u
    sc_add(to_bytes(enote_view_extension_u_out), to_bytes(sender_extension_u), to_bytes(spendkey_extension_u));
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void make_enote_view_extensions_helper(const rct::key &jamtis_spend_pubkey,
    const crypto::secret_key &s_generate_address,
    const jamtis::address_index_t &j,
    const rct::key &recipient_address_spendkey,  //K_1
    const rct::key &sender_receiver_secret,
    const rct::key &amount_commitment,
    crypto::secret_key &enote_view_extension_g_out,
    crypto::secret_key &enote_view_extension_x_out,
    crypto::secret_key &enote_view_extension_u_out)
{
    // 1. construct the enote view privkey for the G component: k_g = k^o_g + k^j_g
    make_enote_view_extension_g_helper(jamtis_spend_pubkey,
        s_generate_address,
        j,
        recipient_address_spendkey,
        sender_receiver_secret,
        amount_commitment,
        enote_view_extension_g_out);

    // 2. construct the enote view privkey for the X component: k_x = k^o_x + k^j_x
    make_enote_view_extension_x_helper(jamtis_spend_pubkey,
        s_generate_address,
        j,
        recipient_address_spendkey,
        sender_receiver_secret,
        amount_commitment,
        enote_view_extension_x_out);

    // 3. construct the enote view privkey for the U component: k_u = k^o_u + k^j_u
    make_enote_view_extension_u_helper(jamtis_spend_pubkey,
        s_generate_address,
        j,
        recipient_address_spendkey,
        sender_receiver_secret,
        amount_commitment,
        enote_view_extension_u_out);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static jamtis::address_index_t decrypt_and_decipher_address_index(const SpEnoteVariant &enote,
    const rct::key &nominal_sender_receiver_secret,
    const jamtis::jamtis_address_tag_cipher_context &cipher_context)
{
    // 1. decrypt address tag addr_tag = addr_tag_enc XOR H_32(q, Ko)
    const jamtis::address_tag_t decrypted_addr_tag = decrypt_address_tag(
        nominal_sender_receiver_secret, onetime_address_ref(enote), addr_tag_enc_ref(enote));

    // 2. j' = decipher[k](addr_tag)
    jamtis::address_index_t nominal_address_index;
    decipher_address_index(cipher_context, decrypted_addr_tag, nominal_address_index);

    return nominal_address_index;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void make_seraphis_key_image_helper(const rct::key &jamtis_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    const crypto::secret_key &enote_view_extension_x,
    const crypto::secret_key &enote_view_extension_u,
    crypto::key_image &key_image_out)
{
    // make key image: (k_u + k_m)/(k_x + k_vb) U
    rct::key spend_pubkey_U_component{jamtis_spend_pubkey};  //k_vb X + k_m U
    reduce_seraphis_spendkey_x(k_view_balance, spend_pubkey_U_component);  //k_m U
    extend_seraphis_spendkey_u(enote_view_extension_u, spend_pubkey_U_component);  //(k_u + k_m) U
    make_seraphis_key_image(add_secrets(enote_view_extension_x, k_view_balance),
        rct::rct2pk(spend_pubkey_U_component),
        key_image_out);  //(k_u + k_m)/(k_x + k_vb) U
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static bool try_get_amount_commitment_information(const SpEnoteVariant &enote,
    const rct::key &sender_receiver_secret,
    const rct::key &amount_baked_key,
    rct::xmr_amount &amount_out,
    crypto::secret_key &amount_blinding_factor_out)
{
    if (const SpCoinbaseEnoteV1 *enote_ptr = enote.try_unwrap<SpCoinbaseEnoteV1>())
    {
        amount_out                 = enote_ptr->core.amount;
        amount_blinding_factor_out = rct::rct2sk(rct::I);
        return true;
    }
    else if (const SpEnoteV1 *enote_ptr = enote.try_unwrap<SpEnoteV1>())
    {
        return jamtis::try_get_jamtis_amount(sender_receiver_secret,
            amount_baked_key,
            enote_ptr->core.amount_commitment,
            enote_ptr->encoded_amount,
            amount_out,
            amount_blinding_factor_out);
    }
    else
        CHECK_AND_ASSERT_THROW_MES(false, "try get amount commitment information: unknown enote type.");

    return false;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static bool check_view_tag_v1(const SpEnoteVariant &enote,
    const crypto::x25519_pubkey &enote_ephemeral_pubkey,
    const rct::key &input_context,
    const crypto::x25519_pubkey &sender_receiver_DH_derivation,
    bool dense_check)
{
    if (dense_check)
    {
        jamtis::dense_view_tag_t dvt;
        jamtis::make_jamtis_dense_view_tag(sender_receiver_DH_derivation,
            onetime_address_ref(enote),
            dvt);

        return dvt == dense_view_tag(enote);
    }
    else // sparse view tag check
    {
        jamtis::sparse_view_tag_t svt;
        jamtis::make_jamtis_sparse_view_tag(sender_receiver_DH_derivation,
            onetime_address_ref(enote),
            svt);

        return svt == sparse_view_tag(enote);
    }
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static bool check_view_tag_v1(const SpEnoteVariant &enote,
    const crypto::x25519_pubkey &enote_ephemeral_pubkey,
    const rct::key &input_context,
    const crypto::x25519_secret_key &xk_dense_or_sparse_view,
    bool dense_check,
    crypto::x25519_pubkey &sender_receiver_DH_derivation_out)
{
    // xK_d_{dv/sv} = xk_{dv/sv} * xK_e
    crypto::x25519_scmul_key(xk_dense_or_sparse_view,
        enote_ephemeral_pubkey,
        sender_receiver_DH_derivation_out);

    return check_view_tag_v1(enote,
        enote_ephemeral_pubkey,
        input_context,
        sender_receiver_DH_derivation_out,
        dense_check);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static bool check_both_view_tags_v1(const SpEnoteVariant &enote,
    const crypto::x25519_pubkey &enote_ephemeral_pubkey,
    const rct::key &input_context,
    const crypto::x25519_secret_key &xk_dense_view,
    const crypto::x25519_secret_key &xk_sparse_view,
    crypto::x25519_pubkey &sender_receiver_DH_derivation_dv_out,
    crypto::x25519_pubkey &sender_receiver_DH_derivation_sv_out,
    bool dense_first = false)
{
    // 1. check first view tag
    if (!check_view_tag_v1(enote,
            enote_ephemeral_pubkey,
            input_context,
            dense_first ? xk_dense_view : xk_sparse_view,
            dense_first,
            dense_first ? sender_receiver_DH_derivation_dv_out : sender_receiver_DH_derivation_sv_out))
        return false;

    // 2. check second view tag
    return check_view_tag_v1(enote,
            enote_ephemeral_pubkey,
            input_context,
            dense_first ? xk_sparse_view : xk_dense_view,
            !dense_first,
            dense_first ? sender_receiver_DH_derivation_sv_out : sender_receiver_DH_derivation_dv_out);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static bool check_opposite_view_tag_v1(const SpBasicEnoteRecordV1 &basic_record,
    const crypto::x25519_secret_key &xk_dense_view,
    const crypto::x25519_secret_key &xk_sparse_view,
    crypto::x25519_pubkey &opposite_sender_receiver_DH_derivation_out)
{
    return check_view_tag_v1(basic_record.enote,
        basic_record.enote_ephemeral_pubkey,
        basic_record.input_context,
        basic_record.dense_check ? xk_sparse_view : xk_dense_view,
        !basic_record.dense_check,
        opposite_sender_receiver_DH_derivation_out);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static bool try_get_plain_info_from_unscanned_enote_v1(
    const SpEnoteVariant &enote,
    const crypto::x25519_pubkey &enote_ephemeral_pubkey,
    const rct::key &input_context,
    const crypto::x25519_secret_key &xk_dense_view,
    const crypto::x25519_secret_key &xk_sparse_view,
    const jamtis::jamtis_address_tag_cipher_context &cipher_context,
    rct::key &nominal_sender_receiver_secret_out,
    jamtis::address_index_t &nominal_address_index_out
)
{
    // 1. check both view tags and get DHs
    crypto::x25519_pubkey sender_receiver_DH_derivation_dv;
    crypto::x25519_pubkey sender_receiver_DH_derivation_sv;
    if (!check_both_view_tags_v1(enote,
            enote_ephemeral_pubkey,
            input_context,
            xk_dense_view,
            xk_sparse_view,
            sender_receiver_DH_derivation_dv,
            sender_receiver_DH_derivation_sv))
        return false;
    
    // 2. get nominal plain sender-receiver secret q' = H_32(xK_d_dv, xK_d_sv, xK_e, input_context)
    jamtis::make_jamtis_sender_receiver_secret_plain(sender_receiver_DH_derivation_dv,
        sender_receiver_DH_derivation_sv,
        enote_ephemeral_pubkey,
        input_context,
        nominal_sender_receiver_secret_out); 

    // 3. get nominal address index j'
    nominal_address_index_out = decrypt_and_decipher_address_index(
        enote, nominal_sender_receiver_secret_out, cipher_context);
    
    return true;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static bool try_get_plain_info_from_basic_record_v1(const SpBasicEnoteRecordV1 &basic_record,
    const crypto::x25519_pubkey &opposite_sender_receiver_DH_derivation,
    const crypto::x25519_secret_key &xk_dense_view,
    const crypto::x25519_secret_key &xk_sparse_view,
    const jamtis::jamtis_address_tag_cipher_context &cipher_context,
    rct::key &nominal_sender_receiver_secret_out,
    jamtis::address_index_t &nominal_address_index_out)
{
    // 1. rederive sender-receiver DH derivation for old, already checked view tag and double-check
    //    view tag for robustness
    crypto::x25519_pubkey old_sender_receiver_DH_derivation;
    if (!check_view_tag_v1(basic_record.enote,
            basic_record.enote_ephemeral_pubkey,
            basic_record.input_context,
            basic_record.dense_check ? xk_dense_view : xk_sparse_view,
            basic_record.dense_check,
            old_sender_receiver_DH_derivation))
        return false;

    // 2. get nominal plain sender-receiver secret q' = H_32(xK_d_dv, xK_d_sv, xK_e, input_context)
    const crypto::x25519_pubkey &dv_DH = basic_record.dense_check ?
        old_sender_receiver_DH_derivation : opposite_sender_receiver_DH_derivation;
    const crypto::x25519_pubkey &sv_DH = basic_record.dense_check ?
        opposite_sender_receiver_DH_derivation : old_sender_receiver_DH_derivation;
    jamtis::make_jamtis_sender_receiver_secret_plain(dv_DH,
        sv_DH,
        basic_record.enote_ephemeral_pubkey,
        basic_record.input_context,
        nominal_sender_receiver_secret_out); 

    // 3. get nominal address index j'
    nominal_address_index_out = decrypt_and_decipher_address_index(
        basic_record.enote, nominal_sender_receiver_secret_out, cipher_context);

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static bool try_get_plain_info_from_basic_record_v1(const SpBasicEnoteRecordV1 &basic_record,
    const crypto::x25519_secret_key &xk_dense_view,
    const crypto::x25519_secret_key &xk_sparse_view,
    const jamtis::jamtis_address_tag_cipher_context &cipher_context,
    rct::key &nominal_sender_receiver_secret_out,
    jamtis::address_index_t &nominal_address_index_out)
{
    // 1. check missing view tag and get corresponding DH derivation
    crypto::x25519_pubkey opposite_sender_receiver_DH_derivation;
    if (!check_opposite_view_tag_v1(basic_record,
            xk_dense_view,
            xk_sparse_view,
            opposite_sender_receiver_DH_derivation))
        return false;

    // 2. Use opposite_sender_receiver_DH_derivation to finish getting the plain info
    return try_get_plain_info_from_basic_record_v1(basic_record,
        opposite_sender_receiver_DH_derivation,
        xk_dense_view,
        xk_sparse_view,
        cipher_context,
        nominal_sender_receiver_secret_out,
        nominal_address_index_out);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static bool try_get_intermediate_record_info_v1_helper(const SpEnoteVariant &enote,
    const crypto::x25519_pubkey &enote_ephemeral_pubkey,
    const jamtis::address_index_t &nominal_address_index,
    const rct::key &nominal_sender_receiver_secret,
    const rct::key &jamtis_spend_pubkey,
    const crypto::x25519_secret_key &xk_unlock_amounts,
    const crypto::secret_key &s_generate_address,
    rct::key &recipient_address_spendkey_out,
    rct::xmr_amount &amount_out,
    crypto::secret_key &amount_blinding_factor_out)
{
    // get intermediate info (validate address index, amount, amount blinding factor) for a plain jamtis enote

    // 1. spend key of address that might own this enote
    jamtis::make_jamtis_address_spend_key(jamtis_spend_pubkey,
        s_generate_address,
        nominal_address_index,
        recipient_address_spendkey_out);

    // 2. check if the spend key owns this enote
    if (!jamtis::test_jamtis_onetime_address(recipient_address_spendkey_out,
            nominal_sender_receiver_secret,
            amount_commitment_ref(enote),
            onetime_address_ref(enote)))
        return false;

    // 3. make the amount commitment baked key
    crypto::x25519_secret_key address_privkey;
    jamtis::make_jamtis_address_privkey(jamtis_spend_pubkey, s_generate_address, nominal_address_index, address_privkey);

    rct::key amount_baked_key;
    jamtis::make_jamtis_amount_baked_key_plain_recipient(address_privkey,
        xk_unlock_amounts,
        enote_ephemeral_pubkey,
        amount_baked_key);

    // 4. try to recover the amount and amount blinding factor
    if (!try_get_amount_commitment_information(enote,
            nominal_sender_receiver_secret,
            amount_baked_key,
            amount_out,
            amount_blinding_factor_out))
        return false;

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void get_final_record_info_v1_helper(const rct::key &sender_receiver_secret,
    const rct::key &amount_commitment,
    const jamtis::address_index_t &j,
    const rct::key &jamtis_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    const crypto::secret_key &s_generate_address,
    const rct::key &recipient_address_spendkey,
    crypto::secret_key &enote_view_extension_g_out,
    crypto::secret_key &enote_view_extension_x_out,
    crypto::secret_key &enote_view_extension_u_out,
    crypto::key_image &key_image_out)
{
    // get final info (enote view privkey, key image)

    // 1. construct the enote view extensions
    make_enote_view_extensions_helper(jamtis_spend_pubkey,
        s_generate_address,
        j,
        recipient_address_spendkey,
        sender_receiver_secret,
        amount_commitment,
        enote_view_extension_g_out,
        enote_view_extension_x_out,
        enote_view_extension_u_out);

    // 2. make the key image: (k_u + k_m)/(k_x + k_vb) U
    make_seraphis_key_image_helper(jamtis_spend_pubkey,
        k_view_balance,
        enote_view_extension_x_out,
        enote_view_extension_u_out,
        key_image_out);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static bool try_get_intermediate_enote_record_v1_finalize(const SpEnoteVariant &enote,
    const crypto::x25519_pubkey &enote_ephemeral_pubkey,
    const rct::key &input_context,
    const jamtis::address_index_t &nominal_address_index,
    const rct::key &nominal_sender_receiver_secret,
    const rct::key &jamtis_spend_pubkey,
    const crypto::x25519_secret_key &xk_unlock_amounts,
    const crypto::secret_key &s_generate_address,
    SpIntermediateEnoteRecordV1 &record_out)
{
    // finalize an intermediate enote record

    // 1. get intermediate info: address spendkey, amount and amount blinding factor
    rct::key recipient_address_spendkey_temp;
    if (!try_get_intermediate_record_info_v1_helper(enote,
            enote_ephemeral_pubkey,
            nominal_address_index,
            nominal_sender_receiver_secret,
            jamtis_spend_pubkey,
            xk_unlock_amounts,
            s_generate_address,
            recipient_address_spendkey_temp,
            record_out.amount,
            record_out.amount_blinding_factor))
        return false;

    // 2. record the enote and sender-receiver secret
    record_out.enote                  = enote;
    record_out.enote_ephemeral_pubkey = enote_ephemeral_pubkey;
    record_out.input_context          = input_context;
    record_out.address_index          = nominal_address_index;

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static bool try_get_enote_record_v1_plain_finalize(const SpEnoteVariant &enote,
    const crypto::x25519_pubkey &enote_ephemeral_pubkey,
    const rct::key &input_context,
    const jamtis::address_index_t &nominal_address_index,
    const rct::key &nominal_sender_receiver_secret,
    const rct::key &jamtis_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    const crypto::x25519_secret_key &xk_unlock_amounts,
    const crypto::secret_key &s_generate_address,
    SpEnoteRecordV1 &record_out)
{
    // finalize an enote record

    // 1. get intermediate info: address spendkey, amount and amount blinding factor
    rct::key recipient_address_spendkey_temp;
    if (!try_get_intermediate_record_info_v1_helper(enote,
            enote_ephemeral_pubkey,
            nominal_address_index,
            nominal_sender_receiver_secret,
            jamtis_spend_pubkey,
            xk_unlock_amounts,
            s_generate_address,
            recipient_address_spendkey_temp,
            record_out.amount,
            record_out.amount_blinding_factor))
        return false;

    // 2. get final info: enote view extensions, key image
    get_final_record_info_v1_helper(nominal_sender_receiver_secret,
        amount_commitment_ref(enote),
        nominal_address_index,
        jamtis_spend_pubkey,
        k_view_balance,
        s_generate_address,
        recipient_address_spendkey_temp,
        record_out.enote_view_extension_g,
        record_out.enote_view_extension_x,
        record_out.enote_view_extension_u,
        record_out.key_image);

    // 3. record the remaining information
    record_out.enote                  = enote;
    record_out.enote_ephemeral_pubkey = enote_ephemeral_pubkey;
    record_out.input_context          = input_context;
    record_out.address_index          = nominal_address_index;
    record_out.type                   = jamtis::JamtisEnoteType::PLAIN;

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static bool try_get_enote_record_v1_selfsend_for_type(const SpEnoteVariant &enote,
    const crypto::x25519_pubkey &enote_ephemeral_pubkey,
    const rct::key &input_context,
    const rct::key &jamtis_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    const crypto::secret_key &s_generate_address,
    const jamtis::jamtis_address_tag_cipher_context &cipher_context,
    const jamtis::JamtisSelfSendType test_type,
    SpEnoteRecordV1 &record_out)
{
    // get an enote record for a specified jamtis selfsend enote type
    //   by this point, both view tags should have already passed

    // 1. sender-receiver secret for specified self-send type
    rct::key q;
    jamtis::make_jamtis_sender_receiver_secret_selfsend(k_view_balance,
        enote_ephemeral_pubkey,
        input_context,
        test_type,
        q);
    
    // 2. j'
    record_out.address_index = decrypt_and_decipher_address_index(enote, q, cipher_context);

    // 3. spend key of address that might own this enote
    rct::key recipient_address_spendkey;
    jamtis::make_jamtis_address_spend_key(jamtis_spend_pubkey,
        s_generate_address,
        record_out.address_index,
        recipient_address_spendkey);

    // 4. save a copy of the amount commitment
    const rct::key amount_commitment{amount_commitment_ref(enote)};

    // 5. check if the spend key owns this enote
    if (!jamtis::test_jamtis_onetime_address(recipient_address_spendkey,
            q,
            amount_commitment,
            onetime_address_ref(enote)))
        return false;

    // 6. compute the amount baked key (selfsend version)
    rct::key amount_baked_key;
    jamtis::make_jamtis_amount_baked_key_selfsend(k_view_balance, q, amount_baked_key);

    // 7. try to recover the amount and blinding factor
    if (!try_get_amount_commitment_information(enote,
            q,
            amount_baked_key,
            record_out.amount,
            record_out.amount_blinding_factor))
        return false;

    // 8. construct enote view extensions
    make_enote_view_extensions_helper(jamtis_spend_pubkey,
        s_generate_address,
        record_out.address_index,
        recipient_address_spendkey,
        q,
        amount_commitment,
        record_out.enote_view_extension_g,
        record_out.enote_view_extension_x,
        record_out.enote_view_extension_u);

    // 9. make key image: (k_u + k_m)/(k_x + k_vb) U
    make_seraphis_key_image_helper(jamtis_spend_pubkey,
        k_view_balance,
        record_out.enote_view_extension_x,
        record_out.enote_view_extension_u,
        record_out.key_image);

    // 10. record the remaining information
    record_out.enote                  = enote;
    record_out.enote_ephemeral_pubkey = enote_ephemeral_pubkey;
    record_out.input_context          = input_context;
    CHECK_AND_ASSERT_THROW_MES(jamtis::try_get_jamtis_enote_type(test_type, record_out.type),
        "getting self-send enote record (v1): could not convert self-send type to enote type (bug).");

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
bool try_get_basic_enote_record_v1(const SpEnoteVariant &enote,
    const crypto::x25519_pubkey &enote_ephemeral_pubkey,
    const rct::key &input_context,
    const crypto::x25519_pubkey &sender_receiver_DH_derivation,
    bool dense_check,
    SpBasicEnoteRecordV1 &basic_record_out)
{
    // get a basic record

    // 1. try to decrypt the address tag
    if (!check_view_tag_v1(enote,
            enote_ephemeral_pubkey,
            input_context,
            sender_receiver_DH_derivation,
            dense_check))
        return false;

    // 2. copy remaining information
    basic_record_out.enote                  = enote;
    basic_record_out.enote_ephemeral_pubkey = enote_ephemeral_pubkey;
    basic_record_out.input_context          = input_context;
    basic_record_out.dense_check            = dense_check;

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool try_get_basic_enote_record_v1(const SpEnoteVariant &enote,
    const crypto::x25519_pubkey &enote_ephemeral_pubkey,
    const rct::key &input_context,
    const crypto::x25519_secret_key &xk_dense_or_sparse_view,
    bool dense_check,
    SpBasicEnoteRecordV1 &basic_record_out)
{
    // compute DH derivation then get basic record

    // sender-receiver DH derivation
    crypto::x25519_pubkey sender_receiver_DH_derivation;
    crypto::x25519_scmul_key(xk_dense_or_sparse_view, enote_ephemeral_pubkey, sender_receiver_DH_derivation);

    return try_get_basic_enote_record_v1(enote,
        enote_ephemeral_pubkey,
        input_context,
        sender_receiver_DH_derivation,
        dense_check,
        basic_record_out);
}
//-------------------------------------------------------------------------------------------------------------------
bool try_get_intermediate_enote_record_v1(const SpEnoteVariant &enote,
    const crypto::x25519_pubkey &enote_ephemeral_pubkey,
    const rct::key &input_context,
    const rct::key &jamtis_spend_pubkey,
    const crypto::x25519_secret_key &xk_unlock_amounts,
    const crypto::x25519_secret_key &xk_dense_view,
    const crypto::x25519_secret_key &xk_sparse_view,
    const crypto::secret_key &s_generate_address,
    const jamtis::jamtis_address_tag_cipher_context &cipher_context,
    SpIntermediateEnoteRecordV1 &record_out)
{
    // try to process basic info then get an intermediate record

    // 1. check both view tags and get plain nominal sender-receiver secret and address index
    rct::key nominal_sender_receiver_secret;
    jamtis::address_index_t nominal_address_index;
    if (!try_get_plain_info_from_unscanned_enote_v1(enote,
            enote_ephemeral_pubkey,
            input_context,
            xk_dense_view,
            xk_sparse_view,
            cipher_context,
            nominal_sender_receiver_secret,
            nominal_address_index))
        return false;

    // 2. try to finalize the intermediate enote record
    if (!try_get_intermediate_enote_record_v1_finalize(enote,
            enote_ephemeral_pubkey,
            input_context,
            nominal_address_index,
            nominal_sender_receiver_secret,
            jamtis_spend_pubkey,
            xk_unlock_amounts,
            s_generate_address,
            record_out))
        return false;

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool try_get_intermediate_enote_record_v1(const SpEnoteVariant &enote,
    const crypto::x25519_pubkey &enote_ephemeral_pubkey,
    const rct::key &input_context,
    const rct::key &jamtis_spend_pubkey,
    const crypto::x25519_secret_key &xk_unlock_amounts,
    const crypto::x25519_secret_key &xk_dense_view,
    const crypto::x25519_secret_key &xk_sparse_view,
    const crypto::secret_key &s_generate_address,
    SpIntermediateEnoteRecordV1 &record_out)
{
    // get cipher context then get an intermediate record
    const jamtis::jamtis_address_tag_cipher_context cipher_context = 
        jamtis::jamtis_address_tag_cipher_context::from_generateaddress_secret(s_generate_address);

    return try_get_intermediate_enote_record_v1(enote,
        enote_ephemeral_pubkey,
        input_context,
        jamtis_spend_pubkey,
        xk_unlock_amounts,
        xk_dense_view,
        xk_sparse_view,
        s_generate_address,
        cipher_context,
        record_out);
}
//-------------------------------------------------------------------------------------------------------------------
bool try_get_intermediate_enote_record_v1(const SpBasicEnoteRecordV1 &basic_record,
    const rct::key &jamtis_spend_pubkey,
    const crypto::x25519_secret_key &xk_unlock_amounts,
    const crypto::x25519_secret_key &xk_dense_view,
    const crypto::x25519_secret_key &xk_sparse_view,
    const crypto::secret_key &s_generate_address,
    const jamtis::jamtis_address_tag_cipher_context &cipher_context,
    SpIntermediateEnoteRecordV1 &record_out)
{
    // process basic record then get an intermediate record

    // 1. try get plain nominal info
    rct::key nominal_sender_receiver_secret;
    jamtis::address_index_t nominal_address_index;
    if (!try_get_plain_info_from_basic_record_v1(basic_record,
            xk_dense_view,
            xk_sparse_view,
            cipher_context,
            nominal_sender_receiver_secret,
            nominal_address_index))
        return false;

    // 2. finalize the intermediate record
    if (!try_get_intermediate_enote_record_v1_finalize(basic_record.enote,
            basic_record.enote_ephemeral_pubkey,
            basic_record.input_context,
            nominal_address_index,
            nominal_sender_receiver_secret,
            jamtis_spend_pubkey,
            xk_unlock_amounts,
            s_generate_address,
            record_out))
        return false;

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool try_get_intermediate_enote_record_v1(const SpBasicEnoteRecordV1 &basic_record,
    const rct::key &jamtis_spend_pubkey,
    const crypto::x25519_secret_key &xk_unlock_amounts,
    const crypto::x25519_secret_key &xk_dense_view,
    const crypto::x25519_secret_key &xk_sparse_view,
    const crypto::secret_key &s_generate_address,
    SpIntermediateEnoteRecordV1 &record_out)
{
    // make cipher context then get an intermediate record
    const jamtis::jamtis_address_tag_cipher_context cipher_context = 
        jamtis::jamtis_address_tag_cipher_context::from_generateaddress_secret(s_generate_address);

    return try_get_intermediate_enote_record_v1(basic_record,
        jamtis_spend_pubkey,
        xk_unlock_amounts,
        xk_dense_view,
        xk_sparse_view,
        s_generate_address,
        cipher_context,
        record_out);
}
//-------------------------------------------------------------------------------------------------------------------
bool try_get_enote_record_v1_plain(const SpEnoteVariant &enote,
    const crypto::x25519_pubkey &enote_ephemeral_pubkey,
    const rct::key &input_context,
    const rct::key &jamtis_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    SpEnoteRecordV1 &record_out)
{
    // try to process basic info then get intermediate record
    crypto::x25519_secret_key xk_unlock_amounts;
    crypto::x25519_secret_key xk_dense_view;
    crypto::x25519_secret_key xk_sparse_view;
    crypto::secret_key s_generate_address;
    crypto::secret_key s_cipher_tag;
    jamtis::make_jamtis_unlockamounts_key(k_view_balance, xk_unlock_amounts);
    jamtis::make_jamtis_denseview_key(k_view_balance, xk_dense_view);
    jamtis::make_jamtis_sparseview_key(k_view_balance, xk_sparse_view);
    jamtis::make_jamtis_generateaddress_secret(k_view_balance, s_generate_address);
    jamtis::make_jamtis_ciphertag_secret(s_generate_address, s_cipher_tag);

    const jamtis::jamtis_address_tag_cipher_context cipher_context{s_cipher_tag};

    // 1. check both view tags and get plain nominal sender-receiver secret and address index
    rct::key nominal_sender_receiver_secret;
    jamtis::address_index_t nominal_address_index;
    if (!try_get_plain_info_from_unscanned_enote_v1(enote,
            enote_ephemeral_pubkey,
            input_context,
            xk_dense_view,
            xk_sparse_view,
            cipher_context,
            nominal_sender_receiver_secret,
            nominal_address_index))
        return false;

    // 2. finalize the enote record
    if (!try_get_enote_record_v1_plain_finalize(enote,
            enote_ephemeral_pubkey,
            input_context,
            nominal_address_index,
            nominal_sender_receiver_secret,
            jamtis_spend_pubkey,
            k_view_balance,
            xk_unlock_amounts,
            s_generate_address,
            record_out))
        return false;

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool try_get_enote_record_v1_plain(const SpBasicEnoteRecordV1 &basic_record,
    const crypto::x25519_pubkey &opposite_sender_receiver_DH_derivation,
    const rct::key &jamtis_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    const crypto::x25519_secret_key &xk_unlock_amounts,
    const crypto::x25519_secret_key &xk_dense_view,
    const crypto::x25519_secret_key &xk_sparse_view,
    const crypto::secret_key &s_generate_address,
    const jamtis::jamtis_address_tag_cipher_context &cipher_context,
    SpEnoteRecordV1 &record_out)
{
    // process basic record then get an enote record

    // 1. try get plain nominal info
    jamtis::address_index_t nominal_address_index;
    rct::key nominal_sender_receiver_secret;
    if (!try_get_plain_info_from_basic_record_v1(basic_record,
            opposite_sender_receiver_DH_derivation,
            xk_dense_view,
            xk_sparse_view,
            cipher_context,
            nominal_sender_receiver_secret,
            nominal_address_index))
        return false;

    // 2. finalize the enote record
    if (!try_get_enote_record_v1_plain_finalize(basic_record.enote,
            basic_record.enote_ephemeral_pubkey,
            basic_record.input_context,
            nominal_address_index,
            nominal_sender_receiver_secret,
            jamtis_spend_pubkey,
            k_view_balance,
            xk_unlock_amounts,
            s_generate_address,
            record_out))
        return false;

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool try_get_enote_record_v1_plain(const SpBasicEnoteRecordV1 &basic_record,
    const rct::key &jamtis_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    const crypto::x25519_secret_key &xk_unlock_amounts,
    const crypto::x25519_secret_key &xk_dense_view,
    const crypto::x25519_secret_key &xk_sparse_view,
    const crypto::secret_key &s_generate_address,
    const jamtis::jamtis_address_tag_cipher_context &cipher_context,
    SpEnoteRecordV1 &record_out)
{
    // 1. try checking opposite view tag
    crypto::x25519_pubkey opposite_sender_receiver_DH_derivation;
    if (!check_opposite_view_tag_v1(basic_record,
            xk_dense_view,
            xk_sparse_view,
            opposite_sender_receiver_DH_derivation))
        return false;
    
    // 2. try get enote record
    return try_get_enote_record_v1_plain(basic_record,
        opposite_sender_receiver_DH_derivation,
        jamtis_spend_pubkey,
        k_view_balance,
        xk_unlock_amounts,
        xk_dense_view,
        xk_sparse_view,
        s_generate_address,
        cipher_context,
        record_out);
}
//-------------------------------------------------------------------------------------------------------------------
bool try_get_enote_record_v1_plain(const SpBasicEnoteRecordV1 &basic_record,
    const rct::key &jamtis_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    SpEnoteRecordV1 &record_out)
{
    // 1. make jamtis account secrets
    crypto::x25519_secret_key xk_unlock_amounts;
    crypto::x25519_secret_key xk_dense_view;
    crypto::x25519_secret_key xk_sparse_view;
    crypto::secret_key s_generate_address;
    crypto::secret_key s_cipher_tag;
    jamtis::make_jamtis_unlockamounts_key(k_view_balance, xk_unlock_amounts);
    jamtis::make_jamtis_denseview_key(k_view_balance, xk_dense_view);
    jamtis::make_jamtis_sparseview_key(k_view_balance, xk_dense_view);
    jamtis::make_jamtis_generateaddress_secret(k_view_balance, s_generate_address);
    jamtis::make_jamtis_ciphertag_secret(s_generate_address, s_cipher_tag);

    const jamtis::jamtis_address_tag_cipher_context cipher_context{s_cipher_tag};

    // 2. try get enote record
    return try_get_enote_record_v1_plain(basic_record,
        jamtis_spend_pubkey,
        k_view_balance,
        xk_unlock_amounts,
        xk_dense_view,
        xk_sparse_view,
        s_generate_address,
        cipher_context,
        record_out);
}
//-------------------------------------------------------------------------------------------------------------------
bool try_get_enote_record_v1_plain(const SpIntermediateEnoteRecordV1 &intermediate_record,
    const rct::key &jamtis_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    SpEnoteRecordV1 &record_out)
{
    return try_get_enote_record_v1_plain(intermediate_record.enote,
        intermediate_record.enote_ephemeral_pubkey,
        intermediate_record.input_context,
        jamtis_spend_pubkey,
        k_view_balance,
        record_out);
}
//-------------------------------------------------------------------------------------------------------------------
bool try_get_enote_record_v1_selfsend(const SpEnoteVariant &enote,
    const crypto::x25519_pubkey &enote_ephemeral_pubkey,
    const rct::key &input_context,
    const rct::key &jamtis_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    const crypto::x25519_secret_key &xk_dense_view,
    const crypto::x25519_secret_key &xk_sparse_view,
    const crypto::secret_key &s_generate_address,
    const jamtis::jamtis_address_tag_cipher_context &cipher_context,
    SpEnoteRecordV1 &record_out)
{
    crypto::x25519_pubkey sender_receiver_DH_derivation_dv;
    crypto::x25519_pubkey sender_receiver_DH_derivation_sv;
    if (!check_both_view_tags_v1(enote,
            enote_ephemeral_pubkey,
            input_context,
            xk_dense_view,
            xk_sparse_view,
            sender_receiver_DH_derivation_dv,
            sender_receiver_DH_derivation_sv))
        return false;

    // try to get an enote record with all the self-send types
    for (unsigned char self_send_type{0};
        self_send_type <= static_cast<unsigned char>(jamtis::JamtisSelfSendType::MAX);
        ++self_send_type)
    {
        if (try_get_enote_record_v1_selfsend_for_type(enote,
                enote_ephemeral_pubkey,
                input_context,
                jamtis_spend_pubkey,
                k_view_balance,
                s_generate_address,
                cipher_context,
                static_cast<jamtis::JamtisSelfSendType>(self_send_type),
                record_out))
        return true;
    }

    return false;
}
//-------------------------------------------------------------------------------------------------------------------
bool try_get_enote_record_v1_selfsend(const SpEnoteVariant &enote,
    const crypto::x25519_pubkey &enote_ephemeral_pubkey,
    const rct::key &input_context,
    const rct::key &jamtis_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    SpEnoteRecordV1 &record_out)
{
    // make generate-address secret and cipher context then get enote record
    crypto::x25519_secret_key xk_dense_view;
    crypto::x25519_secret_key xk_sparse_view;
    crypto::secret_key s_generate_address;
    crypto::secret_key s_cipher_tag;
    jamtis::make_jamtis_denseview_key(k_view_balance, xk_dense_view);
    jamtis::make_jamtis_sparseview_key(k_view_balance, xk_sparse_view);
    jamtis::make_jamtis_generateaddress_secret(k_view_balance, s_generate_address);
    jamtis::make_jamtis_ciphertag_secret(s_generate_address, s_cipher_tag);

    const jamtis::jamtis_address_tag_cipher_context cipher_context{s_cipher_tag};

    return try_get_enote_record_v1_selfsend(enote,
        enote_ephemeral_pubkey,
        input_context,
        jamtis_spend_pubkey,
        k_view_balance,
        xk_dense_view,
        xk_sparse_view,
        s_generate_address,
        cipher_context,
        record_out);
}
//-------------------------------------------------------------------------------------------------------------------
bool try_get_enote_record_v1(const SpEnoteVariant &enote,
    const crypto::x25519_pubkey &enote_ephemeral_pubkey,
    const rct::key &input_context,
    const rct::key &jamtis_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    SpEnoteRecordV1 &record_out)
{
    // note: check for selfsend first since it is very fast for unowned enotes
    //       (assumes selfsends and plain enotes appear in similar quantities)
    return try_get_enote_record_v1_selfsend(enote,
            enote_ephemeral_pubkey,
            input_context,
            jamtis_spend_pubkey,
            k_view_balance,
            record_out) ||
        try_get_enote_record_v1_plain(enote,
            enote_ephemeral_pubkey,
            input_context,
            jamtis_spend_pubkey,
            k_view_balance,
            record_out);
}
//-------------------------------------------------------------------------------------------------------------------
bool try_get_enote_record_v1(const SpBasicEnoteRecordV1 &basic_record,
    const rct::key &jamtis_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    const crypto::x25519_secret_key &xk_unlock_amounts,
    const crypto::x25519_secret_key &xk_dense_view,
    const crypto::x25519_secret_key &xk_sparse_view,
    const crypto::secret_key &s_generate_address,
    const jamtis::jamtis_address_tag_cipher_context &cipher_context,
    SpEnoteRecordV1 &record_out)
{
    static_assert(static_cast<unsigned char>(jamtis::JamtisSelfSendType::MAX) == 2,
        "self-send checks need to be updated here in this function body");

    static constexpr const jamtis::JamtisEnoteType FULL_CHECK_ORDER[] = {
        jamtis::JamtisEnoteType::CHANGE,
        jamtis::JamtisEnoteType::PLAIN,
        jamtis::JamtisEnoteType::SELF_SPEND,
        jamtis::JamtisEnoteType::DUMMY
    };

    // 1. check opposite view tag and get DH
    crypto::x25519_pubkey opposite_sender_receiver_DH_derivation;
    if (!check_opposite_view_tag_v1(basic_record,
            xk_dense_view,
            xk_sparse_view,
            opposite_sender_receiver_DH_derivation))
        return false;

    // 2. Check getting a full record for each enote type in the specified order
    for (const jamtis::JamtisEnoteType enote_type : FULL_CHECK_ORDER)
    {
        if (jamtis::is_jamtis_selfsend_type(enote_type))
        {
            jamtis::JamtisSelfSendType self_send_type = jamtis::JamtisSelfSendType::DUMMY;
            try_get_jamtis_self_send_type(enote_type, self_send_type);
            if (try_get_enote_record_v1_selfsend_for_type(basic_record.enote,
                    basic_record.enote_ephemeral_pubkey,
                    basic_record.input_context,
                    jamtis_spend_pubkey,
                    k_view_balance,
                    s_generate_address,
                    cipher_context,
                    self_send_type,
                    record_out))
                return true;
        }
        else // is plain enote type
        {
            if (try_get_enote_record_v1_plain(basic_record,
                    opposite_sender_receiver_DH_derivation,
                    jamtis_spend_pubkey,
                    k_view_balance,
                    xk_unlock_amounts,
                    xk_dense_view,
                    xk_sparse_view,
                    s_generate_address,
                    cipher_context,
                    record_out))
                return true;
        }
    }

    return false;
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace sp

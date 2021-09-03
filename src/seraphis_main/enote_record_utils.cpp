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
#include "seraphis_core/jamtis_account_secrets.h"
#include "seraphis_core/jamtis_address_tag_utils.h"
#include "seraphis_core/jamtis_address_utils.h"
#include "seraphis_core/jamtis_enote_utils.h"
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
namespace
{
enum class BalanceRecoveryPath
{
    PLAIN,
    EXCLUSIVE_SELFSEND,
    AUXILIARY_SELFSEND
};

static constexpr jamtis::JamtisSelfSendType EXCLUSIVE_SELFSEND_TYPES[2] = {
        jamtis::JamtisSelfSendType::EXCLUSIVE_SELF_SPEND, jamtis::JamtisSelfSendType::EXCLUSIVE_CHANGE};
static constexpr jamtis::JamtisSelfSendType AUXILIARY_SELFSEND_TYPES[2] = {
        jamtis::JamtisSelfSendType::AUXILIARY_SELF_SPEND, jamtis::JamtisSelfSendType::AUXILIARY_CHANGE};
} // anonymous namespace
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static bool try_get_selfsend_types_for_balance_recovery_path(const BalanceRecoveryPath path,
    const jamtis::JamtisSelfSendType *&self_send_types,
    std::size_t &num_self_send_types)
{
    switch (path)
    {
    case BalanceRecoveryPath::PLAIN: return false;
    case BalanceRecoveryPath::EXCLUSIVE_SELFSEND: self_send_types = EXCLUSIVE_SELFSEND_TYPES; num_self_send_types = 2; return true;
    case BalanceRecoveryPath::AUXILIARY_SELFSEND: self_send_types = AUXILIARY_SELFSEND_TYPES; num_self_send_types = 2; return true;
    default:
        throw std::logic_error("bug: unexpected BalanceRecoveryPath enum variant");
    }
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void make_enote_view_extensions_helper(const rct::key &jamtis_spend_pubkey,
    const crypto::secret_key &s_generate_address,
    const jamtis::address_index_t &j,
    const rct::key &recipient_address_spendkey,  //K^j_s
    const rct::key &sender_receiver_secret,
    const rct::key &amount_commitment,
    crypto::secret_key &enote_view_extension_g_out,
    crypto::secret_key &enote_view_extension_x_out,
    crypto::secret_key &enote_view_extension_u_out)
{
    crypto::secret_key spendkey_extension_g, spendkey_extension_x, spendkey_extension_u; // k^j_{g/x/u}
    crypto::secret_key sender_extension_g, sender_extension_x, sender_extension_u; // // k^o_{g/x/u}

    // 1. construct the enote view privkey for the G component: k_g = k^o_g + k^j_g
    jamtis::make_jamtis_spendkey_extension_g(jamtis_spend_pubkey, s_generate_address, j, spendkey_extension_g);
    jamtis::make_jamtis_onetime_address_extension_g(recipient_address_spendkey,
        sender_receiver_secret,
        amount_commitment,
        sender_extension_g);
    sc_add(to_bytes(enote_view_extension_g_out), to_bytes(sender_extension_g), to_bytes(spendkey_extension_g));

    // 2. construct the enote view privkey for the X component: k_x = k^o_x + k^j_x
    jamtis::make_jamtis_spendkey_extension_x(jamtis_spend_pubkey, s_generate_address, j, spendkey_extension_x);
    jamtis::make_jamtis_onetime_address_extension_x(recipient_address_spendkey,
        sender_receiver_secret,
        amount_commitment,
        sender_extension_x);
    sc_add(to_bytes(enote_view_extension_x_out), to_bytes(sender_extension_x), to_bytes(spendkey_extension_x));

    // 3. construct the enote view privkey for the U component: k_u = k^o_u + k^j_u
    jamtis::make_jamtis_spendkey_extension_u(jamtis_spend_pubkey, s_generate_address, j, spendkey_extension_u);
    jamtis::make_jamtis_onetime_address_extension_u(recipient_address_spendkey,
        sender_receiver_secret,
        amount_commitment,
        sender_extension_u);
    sc_add(to_bytes(enote_view_extension_u_out), to_bytes(sender_extension_u), to_bytes(spendkey_extension_u));
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
static bool try_recover_amount_commitment_info(const SpEnoteVariant &enote,
    const crypto::x25519_pubkey &enote_ephemeral_pubkey,
    const rct::key &sender_receiver_secret,
    const rct::key &jamtis_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    const crypto::x25519_secret_key &d_view_received,
    const jamtis::address_index_t &address_index,
    const crypto::secret_key &s_generate_address,
    const BalanceRecoveryPath balance_recovery_path,
    rct::xmr_amount &amount_out,
    crypto::secret_key &amount_blinding_factor_out,
    jamtis::JamtisEnoteType &enote_type_out)
{
    // if this enote is a coinbase enote, extract the public amount info and return
    if (const SpCoinbaseEnoteV1 *enote_ptr = enote.try_unwrap<SpCoinbaseEnoteV1>())
    {
        amount_out                 = enote_ptr->core.amount;
        amount_blinding_factor_out = rct::rct2sk(rct::I);
        enote_type_out             = jamtis::JamtisEnoteType::PLAIN;
        return true;
    }

    // otherwise we should have a normal enote
    const SpEnoteV1 *enote_ptr = enote.try_unwrap<SpEnoteV1>();
    CHECK_AND_ASSERT_THROW_MES(enote_ptr, "unknown enote type in try_get_amount_commitment_info");

    if (balance_recovery_path == BalanceRecoveryPath::PLAIN)
    {
        enote_type_out = jamtis::JamtisEnoteType::PLAIN;

        // d^j_a = H_n_x25519(K_s, j, s^j_gen)
        crypto::x25519_secret_key address_privkey;
        jamtis::make_jamtis_address_privkey(jamtis_spend_pubkey,
            s_generate_address,
            address_index,
            address_privkey);

        // baked_key = H_32(1/(d^j_a * d_vr) * D_e)
        rct::key amount_baked_key;
        jamtis::make_jamtis_amount_baked_key_plain_recipient(address_privkey,
            d_view_received,
            enote_ephemeral_pubkey,
            amount_baked_key);

        return jamtis::try_get_jamtis_amount(sender_receiver_secret,
            amount_baked_key,
            enote_ptr->core.amount_commitment,
            enote_ptr->encoded_amount,
            amount_out,
            amount_blinding_factor_out);
    }
    else // on self-send path
    {
        const jamtis::JamtisSelfSendType *self_send_types_to_check;
        std::size_t num_self_send_types_to_check;
        CHECK_AND_ASSERT_THROW_MES(try_get_selfsend_types_for_balance_recovery_path(balance_recovery_path,
                self_send_types_to_check,
                num_self_send_types_to_check),
            "bug: no self send types provided for non-plain recovery path");

        // for each applicable self send type...
        for (std::size_t i = 0; i < num_self_send_types_to_check; ++i)
        {
            // baked_key = H_32[k_vb](q)
            rct::key amount_baked_key;
            jamtis::make_jamtis_amount_baked_key_selfsend(k_view_balance,
                sender_receiver_secret,
                self_send_types_to_check[i],
                amount_baked_key);

            if (jamtis::try_get_jamtis_amount(sender_receiver_secret,
                amount_baked_key,
                enote_ptr->core.amount_commitment,
                enote_ptr->encoded_amount,
                amount_out,
                amount_blinding_factor_out))
            {
                // we successfully recovered enote amount, write the enote type and return, no more looping needed
                CHECK_AND_ASSERT_THROW_MES(jamtis::try_get_jamtis_enote_type(self_send_types_to_check[i],
                    enote_type_out), "bug: could not convert self-send type into enote type");
                return true;
            }
        }

        return false;
    }
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
template <class SpIntermediateLikeEnoteRecord>
static bool try_core_balance_recovery_v1(const SpEnoteVariant &enote,
    const crypto::x25519_pubkey &enote_ephemeral_pubkey,
    const std::uint8_t num_primary_view_tag_bits,
    const rct::key &input_context,
    const rct::key &jamtis_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    const crypto::x25519_secret_key &d_view_received,
    const crypto::x25519_secret_key &d_filter_assist,
    const crypto::secret_key &s_generate_address,
    const jamtis::jamtis_address_tag_cipher_context &cipher_context,
    const BalanceRecoveryPath balance_recovery_path,
    rct::key &nominal_sender_receiver_secret_out,
    rct::key &recipient_address_spendkey_out,
    jamtis::JamtisEnoteType &enote_type_out,
    SpIntermediateLikeEnoteRecord &record_out) // type must contains a superset of SpIntermediateEnoteRecordV1's fields 
{
    // "Core" balance recovery is the stages from nominal sender receiver secret derivation and
    // before key image calculation for both plain and self-send enotes. We attempt to recover the
    // following information and fill in the corresponding fields of an intermediate record:
    // whether enote is owned, address index, amount, amount blinding factor, enote type

    // derive nominal sender-receiver secret q' for given path
    if (balance_recovery_path == BalanceRecoveryPath::PLAIN)
    {
        // q' = H_32(xr * d_vr * xG, D_e, input_context)
        jamtis::make_jamtis_sender_receiver_secret_plain(d_view_received,
            enote_ephemeral_pubkey,
            enote_ephemeral_pubkey,
            input_context,
            nominal_sender_receiver_secret_out);

        // test complementary view tag
        if (!jamtis::test_jamtis_complementary_view_tag(nominal_sender_receiver_secret_out,
                view_tag_ref(enote),
                num_primary_view_tag_bits))
            return false;
    }
    else // send-send scan path
    {
        // q' = H_32[k_vb](D_e, input_context)
        const bool is_auxiliary_self_send_type = balance_recovery_path == BalanceRecoveryPath::AUXILIARY_SELFSEND;
        jamtis::make_jamtis_sender_receiver_secret_selfsend(k_view_balance,
            enote_ephemeral_pubkey,
            input_context,
            is_auxiliary_self_send_type,
            nominal_sender_receiver_secret_out);
    }

    // addr_tag' = addr_tag_enc XOR H_32(q, Ko)
    const jamtis::address_tag_t addr_tag = jamtis::decrypt_address_tag(
        nominal_sender_receiver_secret_out, onetime_address_ref(enote), addr_tag_enc_ref(enote));

    // j' = decipher[s_ct](addr_tag')
    jamtis::decipher_address_index(cipher_context, addr_tag, record_out.address_index);

    // K^j_s' = k^j_g' G + k^j_x' X + k^j_u' U + K_s'
    jamtis::make_jamtis_address_spend_key(jamtis_spend_pubkey,
        s_generate_address,
        record_out.address_index,
        recipient_address_spendkey_out);

    // [Ko' = k^o_g' G + k^o_x X' + k^o_u U' + K^j_s'] =?= Ko
    if (!jamtis::test_jamtis_onetime_address(recipient_address_spendkey_out,
            nominal_sender_receiver_secret_out,
            amount_commitment_ref(enote),
            onetime_address_ref(enote)))
        return false;

    // D^d_fa = d_fa D_e
    crypto::x25519_pubkey dhe_fa;
    crypto::x25519_scmul_key(d_filter_assist, enote_ephemeral_pubkey, dhe_fa);

    // if we use a standard view tag, check primary tag for correctness
    if (balance_recovery_path != BalanceRecoveryPath::AUXILIARY_SELFSEND)
    {
        if (!jamtis::test_jamtis_primary_view_tag(dhe_fa,
                onetime_address_ref(enote),
                view_tag_ref(enote),
                num_primary_view_tag_bits))
            return false;
    }

    // try to recover amount commitment information: amount & blinding factor
    if (!try_recover_amount_commitment_info(enote,
            enote_ephemeral_pubkey,
            nominal_sender_receiver_secret_out,
            jamtis_spend_pubkey,
            k_view_balance,
            d_view_received,
            record_out.address_index,
            s_generate_address,
            balance_recovery_path,
            record_out.amount,
            record_out.amount_blinding_factor,
            enote_type_out))
        return false;

    // finish filling out intermediate record fields
    record_out.enote = enote;
    record_out.enote_ephemeral_pubkey = enote_ephemeral_pubkey;
    record_out.num_primary_view_tag_bits = num_primary_view_tag_bits;
    record_out.input_context = input_context;

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static bool try_plain_core_balance_recovery_v1(const SpEnoteVariant &enote,
    const crypto::x25519_pubkey &enote_ephemeral_pubkey,
    const std::uint8_t num_primary_view_tag_bits,
    const rct::key &input_context,
    const rct::key &jamtis_spend_pubkey,
    const crypto::x25519_secret_key &d_view_received,
    const crypto::x25519_secret_key &d_filter_assist,
    const crypto::secret_key &s_generate_address,
    const jamtis::jamtis_address_tag_cipher_context &cipher_context,
    SpIntermediateEnoteRecordV1 &record_out)
{
    rct::key dummy_sender_receiver_secret;
    rct::key dummy_recipient_address_spendkey;
    jamtis::JamtisEnoteType dummy_enote_type;
    return try_core_balance_recovery_v1(enote,
        enote_ephemeral_pubkey,
        num_primary_view_tag_bits,
        input_context,
        jamtis_spend_pubkey,
        crypto::null_skey,
        d_view_received,
        d_filter_assist,
        s_generate_address,
        cipher_context,
        BalanceRecoveryPath::PLAIN,
        dummy_sender_receiver_secret,
        dummy_recipient_address_spendkey,
        dummy_enote_type,
        record_out);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static bool try_complete_balance_recovery_v1(const SpEnoteVariant &enote,
    const crypto::x25519_pubkey &enote_ephemeral_pubkey,
    const std::uint8_t num_primary_view_tag_bits,
    const rct::key &input_context,
    const rct::key &jamtis_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    const crypto::x25519_secret_key &d_view_received,
    const crypto::x25519_secret_key &d_filter_assist,
    const crypto::secret_key &s_generate_address,
    const jamtis::jamtis_address_tag_cipher_context &cipher_context,
    const BalanceRecoveryPath balance_recovery_path,
    SpEnoteRecordV1 &record_out)
{
    // "Complete" balance recovery is the all stages of balance recovery after the primary view tag
    // check for both plain and self-send enotes. We attempt to recover the following information
    // and fill in the corresponding fields of a full enote record: whether enote is owned, address
    // index, amount, amount blinding factor, enote type, enote view extensions, key image

    if (balance_recovery_path == BalanceRecoveryPath::AUXILIARY_SELFSEND)
    {
        // test auxiliary self-send view tag
        if (!jamtis::test_jamtis_auxiliary_view_tag(k_view_balance,
                onetime_address_ref(enote),
                view_tag_ref(enote)))
            return false;
    }

    // attempt core balance recovery for given path
    rct::key nominal_sender_receiver_secret;
    rct::key recipient_address_spendkey;
    if (!try_core_balance_recovery_v1(enote,
            enote_ephemeral_pubkey,
            num_primary_view_tag_bits,
            input_context,
            jamtis_spend_pubkey,
            k_view_balance,
            d_view_received,
            d_filter_assist,
            s_generate_address,
            cipher_context,
            balance_recovery_path,
            nominal_sender_receiver_secret,
            recipient_address_spendkey,
            record_out.type,
            record_out))
        return false;

    // make enote view extensions
    make_enote_view_extensions_helper(jamtis_spend_pubkey,
        s_generate_address,
        record_out.address_index,
        recipient_address_spendkey,
        nominal_sender_receiver_secret,
        amount_commitment_ref(enote),
        record_out.enote_view_extension_g,
        record_out.enote_view_extension_x,
        record_out.enote_view_extension_u);

    // make key image: (k_u + k_m)/(k_x + k_vb) U
    make_seraphis_key_image_helper(jamtis_spend_pubkey,
        k_view_balance,
        record_out.enote_view_extension_x,
        record_out.enote_view_extension_u,
        record_out.key_image);

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static bool try_complete_balance_recovery_multipath_v1(const SpEnoteVariant &enote,
    const crypto::x25519_pubkey &enote_ephemeral_pubkey,
    const std::uint8_t num_primary_view_tag_bits,
    const rct::key &input_context,
    const rct::key &jamtis_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    const crypto::x25519_secret_key &d_view_received,
    const crypto::x25519_secret_key &d_filter_assist,
    const crypto::secret_key &s_generate_address,
    const jamtis::jamtis_address_tag_cipher_context &cipher_context,
    const epee::span<const BalanceRecoveryPath> balance_recovery_paths,
    SpEnoteRecordV1 &record_out)
{
    for (size_t i = 0; i < balance_recovery_paths.size(); ++i)
    {
        if (try_complete_balance_recovery_v1(enote,
                enote_ephemeral_pubkey,
                num_primary_view_tag_bits,
                input_context,
                jamtis_spend_pubkey,
                k_view_balance,
                d_view_received,
                d_filter_assist,
                s_generate_address,
                cipher_context,
                balance_recovery_paths[i],
                record_out))
            return true;
    }

    return false;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
bool try_get_basic_enote_record_v1(const SpEnoteVariant &enote,
    const crypto::x25519_pubkey &enote_ephemeral_pubkey,
    const std::uint8_t num_primary_view_tag_bits,
    const rct::key &input_context,
    const crypto::x25519_pubkey &dhe_fa,
    SpBasicEnoteRecordV1 &basic_record_out)
{
    // get a basic record

    // 1. check against primary view tag
    if (!jamtis::test_jamtis_primary_view_tag(dhe_fa,
            onetime_address_ref(enote),
            view_tag_ref(enote),
            num_primary_view_tag_bits))
        return false;

    // 2. copy remaining information
    basic_record_out.enote                  = enote;
    basic_record_out.enote_ephemeral_pubkey = enote_ephemeral_pubkey;
    basic_record_out.input_context          = input_context;
    basic_record_out.passed_exclusive_check = true;

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool try_get_basic_enote_record_v1(const SpEnoteVariant &enote,
    const crypto::x25519_pubkey &enote_ephemeral_pubkey,
    const std::uint8_t num_primary_view_tag_bits,
    const rct::key &input_context,
    const crypto::x25519_secret_key &d_filter_assist,
    SpBasicEnoteRecordV1 &basic_record_out)
{
    // compute DH derivation then get basic record

    // D^d_fa = xr D^j_fa = d_fa D_e
    crypto::x25519_pubkey dhe_fa;
    crypto::x25519_scmul_key(d_filter_assist, enote_ephemeral_pubkey, dhe_fa);

    return try_get_basic_enote_record_v1(enote,
        enote_ephemeral_pubkey,
        num_primary_view_tag_bits,
        input_context,
        dhe_fa,
        basic_record_out);
}
//-------------------------------------------------------------------------------------------------------------------
bool try_get_intermediate_enote_record_v1(const SpEnoteVariant &enote,
    const crypto::x25519_pubkey &enote_ephemeral_pubkey,
    const std::uint8_t num_primary_view_tag_bits,
    const rct::key &input_context,
    const rct::key &jamtis_spend_pubkey,
    const crypto::x25519_secret_key &d_view_received,
    const crypto::x25519_secret_key &d_filter_assist,
    const crypto::secret_key &s_generate_address,
    const jamtis::jamtis_address_tag_cipher_context &cipher_context,
    SpIntermediateEnoteRecordV1 &record_out)
{
    // try to process basic info then get an intermediate record

    // test primary view tag
    if (!jamtis::test_jamtis_primary_view_tag(d_filter_assist,
            enote_ephemeral_pubkey,
            onetime_address_ref(enote),
            view_tag_ref(enote),
            num_primary_view_tag_bits))
        return false;

    return try_plain_core_balance_recovery_v1(enote,
        enote_ephemeral_pubkey,
        num_primary_view_tag_bits,
        input_context,
        jamtis_spend_pubkey,
        d_view_received,
        d_filter_assist,
        s_generate_address,
        cipher_context,
        record_out);
}
//-------------------------------------------------------------------------------------------------------------------
bool try_get_intermediate_enote_record_v1(const SpEnoteVariant &enote,
    const crypto::x25519_pubkey &enote_ephemeral_pubkey,
    const std::uint8_t num_primary_view_tag_bits,
    const rct::key &input_context,
    const rct::key &jamtis_spend_pubkey,
    const crypto::x25519_secret_key &d_view_received,
    const crypto::x25519_secret_key &d_filter_assist,
    const crypto::secret_key &s_generate_address,
    SpIntermediateEnoteRecordV1 &record_out)
{
    // get cipher context then get an intermediate record
    crypto::secret_key s_cipher_tag;
    jamtis::make_jamtis_ciphertag_secret(s_generate_address, s_cipher_tag);

    const jamtis::jamtis_address_tag_cipher_context cipher_context{s_cipher_tag};

    return try_get_intermediate_enote_record_v1(enote,
        enote_ephemeral_pubkey,
        num_primary_view_tag_bits,
        input_context,
        jamtis_spend_pubkey,
        d_view_received,
        d_filter_assist,
        s_generate_address,
        cipher_context,
        record_out);
}
//-------------------------------------------------------------------------------------------------------------------
bool try_get_intermediate_enote_record_v1(const SpBasicEnoteRecordV1 &basic_record,
    const rct::key &jamtis_spend_pubkey,
    const crypto::x25519_secret_key &d_view_received,
    const crypto::x25519_secret_key &d_filter_assist,
    const crypto::secret_key &s_generate_address,
    const jamtis::jamtis_address_tag_cipher_context &cipher_context,
    SpIntermediateEnoteRecordV1 &record_out)
{
    // process basic record then get an intermediate record

    if (!basic_record.passed_exclusive_check)
        return false;

    return try_plain_core_balance_recovery_v1(basic_record.enote,
        basic_record.enote_ephemeral_pubkey,
        basic_record.num_primary_view_tag_bits,
        basic_record.input_context,
        jamtis_spend_pubkey,
        d_view_received,
        d_filter_assist,
        s_generate_address,
        cipher_context,
        record_out);
}
//-------------------------------------------------------------------------------------------------------------------
bool try_get_intermediate_enote_record_v1(const SpBasicEnoteRecordV1 &basic_record,
    const rct::key &jamtis_spend_pubkey,
    const crypto::x25519_secret_key &d_view_received,
    const crypto::x25519_secret_key &d_filter_assist,
    const crypto::secret_key &s_generate_address,
    SpIntermediateEnoteRecordV1 &record_out)
{
    // make cipher context then get an intermediate record
    crypto::secret_key s_cipher_tag;
    jamtis::make_jamtis_ciphertag_secret(s_generate_address, s_cipher_tag);

    const jamtis::jamtis_address_tag_cipher_context cipher_context{s_cipher_tag};

    return try_get_intermediate_enote_record_v1(basic_record,
        jamtis_spend_pubkey,
        d_view_received,
        d_filter_assist,
        s_generate_address,
        cipher_context,
        record_out);
}
//-------------------------------------------------------------------------------------------------------------------
bool try_get_enote_record_v1(const SpBasicEnoteRecordV1 &basic_record,
    const rct::key &jamtis_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    const crypto::x25519_secret_key &d_view_received,
    const crypto::x25519_secret_key &d_filter_assist,
    const crypto::secret_key &s_generate_address,
    const jamtis::jamtis_address_tag_cipher_context &cipher_context,
    SpEnoteRecordV1 &record_out)
{
    constexpr BalanceRecoveryPath ALL_PATHS[] = {
        BalanceRecoveryPath::PLAIN,
        BalanceRecoveryPath::EXCLUSIVE_SELFSEND,
        BalanceRecoveryPath::AUXILIARY_SELFSEND };

    constexpr BalanceRecoveryPath AUX_PATH[] = { BalanceRecoveryPath::AUXILIARY_SELFSEND };

    const auto paths_to_try = basic_record.passed_exclusive_check
        ? epee::span<const BalanceRecoveryPath>(ALL_PATHS)
        : epee::span<const BalanceRecoveryPath>(AUX_PATH);

    return try_complete_balance_recovery_multipath_v1(basic_record.enote,
        basic_record.enote_ephemeral_pubkey,
        basic_record.num_primary_view_tag_bits,
        basic_record.input_context,
        jamtis_spend_pubkey,
        k_view_balance,
        d_view_received,
        d_filter_assist,
        s_generate_address,
        cipher_context,
        paths_to_try,
        record_out);
}
//-------------------------------------------------------------------------------------------------------------------
bool try_get_enote_record_v1(const SpEnoteVariant &enote,
    const crypto::x25519_pubkey &enote_ephemeral_pubkey,
    const std::uint8_t num_primary_view_tag_bits,
    const rct::key &input_context,
    const rct::key &jamtis_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    SpEnoteRecordV1 &record_out)
{
    // 1. generate account secrets tree from k_vb
    crypto::x25519_secret_key d_view_received;
    crypto::x25519_secret_key d_filter_assist;
    crypto::secret_key s_generate_address;
    crypto::secret_key s_cipher_tag;
    jamtis::make_jamtis_viewreceived_key(k_view_balance, d_view_received);
    jamtis::make_jamtis_filterassist_key(d_view_received, d_filter_assist);
    jamtis::make_jamtis_generateaddress_secret(d_view_received, s_generate_address);
    jamtis::make_jamtis_ciphertag_secret(s_generate_address, s_cipher_tag);

    const jamtis::jamtis_address_tag_cipher_context cipher_context{s_cipher_tag};

    // 2. do primary DH and primary view tag check
    const bool view_tag_match = jamtis::test_jamtis_primary_view_tag(d_filter_assist,
        enote_ephemeral_pubkey,
        onetime_address_ref(enote),
        view_tag_ref(enote),
        num_primary_view_tag_bits);

    // 3. if the primary view tag matched, try scanning for plain and exclusive self-send enotes
    constexpr BalanceRecoveryPath ALL_PATHS[] = {
        BalanceRecoveryPath::AUXILIARY_SELFSEND,
        BalanceRecoveryPath::PLAIN,
        BalanceRecoveryPath::EXCLUSIVE_SELFSEND};

    const epee::span<const BalanceRecoveryPath> paths_to_check(ALL_PATHS,
        view_tag_match ? 3 : 1);

    // 4. if the other paths fail, always try auxiliary scanning since we have no tx information
    return try_complete_balance_recovery_multipath_v1(enote,
        enote_ephemeral_pubkey,
        num_primary_view_tag_bits,
        input_context,
        jamtis_spend_pubkey,
        k_view_balance,
        d_view_received,
        d_filter_assist,
        s_generate_address,
        cipher_context,
        paths_to_check,
        record_out);
}
//-------------------------------------------------------------------------------------------------------------------
bool try_get_enote_record_v1(const SpIntermediateEnoteRecordV1 &intermediate_record,
    const rct::key &jamtis_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    SpEnoteRecordV1 &record_out)
{
    return try_get_enote_record_v1(intermediate_record.enote,
        intermediate_record.enote_ephemeral_pubkey,
        intermediate_record.num_primary_view_tag_bits,
        intermediate_record.input_context,
        jamtis_spend_pubkey,
        k_view_balance,
        record_out);
}
//-------------------------------------------------------------------------------------------------------------------
bool try_get_enote_record_plain_v1(const SpBasicEnoteRecordV1 &basic_record,
    const rct::key &jamtis_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    const crypto::x25519_secret_key &d_view_received,
    const crypto::x25519_secret_key &d_filter_assist,
    const crypto::secret_key &s_generate_address,
    const jamtis::jamtis_address_tag_cipher_context &cipher_context,
    SpEnoteRecordV1 &record_out)
{
    if (!basic_record.passed_exclusive_check)
        return false;

    jamtis::JamtisEnoteType enote_type{};
    if (!try_complete_balance_recovery_v1(basic_record.enote,
            basic_record.enote_ephemeral_pubkey,
            basic_record.num_primary_view_tag_bits,
            basic_record.input_context,
            jamtis_spend_pubkey,
            k_view_balance,
            d_view_received,
            d_filter_assist,
            s_generate_address,
            cipher_context,
            BalanceRecoveryPath::PLAIN,
            record_out))
        return false;

    return enote_type == jamtis::JamtisEnoteType::PLAIN;
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace sp

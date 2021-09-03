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
#include <functional>


#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis"

namespace sp
{
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void make_enote_view_extensions_helper(const rct::key &jamtis_spend_pubkey,
    const crypto::secret_key &s_generate_address,
    const jamtis::address_index_t &j,
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
    jamtis::make_jamtis_onetime_address_extension_g(sender_receiver_secret,
        amount_commitment,
        sender_extension_g);
    sc_add(to_bytes(enote_view_extension_g_out), to_bytes(sender_extension_g), to_bytes(spendkey_extension_g));

    // 2. construct the enote view privkey for the X component: k_x = k^o_x + k^j_x
    jamtis::make_jamtis_spendkey_extension_x(jamtis_spend_pubkey, s_generate_address, j, spendkey_extension_x);
    jamtis::make_jamtis_onetime_address_extension_x(sender_receiver_secret,
        amount_commitment,
        sender_extension_x);
    sc_add(to_bytes(enote_view_extension_x_out), to_bytes(sender_extension_x), to_bytes(spendkey_extension_x));

    // 3. construct the enote view privkey for the U component: k_u = k^o_u + k^j_u
    jamtis::make_jamtis_spendkey_extension_u(jamtis_spend_pubkey, s_generate_address, j, spendkey_extension_u);
    jamtis::make_jamtis_onetime_address_extension_u(sender_receiver_secret,
        amount_commitment,
        sender_extension_u);
    sc_add(to_bytes(enote_view_extension_u_out), to_bytes(sender_extension_u), to_bytes(spendkey_extension_u));
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void make_seraphis_key_image_helper(const rct::key &jamtis_spend_pubkey,
    const crypto::secret_key &k_generate_image,
    SpEnoteRecordV1 &enote_record_inout)
{
    // make key image: (k_u + k_ps)/(k_x + k_gi) U
    rct::key spend_pubkey_U_component{jamtis_spend_pubkey};  //k_gi X + k_ps U
    reduce_seraphis_spendkey_x(k_generate_image, spend_pubkey_U_component);  //k_ps U
    extend_seraphis_spendkey_u(enote_record_inout.enote_view_extension_u, spend_pubkey_U_component);  //(k_u + k_m) U
    make_seraphis_key_image(add_secrets(enote_record_inout.enote_view_extension_x, k_generate_image),
        rct::rct2pk(spend_pubkey_U_component),
        enote_record_inout.key_image);  //(k_u + k_ps)/(k_x + k_gi) U
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void make_ringct_key_image_helper(const crypto::secret_key &k_generate_image,
    SpEnoteRecordV1 &enote_record_inout)
{
    // x = k_gi + k^view_g where Ko = x G + y T
    crypto::secret_key x;
    sc_add(to_bytes(x), to_bytes(k_generate_image), to_bytes(enote_record_inout.enote_view_extension_g));

    // L = x Hp(Ko)
    crypto::generate_key_image(rct::rct2pk(onetime_address_ref(enote_record_inout.enote)),
        x,
        enote_record_inout.key_image);

}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void make_key_image_helper(const jamtis::JamtisOnetimeAddressFormat onetime_address_format,
    const rct::key &jamtis_spend_pubkey,
    const crypto::secret_key &k_generate_image,
    SpEnoteRecordV1 &enote_record_inout)
{
    switch (onetime_address_format)
    {
    case jamtis::JamtisOnetimeAddressFormat::SERAPHIS:
        make_seraphis_key_image_helper(jamtis_spend_pubkey, k_generate_image, enote_record_inout);
        return;
    case jamtis::JamtisOnetimeAddressFormat::RINGCT_V2:
        make_ringct_key_image_helper(k_generate_image, enote_record_inout);
        return;
    default:
        ASSERT_MES_AND_THROW("make ringct key image helper: unrecognized onetime address format");
    }
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
struct lazy_scmul_key
{
    const crypto::x25519_scalar &privkey;
    const crypto::x25519_pubkey &pubkey;
    crypto::x25519_pubkey dhe;
    bool done{false};
    jamtis::secret256_ptr_t operator()()
    {
        if (!done)
        {
            crypto::x25519_scmul_key(privkey, pubkey, dhe);
            done = true;
        }
        return dhe.data;
    }
};
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
struct lazy_make_x_ur_plain
{
    const rct::key &jamtis_spend_pubkey;
    const crypto::secret_key &s_generate_address;
    const jamtis::address_index_t &j;
    const crypto::x25519_scalar &d_unlock_received;
    const crypto::x25519_pubkey &enote_ephemeral_pubkey;
    crypto::x25519_pubkey x_ur;
    bool done{false};
    jamtis::secret256_ptr_t operator()()
    {
        if (!done)
        {
            crypto::x25519_secret_key address_privkey;
            jamtis::make_jamtis_address_privkey(jamtis_spend_pubkey, s_generate_address, j, address_privkey);
            crypto::x25519_invmul_key({d_unlock_received, address_privkey}, enote_ephemeral_pubkey, x_ur);
            done = true;
        }
        return x_ur.data;
    }
};
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static bool try_recover_amount_commitment_info(const SpEnoteVariant &enote,
    const rct::key &sender_receiver_secret,
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
    CHECK_AND_ASSERT_THROW_MES(enote_ptr, "unknown enote type in try_recover_amount_commitment_info");

    // for each enote type...
    for (unsigned char i = 0; i <= static_cast<unsigned char>(jamtis::JamtisEnoteType::MAX); ++i)
    {
        enote_type_out = static_cast<jamtis::JamtisEnoteType>(i);

        // compute y' = H_32(q, enote_type) and a' = enc_amount XOR H_8(q, Ko) and check C ?= a' H + y' G
        if (jamtis::try_get_jamtis_amount(sender_receiver_secret,
                enote_ptr->core.onetime_address,
                enote_type_out,
                enote_ptr->core.amount_commitment,
                enote_ptr->encrypted_amount,
                amount_out,
                amount_blinding_factor_out))
            return true;
    }

    return false;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
template <class MakeXfa, class MakeXur, class SpIntermediateLikeEnoteRecord>
static bool try_core_balance_recovery_v1(const SpEnoteVariant &enote,
    const crypto::x25519_pubkey &enote_ephemeral_pubkey,
    const std::uint8_t num_primary_view_tag_bits,
    const rct::key &input_context,
    const rct::key &jamtis_spend_pubkey,
    MakeXfa &&make_x_fa, // () -> jamtis::secret256_ptr_t functional object
    const jamtis::secret256_ptr_t x_ir,
    MakeXur &&make_x_ur, // () -> jamtis::secret256_ptr_t functional object
    const crypto::secret_key &s_generate_address,
    const jamtis::jamtis_address_tag_cipher_context &cipher_context,
    const jamtis::JamtisOnetimeAddressFormat onetime_address_format,
    rct::key &nominal_sender_receiver_secret_out,
    rct::key &recipient_address_spendkey_out,
    jamtis::JamtisEnoteType &enote_type_out,
    SpIntermediateLikeEnoteRecord &record_out) // type must contains a superset of SpIntermediateEnoteRecordV1's fields 
{
    // "core" balance recovery is the stages from secondary view tag recomputation and
    // before key image calculation for both plain and self-send enotes. We attempt to recover the
    // following information and fill in the corresponding fields of an intermediate record:
    // whether enote is owned, address index, amount, amount blinding factor, enote type

    // check secondary view tag
    bool matched_all_secondary_bits{false};
    if (!jamtis::test_jamtis_secondary_view_tag(x_ir,
            onetime_address_ref(enote),
            view_tag_ref(enote),
            num_primary_view_tag_bits,
            matched_all_secondary_bits))
        return false;

    // derive X_fa
    const jamtis::secret256_ptr_t x_fa{make_x_fa()};

    // check primary view tag if not possibly a 'hidden' enote
    if (!matched_all_secondary_bits)
        if (!jamtis::test_jamtis_primary_view_tag(x_fa,
                onetime_address_ref(enote),
                view_tag_ref(enote),
                num_primary_view_tag_bits))
            return false;

    // addr_tag' = addr_tag_enc XOR H_32(x_fa, x_ir, Ko)
    const jamtis::address_tag_t addr_tag = jamtis::decrypt_jamtis_address_tag(addr_tag_enc_ref(enote), x_fa, x_ir,
        onetime_address_ref(enote));

    // j' = decipher[s_ct](addr_tag')
    jamtis::decipher_address_index(cipher_context, addr_tag, record_out.address_index);

    // K^j_s' = k^j_g' G + k^j_x' X + k^j_u' U + K_s'
    jamtis::make_jamtis_address_spend_key(onetime_address_format,
        jamtis_spend_pubkey,
        s_generate_address,
        record_out.address_index,
        recipient_address_spendkey_out);
    
    // derive X_ur
    const jamtis::secret256_ptr_t x_ur{make_x_ur()};
    
    // derive nominal sender-receiver secret q' = H_32(X_fa, X_ir, X_ur, D_e, input_context)
    jamtis::make_jamtis_sender_receiver_secret(x_fa, x_ir, x_ur, enote_ephemeral_pubkey, input_context,
        nominal_sender_receiver_secret_out);

    // [Ko' = k^o_g' G + k^o_x X' + k^o_u U' + K^j_s'] =?= Ko
    if (!jamtis::test_jamtis_onetime_address(onetime_address_format,
            recipient_address_spendkey_out,
            nominal_sender_receiver_secret_out,
            amount_commitment_ref(enote),
            onetime_address_ref(enote)))
        return false;

    // try to recover amount commitment information: amount & blinding factor
    if (!try_recover_amount_commitment_info(enote,
            nominal_sender_receiver_secret_out,
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
    const crypto::x25519_secret_key &d_unlock_received,
    const crypto::x25519_secret_key &d_identify_received,
    const crypto::x25519_secret_key &d_filter_assist,
    const crypto::secret_key &s_generate_address,
    const jamtis::jamtis_address_tag_cipher_context &cipher_context,
    const jamtis::JamtisOnetimeAddressFormat onetime_address_format,
    SpIntermediateEnoteRecordV1 &record_out)
{
    // X_ir = d_ir D_e
    crypto::x25519_pubkey x_ir;
    crypto::x25519_scmul_key(d_identify_received, enote_ephemeral_pubkey, x_ir);

    rct::key dummy_sender_receiver_secret;
    rct::key dummy_recipient_address_spendkey;
    jamtis::JamtisEnoteType dummy_enote_type;
    return try_core_balance_recovery_v1(enote,
        enote_ephemeral_pubkey,
        num_primary_view_tag_bits,
        input_context,
        jamtis_spend_pubkey,
        lazy_scmul_key{d_filter_assist, enote_ephemeral_pubkey},
        x_ir.data,
        lazy_make_x_ur_plain{jamtis_spend_pubkey, s_generate_address, record_out.address_index,
            d_unlock_received, enote_ephemeral_pubkey},
        s_generate_address,
        cipher_context,
        onetime_address_format,
        dummy_sender_receiver_secret,
        dummy_recipient_address_spendkey,
        dummy_enote_type,
        record_out);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
template <class MakeXfa, class MakeXur>
static bool try_complete_balance_recovery_v1(const SpEnoteVariant &enote,
    const crypto::x25519_pubkey &enote_ephemeral_pubkey,
    const std::uint8_t num_primary_view_tag_bits,
    const rct::key &input_context,
    const rct::key &jamtis_spend_pubkey,
    MakeXfa &&make_x_fa, // () -> jamtis::secret256_ptr_t functional object
    const jamtis::secret256_ptr_t x_ir,
    MakeXur &&make_x_ur, // (jamtis::address_index_t) -> jamtis::secret256_ptr_t functional object
    const crypto::secret_key &k_generate_image,
    const crypto::secret_key &s_generate_address,
    const jamtis::jamtis_address_tag_cipher_context &cipher_context,
    const jamtis::JamtisOnetimeAddressFormat onetime_address_format,
    SpEnoteRecordV1 &record_out)
{
    // "complete" balance recovery is the all stages of balance recovery after the primary view tag
    // check for both plain and self-send enotes. We attempt to recover the following information
    // and fill in the corresponding fields of a full enote record: whether enote is owned, address
    // index, amount, amount blinding factor, enote type, enote view extensions, key image

    // attempt core balance recovery for given path
    rct::key nominal_sender_receiver_secret;
    rct::key recipient_address_spendkey;
    if (!try_core_balance_recovery_v1(enote,
            enote_ephemeral_pubkey,
            num_primary_view_tag_bits,
            input_context,
            jamtis_spend_pubkey,
            make_x_fa,
            x_ir,
            make_x_ur,
            s_generate_address,
            cipher_context,
            onetime_address_format,
            nominal_sender_receiver_secret,
            recipient_address_spendkey,
            record_out.type,
            record_out))
        return false;

    // make enote view extensions
    make_enote_view_extensions_helper(jamtis_spend_pubkey,
        s_generate_address,
        record_out.address_index,
        nominal_sender_receiver_secret,
        amount_commitment_ref(enote),
        record_out.enote_view_extension_g,
        record_out.enote_view_extension_x,
        record_out.enote_view_extension_u);

    // make key image:
    //   * Seraphis: (k_u + k_ps)/(k_x + k_gi) U
    //   * RingCT: (k_g + k_gi) Hp(Ko)
    make_key_image_helper(onetime_address_format,
        jamtis_spend_pubkey,
        k_generate_image,
        record_out);

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
bool try_get_basic_enote_record_v1(const SpEnoteVariant &enote,
    const crypto::x25519_pubkey &enote_ephemeral_pubkey,
    const std::uint8_t num_primary_view_tag_bits,
    const rct::key &input_context,
    const crypto::x25519_pubkey x_fa,
    SpBasicEnoteRecordV1 &basic_record_out)
{
    // get a basic record

    // 1. check against primary view tag
    if (!jamtis::test_jamtis_primary_view_tag(x_fa.data,
            onetime_address_ref(enote),
            view_tag_ref(enote),
            num_primary_view_tag_bits))
        return false;

    // 2. copy remaining information
    basic_record_out.enote                     = enote;
    basic_record_out.enote_ephemeral_pubkey    = enote_ephemeral_pubkey;
    basic_record_out.num_primary_view_tag_bits = num_primary_view_tag_bits;
    basic_record_out.input_context             = input_context;
    basic_record_out.primary_vt_matches        = true;

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

    // X_fa = xr D^j_fa = d_fa D_e
    crypto::x25519_pubkey x_fa;
    crypto::x25519_scmul_key(d_filter_assist, enote_ephemeral_pubkey, x_fa);

    return try_get_basic_enote_record_v1(enote,
        enote_ephemeral_pubkey,
        num_primary_view_tag_bits,
        input_context,
        x_fa,
        basic_record_out);
}
//-------------------------------------------------------------------------------------------------------------------
bool try_get_intermediate_enote_record_v1(const SpEnoteVariant &enote,
    const crypto::x25519_pubkey &enote_ephemeral_pubkey,
    const std::uint8_t num_primary_view_tag_bits,
    const rct::key &input_context,
    const rct::key &jamtis_spend_pubkey,
    const crypto::x25519_secret_key &d_unlock_received,
    const crypto::x25519_secret_key &d_identify_received,
    const crypto::x25519_secret_key &d_filter_assist,
    const crypto::secret_key &s_generate_address,
    const jamtis::jamtis_address_tag_cipher_context &cipher_context,
    SpIntermediateEnoteRecordV1 &record_out,
    const jamtis::JamtisOnetimeAddressFormat onetime_address_format)
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
        d_unlock_received,
        d_identify_received,
        d_filter_assist,
        s_generate_address,
        cipher_context,
        onetime_address_format,
        record_out);
}
//-------------------------------------------------------------------------------------------------------------------
bool try_get_intermediate_enote_record_v1(const SpEnoteVariant &enote,
    const crypto::x25519_pubkey &enote_ephemeral_pubkey,
    const std::uint8_t num_primary_view_tag_bits,
    const rct::key &input_context,
    const rct::key &jamtis_spend_pubkey,
    const crypto::x25519_secret_key &d_unlock_received,
    const crypto::x25519_secret_key &d_identify_received,
    const crypto::x25519_secret_key &d_filter_assist,
    const crypto::secret_key &s_generate_address,
    SpIntermediateEnoteRecordV1 &record_out,
    const jamtis::JamtisOnetimeAddressFormat onetime_address_format)
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
        d_unlock_received,
        d_identify_received,
        d_filter_assist,
        s_generate_address,
        cipher_context,
        record_out);
}
//-------------------------------------------------------------------------------------------------------------------
bool try_get_intermediate_enote_record_v1(const SpBasicEnoteRecordV1 &basic_record,
    const rct::key &jamtis_spend_pubkey,
    const crypto::x25519_secret_key &d_unlock_received,
    const crypto::x25519_secret_key &d_identify_received,
    const crypto::x25519_secret_key &d_filter_assist,
    const crypto::secret_key &s_generate_address,
    const jamtis::jamtis_address_tag_cipher_context &cipher_context,
    SpIntermediateEnoteRecordV1 &record_out,
    const jamtis::JamtisOnetimeAddressFormat onetime_address_format)
{
    // process basic record then get an intermediate record

    if (!basic_record.primary_vt_matches)
        return false;

    return try_plain_core_balance_recovery_v1(basic_record.enote,
        basic_record.enote_ephemeral_pubkey,
        basic_record.num_primary_view_tag_bits,
        basic_record.input_context,
        jamtis_spend_pubkey,
        d_unlock_received,
        d_identify_received,
        d_filter_assist,
        s_generate_address,
        cipher_context,
        onetime_address_format,
        record_out);
}
//-------------------------------------------------------------------------------------------------------------------
bool try_get_intermediate_enote_record_v1(const SpBasicEnoteRecordV1 &basic_record,
    const rct::key &jamtis_spend_pubkey,
    const crypto::x25519_secret_key &d_unlock_received,
    const crypto::x25519_secret_key &d_identify_received,
    const crypto::x25519_secret_key &d_filter_assist,
    const crypto::secret_key &s_generate_address,
    SpIntermediateEnoteRecordV1 &record_out,
    const jamtis::JamtisOnetimeAddressFormat onetime_address_format)
{
    // make cipher context then get an intermediate record
    crypto::secret_key s_cipher_tag;
    jamtis::make_jamtis_ciphertag_secret(s_generate_address, s_cipher_tag);

    const jamtis::jamtis_address_tag_cipher_context cipher_context{s_cipher_tag};

    return try_get_intermediate_enote_record_v1(basic_record,
        jamtis_spend_pubkey,
        d_unlock_received,
        d_identify_received,
        d_filter_assist,
        s_generate_address,
        cipher_context,
        record_out);
}
//-------------------------------------------------------------------------------------------------------------------
bool try_get_enote_record_v1(const SpBasicEnoteRecordV1 &basic_record,
    const rct::key &jamtis_spend_pubkey,
    const crypto::secret_key &s_view_balance,
    const crypto::secret_key &k_generate_image,
    const crypto::x25519_secret_key &d_unlock_received,
    const crypto::x25519_secret_key &d_identify_received,
    const crypto::x25519_secret_key &d_filter_assist,
    const crypto::secret_key &s_generate_address,
    const jamtis::jamtis_address_tag_cipher_context &cipher_context,
    SpEnoteRecordV1 &record_out,
    const jamtis::JamtisOnetimeAddressFormat onetime_address_format)
{
    lazy_scmul_key make_x_fa{d_filter_assist, basic_record.enote_ephemeral_pubkey};

    if (basic_record.primary_vt_matches)
    {
        // X_ir = d_ir D_e
        crypto::x25519_pubkey x_ir;
        crypto::x25519_scmul_key(d_identify_received, basic_record.enote_ephemeral_pubkey, x_ir);

        if (try_complete_balance_recovery_v1(basic_record.enote,
                basic_record.enote_ephemeral_pubkey,
                basic_record.num_primary_view_tag_bits,
                basic_record.input_context,
                jamtis_spend_pubkey,
                make_x_fa,
                x_ir.data,
                lazy_make_x_ur_plain{jamtis_spend_pubkey, s_generate_address, record_out.address_index,
                    d_unlock_received, basic_record.enote_ephemeral_pubkey},
                k_generate_image,
                s_generate_address,
                cipher_context,
                onetime_address_format,
                record_out))
            return true;
    }

    if (try_complete_balance_recovery_v1(basic_record.enote,
            basic_record.enote_ephemeral_pubkey,
            basic_record.num_primary_view_tag_bits,
            basic_record.input_context,
            jamtis_spend_pubkey,
            make_x_fa,
            reinterpret_cast<jamtis::secret256_ptr_t>(s_view_balance.data),
            [&s_view_balance]() { return reinterpret_cast<jamtis::secret256_ptr_t>(s_view_balance.data); },
            k_generate_image,
            s_generate_address,
            cipher_context,
            onetime_address_format,
            record_out))
        return true;
    
    return false;
}
//-------------------------------------------------------------------------------------------------------------------
bool try_get_enote_record_v1(const SpEnoteVariant &enote,
    const crypto::x25519_pubkey &enote_ephemeral_pubkey,
    const std::uint8_t num_primary_view_tag_bits,
    const rct::key &input_context,
    const rct::key &jamtis_spend_pubkey,
    const crypto::secret_key &s_view_balance,
    SpEnoteRecordV1 &record_out,
    const jamtis::JamtisOnetimeAddressFormat onetime_address_format)
{
    // generate account secrets tree from s_vb
    crypto::secret_key k_generate_image;
    crypto::x25519_secret_key d_unlock_received;
    crypto::x25519_secret_key d_identify_received;
    crypto::x25519_secret_key d_filter_assist;
    crypto::secret_key s_generate_address;
    crypto::secret_key s_cipher_tag;
    jamtis::make_jamtis_generateimage_key(s_view_balance, k_generate_image);
    jamtis::make_jamtis_unlockreceived_key(s_view_balance, d_unlock_received);
    jamtis::make_jamtis_identifyreceived_key(s_view_balance, d_identify_received);
    jamtis::make_jamtis_filterassist_key(s_view_balance, d_filter_assist);
    jamtis::make_jamtis_generateaddress_secret(s_view_balance, s_generate_address);
    jamtis::make_jamtis_ciphertag_secret(s_generate_address, s_cipher_tag);

    const jamtis::jamtis_address_tag_cipher_context cipher_context{s_cipher_tag};

    // manually construct a fake basic record, pretending that the primary view tag matches
    const SpBasicEnoteRecordV1 basic_record{.enote = enote,
        .enote_ephemeral_pubkey = enote_ephemeral_pubkey,
        .num_primary_view_tag_bits = num_primary_view_tag_bits,
        .input_context = input_context,
        .primary_vt_matches = true};

    return try_get_enote_record_v1(basic_record,
        jamtis_spend_pubkey,
        s_view_balance,
        k_generate_image,
        d_unlock_received,
        d_identify_received,
        d_filter_assist,
        s_generate_address,
        cipher_context,
        record_out,
        onetime_address_format);
}
//-------------------------------------------------------------------------------------------------------------------
bool try_get_enote_record_v1(const SpIntermediateEnoteRecordV1 &intermediate_record,
    const rct::key &jamtis_spend_pubkey,
    const crypto::secret_key &s_view_balance,
    SpEnoteRecordV1 &record_out,
    const jamtis::JamtisOnetimeAddressFormat onetime_address_format)
{
    return try_get_enote_record_v1(intermediate_record.enote,
        intermediate_record.enote_ephemeral_pubkey,
        intermediate_record.num_primary_view_tag_bits,
        intermediate_record.input_context,
        jamtis_spend_pubkey,
        s_view_balance,
        record_out);
}
//-------------------------------------------------------------------------------------------------------------------
bool try_get_enote_record_plain_v1(const SpBasicEnoteRecordV1 &basic_record,
    const rct::key &jamtis_spend_pubkey,
    const crypto::secret_key &s_view_balance,
    const crypto::secret_key &k_generate_image,
    const crypto::x25519_secret_key &d_unlock_received,
    const crypto::x25519_secret_key &d_identify_received,
    const crypto::x25519_secret_key &d_filter_assist,
    const crypto::secret_key &s_generate_address,
    const jamtis::jamtis_address_tag_cipher_context &cipher_context,
    SpEnoteRecordV1 &record_out,
    const jamtis::JamtisOnetimeAddressFormat onetime_address_format)
{
    if (!basic_record.primary_vt_matches)
        return false;

    // X_ir = d_ir D_e
    crypto::x25519_pubkey x_ir;
    crypto::x25519_scmul_key(d_identify_received, basic_record.enote_ephemeral_pubkey, x_ir);

    if (!try_complete_balance_recovery_v1(basic_record.enote,
            basic_record.enote_ephemeral_pubkey,
            basic_record.num_primary_view_tag_bits,
            basic_record.input_context,
            jamtis_spend_pubkey,
            lazy_scmul_key{d_filter_assist, basic_record.enote_ephemeral_pubkey},
            x_ir.data,
            lazy_make_x_ur_plain{jamtis_spend_pubkey, s_generate_address, record_out.address_index,
                d_unlock_received, basic_record.enote_ephemeral_pubkey},
            k_generate_image,
            s_generate_address,
            cipher_context,
            onetime_address_format,
            record_out))
        return false;

    return record_out.type == jamtis::JamtisEnoteType::PLAIN;
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace sp

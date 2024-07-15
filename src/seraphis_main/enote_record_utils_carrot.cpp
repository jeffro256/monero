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

// Utilities for making enote records from enotes.

//local headers
#include "enote_record_utils_carrot.h"
#include "seraphis_core/jamtis_enote_utils.h"
#include "seraphis_crypto/sp_crypto_utils.h"

//third party headers

//standard headers

//forward declarations


namespace sp
{
//----------------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------------
static bool derive_x_all(const crypto::x25519_pubkey &enote_ephemeral_pubkey,
    const crypto::secret_key &k_view,
    rct::key &x_all_out)
{
    // @TODO: this is slow as hell, use accelerated SUPERCOP impl

    ge_p3 p3;
    if (0 != ge_fromx25519_vartime(&p3, enote_ephemeral_pubkey.data)) // K_e
        return false;

    ge_p2 p2;
    ge_scalarmult(&p2, to_bytes(k_view), &p3); // k_v K_e

    ge_p1p1 p1p1;
    ge_mul8(&p1p1, &p2); // 8 k_v K_e

    ge_p1p1_to_p2(&p2, &p1p1);

    ge_tobytes(x_all_out.bytes, &p2);

    normalize_x(x_all_out);

    return true;
}
//----------------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------------
static bool x25519_point_is_in_main_subgroup(const crypto::x25519_pubkey &P)
{
    // @TODO: could be faster, but also isn't used much

    ge_p3 P_p3;
    if (0 != ge_fromx25519_vartime(&P_p3, P.data))
        return false;

    ge_p2 I_p2;
    ge_scalarmult(&I_p2, rct::curveOrder().bytes, &P_p3);

    rct::key I_ser;
    ge_tobytes(I_ser.bytes, &I_p2);

    return I_ser == rct::identity();
}
//----------------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------------
static bool try_intermediate_enote_record_recovery_coinbase(const SpCoinbaseEnoteV1 &enote,
    const rct::key &sender_receiver_secret,
    const rct::key &primary_recipient_spend_pubkey,
    rct::xmr_amount &amount_out,
    crypto::secret_key &amount_blinding_factor_out,
    rct::key &nominal_address_spend_pubkey_out)
{
    // a = a
    amount_out = enote.core.amount;

    // y = 1
    amount_blinding_factor_out = rct::rct2sk(rct::I);

    // K^j_s = Ko - K^o_ext = Ko - (k^o_g G + k^o_u U)
    jamtis::recover_recipient_address_spend_key_rct(sender_receiver_secret,
        rct::zeroCommit(amount_out),
        enote.core.onetime_address,
        nominal_address_spend_pubkey_out);

    // check K^j_s' ?= K^{0}_s since miners only supports primary addresses
    return nominal_address_spend_pubkey_out == primary_recipient_spend_pubkey;
}
//----------------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------------
static bool try_intermediate_enote_record_recovery_noncoinbase(const SpEnoteV1 &enote,
    const crypto::x25519_pubkey &enote_ephemeral_pubkey,
    const rct::key &sender_receiver_secret,
    rct::xmr_amount &amount_out,
    crypto::secret_key &amount_blinding_factor_out,
    rct::key &nominal_address_spend_pubkey_out)
{
    // a = a_enc XOR H_8(q, Ko)
    amount_out = jamtis::decrypt_jamtis_amount(enote.encrypted_amount,
        sender_receiver_secret,
        enote.core.onetime_address);

    // y = H_n(q, PLAIN)
    jamtis::make_jamtis_amount_blinding_factor(sender_receiver_secret,
        jamtis::JamtisEnoteType::PLAIN,
        amount_blinding_factor_out);

    // check (a H + y G) ?= C
    if (!(rct::commit(amount_out, rct::sk2rct(amount_blinding_factor_out)) == enote.core.amount_commitment))
        return false;

    // check that the enote ephemeral pubkey is in the prime subgroup, else the shared secret
    // won't be unique to us
    if (!x25519_point_is_in_main_subgroup(enote_ephemeral_pubkey))
        return false;

    // K^j_s = Ko - K^o_ext = Ko - (k^o_g G + k^o_u U)
    jamtis::recover_recipient_address_spend_key_rct(sender_receiver_secret,
        enote.core.amount_commitment,
        enote.core.onetime_address,
        nominal_address_spend_pubkey_out);
    
    return true;
}
//----------------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------------
template <class IntermediateLikeRecord>
struct try_intermediate_enote_record_recovery_visitor
{
    using result_type = bool;

    bool operator()(const SpCoinbaseEnoteV1 &enote) const
    {
        return try_intermediate_enote_record_recovery_coinbase(enote,
            sender_receiver_secret,
            primary_recipient_spend_pubkey,
            record_out.amount,
            record_out.amount_blinding_factor,
            record_out.nominal_address_spend_pubkey);
    }

    bool operator()(const SpEnoteV1 &enote) const
    {
        return try_intermediate_enote_record_recovery_noncoinbase(enote,
            enote_ephemeral_pubkey,
            sender_receiver_secret,
            record_out.amount,
            record_out.amount_blinding_factor,
            record_out.nominal_address_spend_pubkey);
    }

    bool operator()(boost::blank) const
    { ASSERT_MES_AND_THROW("try_intermediate_enote_record_recovery_visitor: visited blank"); }

    const rct::key &sender_receiver_secret;
    const rct::key &primary_recipient_spend_pubkey;
    const crypto::x25519_pubkey &enote_ephemeral_pubkey;
    IntermediateLikeRecord &record_out;
};
//----------------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------------
template <class IntermediateLikeRecord>
static bool try_get_carrot_intermediate_like_enote_record(const SpEnoteVariant &enote,
    const crypto::x25519_pubkey &enote_ephemeral_pubkey,
    const rct::key &input_context,
    const crypto::secret_key &k_view,
    const rct::key &primary_recipient_spend_pubkey,
    IntermediateLikeRecord &record_out)
{
    // derive X_fa = X_ir = X_ur = 8 * k_v * x2ed(D_e)
    rct::key x_all;
    derive_x_all(enote_ephemeral_pubkey, k_view, x_all);

    // check view tag (note: we check the whole view tag at once with npbits=0)
    bool matched_all_secondary_bits{false};
    if (!jamtis::test_jamtis_secondary_view_tag(x_all.bytes,
            onetime_address_ref(enote),
            view_tag_ref(enote),
            /*num_primary_view_tag_bits=*/0,
            matched_all_secondary_bits))
        return false;

    // sanity check
    CHECK_AND_ASSERT_THROW_MES(matched_all_secondary_bits,
        "test_jamtis_secondary_view_tag: BUG: passed w/ npbits=0 but not matched_all_secondary_bits");

    // make sender receiver secret
    rct::key nominal_sender_receiver_secret;
    jamtis::make_jamtis_sender_receiver_secret(x_all.bytes,
        x_all.bytes,
        x_all.bytes,
        enote_ephemeral_pubkey,
        input_context,
        nominal_sender_receiver_secret);

    try_intermediate_enote_record_recovery_visitor<IntermediateLikeRecord> recovery_vis{
            .sender_receiver_secret = nominal_sender_receiver_secret,
            .primary_recipient_spend_pubkey = primary_recipient_spend_pubkey,
            .enote_ephemeral_pubkey = enote_ephemeral_pubkey,
            .record_out = record_out
        };
    if (!enote.visit(std::move(recovery_vis)))
        return false;

    // @TODO: Do Janus protection check here!

    record_out.enote = enote;
    record_out.enote_ephemeral_pubkey = enote_ephemeral_pubkey;
    record_out.input_context = input_context;

    return true;
}
//----------------------------------------------------------------------------------------------------------------------
bool try_get_carrot_intermediate_enote_record_v1(const SpEnoteVariant &enote,
    const crypto::x25519_pubkey &enote_ephemeral_pubkey,
    const rct::key &input_context,
    const crypto::secret_key &k_view,
    const rct::key &primary_recipient_spend_pubkey,
    CarrotIntermediateEnoteRecordV1 &record_out)
{
    return try_get_carrot_intermediate_like_enote_record(enote,
        enote_ephemeral_pubkey,
        input_context,
        k_view,
        primary_recipient_spend_pubkey,
        record_out);
}
//----------------------------------------------------------------------------------------------------------------------
bool try_get_carrot_enote_record_v1(const SpEnoteVariant &enote,
    const crypto::x25519_pubkey &enote_ephemeral_pubkey,
    const rct::key &input_context,
    const crypto::secret_key &k_view,
    const crypto::secret_key &k_spend,
    const rct::key &primary_recipient_spend_pubkey,
    CarrotEnoteRecordV1 &record_out)
{
    return false;
}
//----------------------------------------------------------------------------------------------------------------------
} //namespace sp

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

//third party headers

//standard headers

//forward declarations


namespace sp
{
//----------------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------------
static bool try_intermediate_enote_record_recovery_coinbase(const SpCoinbaseEnoteV1 &enote,
    const rct::key &sender_receiver_secret,
    const rct::key &primary_recipient_spend_pubkey,
    rct::xmr_amount &amount_out,
    rct::key &amount_blinding_factor_out,
    rct::key &nominal_address_spend_pubkey_out)
{
    // a = a
    amount_out = enote.core.amount;

    // y = 1
    amount_blinding_factor_out = rct::I;

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
template <class IntermediateLikeRecord>
static bool try_intermediate_enote_record_recovery_noncoinbase(const SpEnoteRecordV1 &enote,
    const crypto::x25519_pubkey &enote_ephemeral_pubkey,
    const rct::key &input_context,
    const rct::key &sender_receiver_secret,
    const crypto::public_key &primary_recipient_spend_pubkey,
    rct::xmr_amount &amount_out,
    rct::key &amount_blinding_factor_out,
    crypto::public_key &nominal_address_spend_pubkey_out)
{
    // a = a_enc XOR H_8(q, Ko)
    amount_out = jamtis::decrypt_jamtis_amount(enote.enc_amount,
        sender_receiver_secret,
        enote.core.onetime_address);

    // y = H_n(q, PLAIN)
    jamtis::make_jamtis_amount_blinding_factor(sender_receiver_secret,
        jamtis::JamtisEnoteType::PLAIN,
        amount_blinding_factor_out);

    // check (a H + y G) ?= C
    if (!rct::commit(amount_out, amount_blinding_factor_out) != enote.core.amount_commitment)
        return false;

    // check that the enote ephemeral pubkey is in the prime subgroup, else the shared secret
    // won't be unique to us
    if (!rct::isInMainSubgroup(enote_ephemeral_pubkey))
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
bool try_get_carrot_intermediate_like_enote_record(const SpEnoteVariant &enote,
    const crypto::x25519_pubkey &enote_ephemeral_pubkey,
    const rct::key &input_context,
    const crypto::secret_key &k_view_key,
    const jamtis::secret256_ptr_t x_all,
    IntermediateLikeRecord &record_out)
{
    // check view tag (note: we check the whole view tag at once with npbits=0)
    bool matched_all_secondary_bits{false};
    if (!jamtis::test_jamtis_secondary_view_tag(x_all,
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
    jamtis::make_jamtis_sender_receiver_secret(x_all,
        x_all,
        x_all,
        enote_ephemeral_pubkey,
        input_context,
        nominal_sender_receiver_secret);
    

}
//----------------------------------------------------------------------------------------------------------------------
bool try_get_carrot_intermediate_enote_record_v1(const SpEnoteVariant &enote,
    const crypto::x25519_pubkey &enote_ephemeral_pubkey,
    const rct::key &input_context,
    const crypto::secret_key &k_view_key,
    const jamtis::secret256_ptr_t x_all,
    CarrotIntermediateEnoteRecordV1 &record_out)
{
}
//----------------------------------------------------------------------------------------------------------------------
bool try_get_carrot_enote_record_v1(const SpEnoteVariant &enote,
    const crypto::x25519_pubkey &enote_ephemeral_pubkey,
    const rct::key &input_context,
    const crypto::secret_key &k_view_key,
    const crypto::secret_key &k_spend_key,
    CarrotEnoteRecordV1 &record_out)
{

}
//----------------------------------------------------------------------------------------------------------------------
} //namespace sp

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
#include "carrot_payment_proposal.h"

//local headers
#include "int-util.h"
#include "jamtis_enote_utils.h"
#include "ringct/rctOps.h"
#include "seraphis_crypto/sp_crypto_utils.h"

//third party headers

//standard headers


#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis"

namespace sp
{
namespace jamtis
{
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static const carrot_anchor_t null_anchor{{0}};
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
template <typename T>
static auto auto_wiper(T &obj)
{
    static_assert(std::is_trivially_copyable<T>());
    return epee::misc_utils::create_scope_leave_handler([&]{ memwipe(&obj, sizeof(T)); });
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
crypto::secret_key get_subaddress_secret_key(const crypto::secret_key &k_view, const cryptonote::subaddress_index &index)
{
    char data[sizeof(config::HASH_KEY_SUBADDRESS) + sizeof(crypto::secret_key) + 2 * sizeof(uint32_t)];
    memcpy(data, config::HASH_KEY_SUBADDRESS, sizeof(config::HASH_KEY_SUBADDRESS));
    memcpy(data + sizeof(config::HASH_KEY_SUBADDRESS), &k_view, sizeof(crypto::secret_key));
    uint32_t idx = SWAP32LE(index.major);
    memcpy(data + sizeof(config::HASH_KEY_SUBADDRESS) + sizeof(crypto::secret_key), &idx, sizeof(uint32_t));
    idx = SWAP32LE(index.minor);
    memcpy(data + sizeof(config::HASH_KEY_SUBADDRESS) + sizeof(crypto::secret_key) + sizeof(uint32_t), &idx, sizeof(uint32_t));
    crypto::secret_key m;
    crypto::hash_to_scalar(data, sizeof(data), m);
    return m;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static crypto::public_key get_subaddress_spend_public_key(const crypto::secret_key &k_view,
    const crypto::public_key &spend_pubkey,
    const cryptonote::subaddress_index &index)
{
    if (index.is_zero())
        return spend_pubkey;

    // m = Hs(k_v || index_major || index_minor)
    crypto::secret_key m = get_subaddress_secret_key(k_view, index);

    // M = m*G
    crypto::public_key M;
    crypto::secret_key_to_public_key(m, M);

    // K^j_s = K_s + M
    crypto::public_key D = rct::rct2pk(rct::addKeys(rct::pk2rct(spend_pubkey), rct::pk2rct(M)));
    return D;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static crypto::secret_key get_enote_ephemeral_privkey(const CarrotPaymentProposalV1 &proposal)
{
    // k_e = (H_64(n, b, K^j_s, K^j_v, pid)) mod l
    crypto::secret_key enote_ephemeral_privkey;
    make_carrot_enote_ephemeral_privkey(proposal.randomness,
        proposal.amount,
        proposal.destination.m_spend_public_key,
        proposal.destination.m_view_public_key,
        proposal.payment_id,
        enote_ephemeral_privkey);

    return enote_ephemeral_privkey;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void get_output_proposal_plain_root_secrets_and_ephem_pubkey(const CarrotPaymentProposalV1 &proposal,
    const rct::key &input_context,
    crypto::x25519_pubkey &enote_ephemeral_pubkey_out,
    crypto::public_key &x_all_out,
    rct::key &q_out)
{
    // 1. enote ephemeral pubkey: D_e = ed_to_x(k_e K_base)
    get_enote_ephemeral_pubkey(proposal, enote_ephemeral_pubkey_out);

    // 2. X_fa = X_ir = X_ur = 8 * k_e * K^j_v
    x_all_out = rct::rct2pk(rct::scalarmultKey(rct::scalarmult8(rct::pk2rct(proposal.destination.m_view_public_key)),
        rct::sk2rct(get_enote_ephemeral_privkey(proposal))));
    normalize_x(x_all_out);

    // 5. q = H_32(X_fa, X_ir, X_ur, D_e, input_context)
    make_jamtis_sender_receiver_secret(to_bytes(x_all_out),
        to_bytes(x_all_out),
        to_bytes(x_all_out),
        enote_ephemeral_pubkey_out,
        input_context,
        q_out);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void get_output_proposal_address_parts_v1(const rct::key &q,
    const secret256_ptr_t x_all,
    const crypto::public_key &destination_spend_pubkey,
    const carrot_anchor_t &randomness,
    const rct::key &amount_commitment,
    rct::key &onetime_address_out,
    carrot_encrypted_anchor_t &anchor_enc_out,
    view_tag_t &view_tag_out)
{
    // 1. onetime address: Ko = ... + K^j_s
    make_jamtis_onetime_address_rct(rct::pk2rct(destination_spend_pubkey),
        q,
        amount_commitment,
        onetime_address_out);

    // 2. encrypt anchor: anchor_enc = anchor XOR H_16(q, q, Ko)
    anchor_enc_out = encrypt_jamtis_address_tag(randomness,
        q.bytes,
        q.bytes,
        onetime_address_out);

    // 3. view tag
    jamtis::make_jamtis_view_tag(x_all,
        x_all,
        onetime_address_out,
        /*num_primary_view_tag_bits=*/0,
        view_tag_out);
}
//-------------------------------------------------------------------------------------------------------------------    
//-------------------------------------------------------------------------------------------------------------------
/// equality operators
bool operator==(const CarrotPaymentProposalV1 &a, const CarrotPaymentProposalV1 &b)
{
    return a.destination == b.destination &&
        a.amount == b.amount &&
        a.randomness == b.randomness &&
        a.partial_memo == b.partial_memo;
}
//-------------------------------------------------------------------------------------------------------------------
bool operator==(const CarrotPaymentProposalSelfSendV1 &a, const CarrotPaymentProposalSelfSendV1 &b)
{
    return a.destination_index == b.destination_index &&
        a.amount == b.amount &&
        a.enote_ephemeral_pubkey == b.enote_ephemeral_pubkey &&
        a.partial_memo == b.partial_memo;
}
//-------------------------------------------------------------------------------------------------------------------
void get_enote_ephemeral_pubkey(const CarrotPaymentProposalV1 &proposal,
    crypto::x25519_pubkey &enote_ephemeral_pubkey_out)
{
    // k_e = (H_64(n, b, K^j_s, K^j_v, pid)) mod l
    const crypto::secret_key enote_ephemeral_privkey{get_enote_ephemeral_privkey(proposal)};

    // D_e = ConvertPubkey2(k_e ([subaddress: K^j_s] [primary address: G])
    make_carrot_enote_ephemeral_pubkey(enote_ephemeral_privkey,
        proposal.destination.m_spend_public_key,
        proposal.is_subaddress,
        enote_ephemeral_pubkey_out);
}
//-------------------------------------------------------------------------------------------------------------------
void get_coinbase_output_proposal_v1(const CarrotPaymentProposalV1 &proposal,
    const std::uint64_t block_height,
    SpCoinbaseEnoteCore &output_enote_core_out,
    crypto::x25519_pubkey &enote_ephemeral_pubkey_out,
    encrypted_address_tag_t &addr_tag_enc_out,
    view_tag_t &view_tag_out,
    TxExtra &partial_memo_out)
{
    // 1. sanity checks
    CHECK_AND_ASSERT_THROW_MES(proposal.randomness != null_anchor,
        "jamtis payment proposal: invalid randomness for janus anchor (zero).");

    // 2. coinbase input context
    rct::key input_context;
    make_jamtis_input_context_coinbase(block_height, input_context);

    // 3. plain enote ephemeral pubkey and root secrets: D_e, X_fa, X_ir, q
    crypto::public_key x_all; auto dhe_wiper = auto_wiper(x_all);
    rct::key q; auto q_wiper = auto_wiper(q);
    get_output_proposal_plain_root_secrets_and_ephem_pubkey(proposal,
        input_context, enote_ephemeral_pubkey_out, x_all, q);

    // 4. build the output enote address pieces
    get_output_proposal_address_parts_v1(q,
        to_bytes(x_all),
        proposal.destination.m_spend_public_key,
        proposal.randomness,
        rct::commit(proposal.amount, rct::I),
        output_enote_core_out.onetime_address,
        addr_tag_enc_out,
        view_tag_out);

    // 5. save the amount and parial memo
    output_enote_core_out.amount = proposal.amount;
    partial_memo_out             = proposal.partial_memo;
}
//-------------------------------------------------------------------------------------------------------------------
void get_output_proposal_v1(const CarrotPaymentProposalV1 &proposal,
    const rct::key &input_context,
    SpOutputProposalCore &output_proposal_core_out,
    crypto::x25519_pubkey &enote_ephemeral_pubkey_out,
    std::optional<encrypted_payment_id_t> &encrypted_payment_id_out,
    encrypted_amount_t &encrypted_amount_out,
    encrypted_address_tag_t &addr_tag_enc_out,
    view_tag_t &view_tag_out,
    TxExtra &partial_memo_out)
{
    // 1. sanity checks
    CHECK_AND_ASSERT_THROW_MES(proposal.randomness != null_anchor,
        "jamtis payment proposal: invalid randomness for janus anchor (zero).");

    // 2. plain enote ephemeral pubkey and root secrets: D_e, X_fa, X_ir, q
    crypto::public_key x_all; auto dhe1_wiper = auto_wiper(x_all);
    rct::key q; auto q_wiper = auto_wiper(q);
    get_output_proposal_plain_root_secrets_and_ephem_pubkey(proposal,
        input_context,
        enote_ephemeral_pubkey_out,
        x_all,
        q);

    // 3. amount blinding factor: y = Hn(q, enote_type)
    make_jamtis_amount_blinding_factor(q, JamtisEnoteType::PLAIN, output_proposal_core_out.amount_blinding_factor);

    // 4. build the output enote address pieces
    get_output_proposal_address_parts_v1(q,
        to_bytes(x_all),
        proposal.destination.m_spend_public_key,
        proposal.randomness,
        rct::commit(proposal.amount, rct::sk2rct(output_proposal_core_out.amount_blinding_factor)),
        output_proposal_core_out.onetime_address,
        addr_tag_enc_out,
        view_tag_out);
    
    // 5. make encrypted amount
    encrypted_amount_out = encrypt_jamtis_amount(proposal.amount, q, output_proposal_core_out.onetime_address);

    // 6. make encrypted payment ID if applicable
    encrypted_payment_id_out = (proposal.payment_id == null_payment_id)
        ? std::optional<encrypted_payment_id_t>()
        : encrypt_legacy_payment_id(proposal.payment_id, q, output_proposal_core_out.onetime_address);

    // 7. save the amount and partial memo
    output_proposal_core_out.amount = proposal.amount;
    partial_memo_out                = proposal.partial_memo;
}
//-------------------------------------------------------------------------------------------------------------------
void get_output_proposal_v1(const CarrotPaymentProposalSelfSendV1 &proposal,
    const crypto::secret_key &k_view,
    const crypto::public_key &primary_address_spend_pubkey,
    const rct::key &input_context,
    SpOutputProposalCore &output_proposal_core_out,
    crypto::x25519_pubkey &enote_ephemeral_pubkey_out,
    encrypted_amount_t &encrypted_amount_out,
    encrypted_address_tag_t &addr_tag_enc_out,
    view_tag_t &view_tag_out,
    TxExtra &partial_memo_out)
{
    // 1. X_fa = X_ir = X_ur = NormalizeX(8 * k_v * ConvertPubkey1(D_e))
    crypto::public_key x_all;
    CHECK_AND_ASSERT_THROW_MES(make_carrot_x_all_recipient(k_view,
        proposal.enote_ephemeral_pubkey,
        x_all), "get output proposal v1: carrot enote ephemeral pubkey failed to deserialize");
    
    // 2. q = H_32(X_fa, X_ir, X_ur, D_e, input_context)
    rct::key sender_receiver_secret;
    make_jamtis_sender_receiver_secret(to_bytes(x_all),
        to_bytes(x_all),
        to_bytes(x_all),
        proposal.enote_ephemeral_pubkey,
        input_context,
        sender_receiver_secret);

    // 3. get enote_type
    const JamtisEnoteType enote_type{
            proposal.is_plain_type ? JamtisEnoteType::PLAIN : JamtisEnoteType::CHANGE
        };

    // 4. amount blinding factor: y = Hn(q, enote_type)
    make_jamtis_amount_blinding_factor(sender_receiver_secret,
        enote_type,
        output_proposal_core_out.amount_blinding_factor);

    // 5. K^j_s (we do this here instead of allowing the user to specify the pubkey for robustness)
    const crypto::public_key destination_spend_pubkey{
            get_subaddress_spend_public_key(k_view, primary_address_spend_pubkey, proposal.destination_index)
        };

    // 6. build the output enote address pieces
    carrot_encrypted_anchor_t dummy_anchor_enc;
    get_output_proposal_address_parts_v1(sender_receiver_secret,
        to_bytes(x_all),
        destination_spend_pubkey,
        gen_address_tag(),
        rct::commit(proposal.amount, rct::sk2rct(output_proposal_core_out.amount_blinding_factor)),
        output_proposal_core_out.onetime_address,
        dummy_anchor_enc,
        view_tag_out);
    
    // 7. make encrypted amount
    encrypted_amount_out = encrypt_jamtis_amount(proposal.amount,
        sender_receiver_secret,
        output_proposal_core_out.onetime_address);
    
    // 8. make encrypted special janus anchor
    carrot_anchor_t janus_anchor_special;
    make_carrot_janus_anchor_special(sender_receiver_secret,
        output_proposal_core_out.onetime_address,
        k_view,
        primary_address_spend_pubkey,
        janus_anchor_special);
    addr_tag_enc_out = encrypt_jamtis_address_tag(janus_anchor_special,
        sender_receiver_secret.bytes,
        sender_receiver_secret.bytes,
        output_proposal_core_out.onetime_address);

    // 9. save the amount, enote ephemeral pubkey, and partial memo
    output_proposal_core_out.amount = proposal.amount;
    enote_ephemeral_pubkey_out      = proposal.enote_ephemeral_pubkey;
    partial_memo_out                = proposal.partial_memo;
}
//-------------------------------------------------------------------------------------------------------------------
CarrotPaymentProposalV1 gen_carrot_payment_proposal_v1(const bool is_subaddress,
    const bool has_payment_id,
    const rct::xmr_amount amount,
    const std::size_t num_random_memo_elements)
{
    CarrotPaymentProposalV1 temp;

    temp.destination.m_spend_public_key = rct::rct2pk(rct::pkGen());
    temp.destination.m_view_public_key  = rct::rct2pk(rct::pkGen());
    temp.is_subaddress                  = is_subaddress;
    temp.payment_id                     = has_payment_id ? gen_payment_id() : null_payment_id;
    temp.amount                         = amount;
    temp.randomness                     = gen_address_tag();

    std::vector<ExtraFieldElement> memo_elements;
    memo_elements.resize(num_random_memo_elements);
    for (ExtraFieldElement &element: memo_elements)
        element = gen_extra_field_element();
    make_tx_extra(std::move(memo_elements), temp.partial_memo);

    return temp;
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace jamtis
} //namespace sp

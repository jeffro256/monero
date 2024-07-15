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
#include "jamtis_enote_utils.h"
#include "ringct/rctOps.h"

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
static const carrot_randomness_t null_randomness{{0}};
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
static crypto::secret_key get_enote_ephemeal_privkey(const CarrotPaymentProposalV1 &proposal)
{
    // k_e = (H_64(n, b, K^j_s, K^j_v, pid)) mod l
    crypto::secret_key enote_epemeral_privkey;
    make_carrot_enote_ephemeral_privkey(proposal.randomness,
        proposal.amount,
        proposal.destination.m_spend_public_key,
        proposal.destination.m_view_public_key,
        proposal.payment_id,
        enote_epemeral_privkey);

    return enote_epemeral_privkey;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void get_output_proposal_plain_root_secrets_and_ephem_pubkey(const CarrotPaymentProposalV1 &proposal,
    const rct::key &input_context,
    crypto::x25519_pubkey &enote_ephemeral_pubkey_out,
    rct::key &x_all_out,
    rct::key &q_out)
{
    // 1. enote ephemeral pubkey: D_e = ed_to_x(k_e K_base)
    get_enote_ephemeral_pubkey(proposal, enote_ephemeral_pubkey_out);

    // 2. X_fa = X_ir = X_ur = 8 * k_e * K^j_v
    x_all_out = rct::scalarmultKey(rct::scalarmult8(rct::pk2rct(proposal.destination.m_view_public_key)),
        rct::sk2rct(get_enote_ephemeal_privkey(proposal)));

    // 5. q = H_32(X_fa, X_ir, X_ur, D_e, input_context)
    make_jamtis_sender_receiver_secret(x_all_out.bytes,
        x_all_out.bytes,
        x_all_out.bytes,
        enote_ephemeral_pubkey_out,
        input_context,
        q_out);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void get_output_proposal_address_parts_v1(const rct::key &q,
    const secret256_ptr_t x_all,
    const CarrotPaymentProposalV1 &output_destination,
    const rct::key &amount_commitment,
    rct::key &onetime_address_out,
    carrot_encrypted_randomness_t &randomness_enc_out,
    view_tag_t &view_tag_out)
{
    // 1. onetime address: Ko = ... + K^j_s
    make_jamtis_onetime_address_rct(rct::pk2rct(output_destination.destination.m_spend_public_key),
        q,
        amount_commitment,
        onetime_address_out);

    // 2. encrypt address tag: addr_tag_enc = addr_tag XOR H_16(X_fa, X_ir, Ko)
    randomness_enc_out = encrypt_jamtis_address_tag(output_destination.randomness,
        x_all,
        x_all,
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
void get_enote_ephemeral_pubkey(const CarrotPaymentProposalV1 &proposal,
    crypto::x25519_pubkey &enote_ephemeral_pubkey_out)
{
    // k_e = (H_64(n, b, K^j_s, K^j_v, pid)) mod l
    const crypto::secret_key enote_ephemeral_privkey{get_enote_ephemeal_privkey(proposal)};

    // K_base = G if main address OR K^j_s if subaddress
    const rct::key addr_base_pubkey{proposal.is_subaddress
            ? rct::pk2rct(proposal.destination.m_spend_public_key)
            : rct::G
        };

    // K_e = k_e K_base
    const rct::key enote_ephemeral_pubkey_ed25519{
            rct::scalarmultKey(addr_base_pubkey, rct::sk2rct(enote_ephemeral_privkey))
        };

    // convert K_e to X25519 (AKA D_e)
    ge_p3 ge_p3_Ke;
    ge_frombytes_vartime(&ge_p3_Ke, enote_ephemeral_pubkey_ed25519.bytes);
    ge_p3_to_x25519(enote_ephemeral_pubkey_out.data, &ge_p3_Ke);
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
    CHECK_AND_ASSERT_THROW_MES(proposal.randomness != null_randomness,
        "jamtis payment proposal: invalid enote ephemeral privkey randomness (zero).");

    // 2. coinbase input context
    rct::key input_context;
    make_jamtis_input_context_coinbase(block_height, input_context);

    // 3. plain enote ephemeral pubkey and root secrets: D_e, X_fa, X_ir, q
    rct::key x_all; auto dhe_wiper = auto_wiper(x_all);
    rct::key q; auto q_wiper = auto_wiper(q);
    get_output_proposal_plain_root_secrets_and_ephem_pubkey(proposal,
        input_context, enote_ephemeral_pubkey_out, x_all, q);

    // 4. build the output enote address pieces
    get_output_proposal_address_parts_v1(q,
        x_all.bytes,
        proposal,
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
    encrypted_amount_t &encrypted_amount_out,
    encrypted_address_tag_t &addr_tag_enc_out,
    view_tag_t &view_tag_out,
    TxExtra &partial_memo_out)
{
    // 1. sanity checks
    CHECK_AND_ASSERT_THROW_MES(proposal.randomness != null_randomness,
        "jamtis payment proposal: invalid enote ephemeral privkey randomness (zero).");

    // 2. plain enote ephemeral pubkey and root secrets: D_e, X_fa, X_ir, q
    rct::key x_all; auto dhe1_wiper = auto_wiper(x_all);
    rct::key q; auto q_wiper = auto_wiper(q);
    get_output_proposal_plain_root_secrets_and_ephem_pubkey(proposal,
        input_context, enote_ephemeral_pubkey_out, x_all, q);

    // 3. amount blinding factor: y = Hn(q, enote_type)
    make_jamtis_amount_blinding_factor(q, JamtisEnoteType::PLAIN, output_proposal_core_out.amount_blinding_factor);

    // 4. build the output enote address pieces
    get_output_proposal_address_parts_v1(q,
        x_all.bytes,
        proposal,
        rct::commit(proposal.amount, rct::sk2rct(output_proposal_core_out.amount_blinding_factor)),
        output_proposal_core_out.onetime_address,
        addr_tag_enc_out,
        view_tag_out);
    
    // 5. make encryped amount
    encrypted_amount_out = encrypt_jamtis_amount(proposal.amount, q, output_proposal_core_out.onetime_address);

    // 6. save the amount and partial memo
    output_proposal_core_out.amount = proposal.amount;
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

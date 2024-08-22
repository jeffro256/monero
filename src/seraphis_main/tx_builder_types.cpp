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
#include "tx_builder_types.h"

//local headers
#include "common/container_helpers.h"
#include "crypto/crypto.h"
#include "crypto/x25519.h"
#include "misc_log_ex.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "tx_builders_inputs.h"
#include "tx_builders_mixed.h"
#include "tx_builders_outputs.h"
#include "tx_component_types.h"
#include "txtype_base.h"

//third party headers

//standard headers
#include <vector>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis"

namespace sp
{
//-------------------------------------------------------------------------------------------------------------------
rct::xmr_amount amount_ref(const SpInputProposalV1 &proposal)
{
    return proposal.core.amount;
}
//-------------------------------------------------------------------------------------------------------------------
const crypto::key_image& key_image_ref(const SpInputProposalV1 &proposal)
{
    return proposal.core.key_image;
}
//-------------------------------------------------------------------------------------------------------------------
rct::xmr_amount amount_ref(const SpCoinbaseOutputProposalV1 &proposal)
{
    return proposal.enote.core.amount;
}
//-------------------------------------------------------------------------------------------------------------------
rct::xmr_amount amount_ref(const SpOutputProposalV1 &proposal)
{
    return proposal.core.amount;
}
//-------------------------------------------------------------------------------------------------------------------
bool compare_Ko(const SpCoinbaseOutputProposalV1 &a, const SpCoinbaseOutputProposalV1 &b)
{
    return compare_Ko(a.enote, b.enote);
}
//-------------------------------------------------------------------------------------------------------------------
bool compare_Ko(const SpOutputProposalV1 &a, const SpOutputProposalV1 &b)
{
    return compare_Ko(a.core, b.core);
}
//-------------------------------------------------------------------------------------------------------------------
bool compare_KI(const SpInputProposalV1 &a, const SpInputProposalV1 &b)
{
    return compare_KI(a.core, b.core);
}
//-------------------------------------------------------------------------------------------------------------------
bool compare_KI(const SpPartialInputV1 &a, const SpPartialInputV1 &b)
{
    return compare_KI(a.input_image, b.input_image);
}
//-------------------------------------------------------------------------------------------------------------------
bool alignment_check(const SpAlignableMembershipProofV1 &a, const SpAlignableMembershipProofV1 &b)
{
    return a.masked_address == b.masked_address;
}
//-------------------------------------------------------------------------------------------------------------------
bool alignment_check(const SpAlignableMembershipProofV1 &proof, const rct::key &masked_address)
{
    return proof.masked_address == masked_address;
}
//-------------------------------------------------------------------------------------------------------------------
void get_enote_image_v1(const SpInputProposalV1 &proposal, SpEnoteImageV1 &image_out)
{
    get_enote_image_core(proposal.core, image_out.core);
}
//-------------------------------------------------------------------------------------------------------------------
void get_squash_prefix(const SpInputProposalV1 &proposal, rct::key &squash_prefix_out)
{
    get_squash_prefix(proposal.core, squash_prefix_out);
}
//-------------------------------------------------------------------------------------------------------------------
void get_enote_v1(const SpOutputProposalV1 &proposal, SpEnoteV1 &enote_out)
{
    // enote core
    enote_out.core.onetime_address   = proposal.core.onetime_address;
    enote_out.core.amount_commitment =
        rct::commit(amount_ref(proposal), rct::sk2rct(proposal.core.amount_blinding_factor));

    // enote misc. details
    enote_out.encrypted_amount = proposal.encrypted_amount;
    enote_out.addr_tag_enc     = proposal.addr_tag_enc;
    enote_out.view_tag         = proposal.view_tag;
}
//-------------------------------------------------------------------------------------------------------------------
void get_coinbase_output_proposals_v1(const SpCoinbaseTxProposalV1 &tx_proposal,
    std::vector<SpCoinbaseOutputProposalV1> &output_proposals_out)
{
    // output proposals
    output_proposals_out.clear();
    output_proposals_out.reserve(tx_proposal.normal_payment_proposals.size());

    for (const jamtis::JamtisPaymentProposalV1 &payment_proposal : tx_proposal.normal_payment_proposals)
    {
        make_v1_coinbase_output_proposal_v1(payment_proposal,
            tx_proposal.block_height,
            tools::add_element(output_proposals_out));
    }

    // sort output proposals
    std::sort(output_proposals_out.begin(),
        output_proposals_out.end(),
        tools::compare_func<SpCoinbaseOutputProposalV1>(compare_Ko));
}
//-------------------------------------------------------------------------------------------------------------------
void get_output_proposals_v1(const SpTxProposalV1 &tx_proposal,
    const crypto::secret_key &s_view_balance,
    std::vector<SpOutputProposalV1> &output_proposals_out)
{
    CHECK_AND_ASSERT_THROW_MES(tx_proposal.normal_payment_proposals.size() +
            tx_proposal.selfsend_payment_proposals.size() > 0,
        "Tried to get output proposals for a tx proposal with no outputs!");

    // input context
    jamtis::input_context_t input_context;
    make_standard_input_context_v1(tx_proposal.legacy_input_proposals, tx_proposal.sp_input_proposals, input_context);

    // output proposals
    output_proposals_out.clear();
    output_proposals_out.reserve(tx_proposal.normal_payment_proposals.size() +
        tx_proposal.selfsend_payment_proposals.size());

    for (const jamtis::JamtisPaymentProposalV1 &normal_payment_proposal : tx_proposal.normal_payment_proposals)
        make_v1_output_proposal_v1(normal_payment_proposal,
            input_context,
            tools::add_element(output_proposals_out));

    for (const jamtis::JamtisPaymentProposalSelfSendV1 &selfsend_payment_proposal :
        tx_proposal.selfsend_payment_proposals)
    {
        make_v1_output_proposal_v1(selfsend_payment_proposal,
            s_view_balance,
            input_context,
            tools::add_element(output_proposals_out));
    }

    // sort output proposals
    std::sort(output_proposals_out.begin(),
        output_proposals_out.end(),
        tools::compare_func<SpOutputProposalV1>(compare_Ko));
}
//-------------------------------------------------------------------------------------------------------------------
void get_tx_proposal_prefix_v1(const SpTxProposalV1 &tx_proposal,
    const tx_version_t &tx_version,
    const crypto::secret_key &s_view_balance,
    rct::key &tx_proposal_prefix_out)
{
    // get output proposals
    std::vector<SpOutputProposalV1> output_proposals;
    get_output_proposals_v1(tx_proposal, s_view_balance, output_proposals);

    // sanity check semantics
    check_v1_output_proposal_set_semantics_v1(output_proposals);

    // make the proposal prefix
    make_tx_proposal_prefix_v1(tx_version,
        tx_proposal.legacy_input_proposals,
        tx_proposal.sp_input_proposals,
        output_proposals,
        tx_proposal.tx_fee,
        tx_proposal.partial_memo,
        tx_proposal_prefix_out);
}
//-------------------------------------------------------------------------------------------------------------------
std::uint8_t get_shared_num_primary_view_tag_bits(
    const std::vector<jamtis::JamtisPaymentProposalV1> &normal_payment_proposals,
    const std::vector<jamtis::JamtisPaymentProposalSelfSendV1> &selfsend_payment_proposals,
    const std::vector<SpCoinbaseOutputProposalV1> &coinbase_output_proposals,
    const std::vector<SpOutputProposalV1> &output_proposals)
{
    std::set<std::uint8_t> npbits_values;

    // search thru normal payment proposals
    for (const jamtis::JamtisPaymentProposalV1 &normal_payment_proposal : normal_payment_proposals)
        npbits_values.insert(normal_payment_proposal.num_primary_view_tag_bits);

    // search thru selfsend payment proposals
    for (const jamtis::JamtisPaymentProposalSelfSendV1 &selfsend_payment_proposal : selfsend_payment_proposals)
        npbits_values.insert(selfsend_payment_proposal.num_primary_view_tag_bits);

    // search thru coinbase output proposals
    for (const SpCoinbaseOutputProposalV1 &coinbase_output_proposal : coinbase_output_proposals)
        npbits_values.insert(coinbase_output_proposal.num_primary_view_tag_bits);

    // search thru non-coinbase output proposals
    for (const SpOutputProposalV1 &output_proposal : output_proposals)
        npbits_values.insert(output_proposal.num_primary_view_tag_bits);

    // assert that at least 1 non-zero value exists
    CHECK_AND_ASSERT_THROW_MES(npbits_values.size() && (npbits_values.size() > 1 || *npbits_values.begin() != 0),
        "get shared num primary view tag bits: there are no npbits values, so getting the value is undefined");

    // assert that the set is {x>0} or {0, x>0} (0 means hidden enote)
    CHECK_AND_ASSERT_THROW_MES(npbits_values.size() == 1 || (npbits_values.size() == 2 && *npbits_values.begin() == 0),
        "get shared num primary view tag bits: there are multiple unique values of npbits among these proposals, "
        "so getting the value is undefined");

    // get the npbits value
    const std::uint8_t num_primary_view_tag_bits{*npbits_values.crbegin()};

    // assert that the value of npbits is in acceptable range
    static constexpr size_t MAX_NPBITS_VALUE{8 * jamtis::VIEW_TAG_BYTES};
    CHECK_AND_ASSERT_THROW_MES(num_primary_view_tag_bits <= MAX_NPBITS_VALUE,
        "get shared num primary view tag bits: the value of npbits is too large: "
        << num_primary_view_tag_bits << " vs " << MAX_NPBITS_VALUE);

    return num_primary_view_tag_bits;
}
//-------------------------------------------------------------------------------------------------------------------
SpInputProposalV1 gen_sp_input_proposal_v1(const crypto::secret_key &sp_spend_privkey,
    const crypto::secret_key &k_generate_image,
    const rct::xmr_amount amount)
{
    SpInputProposalV1 temp;
    temp.core = gen_sp_input_proposal_core(sp_spend_privkey, k_generate_image, amount);
    return temp;
}
//-------------------------------------------------------------------------------------------------------------------
SpCoinbaseOutputProposalV1 gen_sp_coinbase_output_proposal_v1(const rct::xmr_amount amount,
    const std::uint8_t num_primary_view_tag_bits,
    const std::size_t num_random_memo_elements)
{
    SpCoinbaseOutputProposalV1 temp;

    // enote
    temp.enote = gen_sp_coinbase_enote_v1();
    temp.enote.core.amount = amount;

    // enote ephemeral pubkey
    temp.enote_ephemeral_pubkey = crypto::x25519_pubkey_gen();

    // npbits
    temp.num_primary_view_tag_bits = num_primary_view_tag_bits;

    // partial memo
    std::vector<ExtraFieldElement> memo_elements;
    memo_elements.resize(num_random_memo_elements);
    for (ExtraFieldElement &element: memo_elements)
        element = gen_extra_field_element();
    make_tx_extra(std::move(memo_elements), temp.partial_memo);

    return temp;
}
//-------------------------------------------------------------------------------------------------------------------
SpOutputProposalV1 gen_sp_output_proposal_v1(const rct::xmr_amount amount,
    const std::uint8_t num_primary_view_tag_bits,
    const std::size_t num_random_memo_elements)
{
    SpOutputProposalV1 temp;

    // gen base of destination
    temp.core = gen_sp_output_proposal_core(amount);

    temp.enote_ephemeral_pubkey = crypto::x25519_pubkey_gen();
    crypto::rand(sizeof(temp.encrypted_amount), temp.encrypted_amount.bytes);
    crypto::rand(sizeof(temp.addr_tag_enc), temp.addr_tag_enc.bytes);
    temp.view_tag = jamtis::gen_view_tag();

    // npbits
    temp.num_primary_view_tag_bits = num_primary_view_tag_bits;

    std::vector<ExtraFieldElement> memo_elements;
    memo_elements.resize(num_random_memo_elements);
    for (ExtraFieldElement &element: memo_elements)
        element = gen_extra_field_element();
    make_tx_extra(std::move(memo_elements), temp.partial_memo);

    return temp;
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace sp

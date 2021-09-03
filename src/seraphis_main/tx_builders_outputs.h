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

#pragma once

//local headers
#include "crypto/crypto.h"
#include "crypto/x25519.h"
#include "ringct/rctTypes.h"
#include "seraphis_core/carrot_payment_proposal.h"
#include "seraphis_core/jamtis_destination.h"
#include "seraphis_core/jamtis_payment_proposal.h"
#include "seraphis_core/jamtis_support_types.h"
#include "tx_builder_types.h"
#include "tx_component_types.h"

//third party headers
#include "boost/multiprecision/cpp_int.hpp"
#include "boost/optional/optional.hpp"

//standard headers
#include <vector>

//forward declarations


namespace sp
{

enum class OutputProposalSetExtraTypeV1
{
    // unique enote ephemeral pubkey,     primary view tag flagging,     change type
    UNIQUE_FLAGGING_CHANGE,
    // unique enote ephemeral pubkey, NOT primary view tag flagging,     change type
    UNIQUE_HIDDEN_CHANGE,
    // shared enote ephemeral pubkey,     primary view tag flagging,     change type
    SHARED_FLAGGING_CHANGE,
    // shared enote ephemeral pubkey, NOT primary view tag flagging,     change type
    SHARED_HIDDEN_CHANGE,
    // shared enote ephemeral pubkey,     primary view tag flagging, self-spend type
    SHARED_FLAGGING_SELFSPEND,
    // shared enote ephemeral pubkey, NOT primary view tag flagging, self-spend type
    SHARED_HIDDEN_SELFSPEND

    // There's no unique ephemeral pubkey + self-spend enum values since we try to avoid setting the
    // enote type to 'self-spend' automatically, since this is intended to be a UX flag. The only
    // time we will automatically add a 'self-spend' enote to an output set is when it is absolutely
    // required to keep the derivation of the enote components unique, which only occurs when the
    // enote ephemeral pubkey is shared (i.e. just 1). When the enote ephemeral pubkeys are unique
    // per enote, the derivation will always be unique.
};

/**
* brief: check_jamtis_payment_proposal_selfsend_semantics_v1 - validate semantics of a self-send payment proposal
* param: selfsend_payment_proposal -
* param: input_context -
* param: spend_pubkey -
* param: s_view_balance -
* return: true if it's a valid self-send proposal
*/
void check_jamtis_payment_proposal_selfsend_semantics_v1(
    const jamtis::JamtisPaymentProposalSelfSendV1 &selfsend_payment_proposal,
    const rct::key &input_context,
    const rct::key &spend_pubkey,
    const crypto::secret_key &s_view_balance);
/**
* brief: check_v1_coinbase_output_proposal_semantics_v1 - check semantics of a coinbase output proposal
*   - throws if a check fails
* param: output_proposal -
*/
void check_v1_coinbase_output_proposal_semantics_v1(const SpCoinbaseOutputProposalV1 &output_proposal);
/**
* brief: check_v1_coinbase_output_proposal_set_semantics_v1 - check semantics of a set of coinbase output proposals
*   - throws if a check fails
* param: output_proposals -
*/
void check_v1_coinbase_output_proposal_set_semantics_v1(const std::vector<SpCoinbaseOutputProposalV1> &output_proposals);
/**
* brief: check_v1_output_proposal_semantics_v1 - check semantics of an output proposal
*   - throws if a check fails
* param: output_proposal -
*/
void check_v1_output_proposal_semantics_v1(const SpOutputProposalV1 &output_proposal);
/**
* brief: check_v1_output_proposal_set_semantics_v1 - check semantics of a set of output proposals
*   - throws if a check fails
* param: output_proposals -
*/
void check_v1_output_proposal_set_semantics_v1(const std::vector<SpOutputProposalV1> &output_proposals);
/**
* brief: make_v1_coinbase_output_proposal_v1 - convert a jamtis proposal to a coinbase output proposal
* param: proposal -
* param: block_height - height of the coinbase tx's block
* outparam: output_proposal_out -
*/
void make_v1_coinbase_output_proposal_v1(const jamtis::JamtisPaymentProposalV1 &proposal,
    const std::uint64_t block_height,
    SpCoinbaseOutputProposalV1 &output_proposal_out);
/**
* brief: make_v1_output_proposal_v1 - convert a jamtis proposal to an output proposal
* param: proposal -
* param: input_context -
* outparam: output_proposal_out -
*/
void make_v1_output_proposal_v1(const jamtis::JamtisPaymentProposalV1 &proposal,
    const rct::key &input_context,
    SpOutputProposalV1 &output_proposal_out);
/**
* brief: make_v1_output_proposal_v1 - convert a jamtis selfsend proposal to an output proposal
* param: proposal -
* param: s_view_balance -
* param: input_context -
* outparam: output_proposal_out -
*/
void make_v1_output_proposal_v1(const jamtis::JamtisPaymentProposalSelfSendV1 &proposal,
    const crypto::secret_key &s_view_balance,
    const rct::key &input_context,
    SpOutputProposalV1 &output_proposal_out);
/**
* brief: make_v1_output_proposal_v1 - convert a jamtis selfsend proposal to an output proposal
* param: proposal -
* param: num_primary_view_tag_bits -
* param: input_context -
* outparam: output_proposal_out -
*/
void make_v1_output_proposal_v1(const jamtis::CarrotPaymentProposalV1 &proposal,
    const std::uint8_t num_primary_view_tag_bits,
    const rct::key &input_context,
    SpOutputProposalV1 &output_proposal_out);
/**
* brief: make_v1_output_proposal_v1 - convert a jamtis selfsend proposal to an output proposal
* param: proposal -
* param: num_primary_view_tag_bits -
* param: k_view -
* param: primary_address_spend_pubkey -
* param: input_context -
* outparam: output_proposal_out -
*/
void make_v1_output_proposal_v1(const jamtis::CarrotPaymentProposalSelfSendV1 &proposal,
    const std::uint8_t num_primary_view_tag_bits,
    const crypto::secret_key &k_view,
    const crypto::public_key &primary_address_spend_pubkey,
    const rct::key &input_context,
    SpOutputProposalV1 &output_proposal_out);
/**
* brief: make_v1_coinbase_outputs_v1 - make v1 coinbase tx outputs
* param: output_proposals -
* outparam: outputs_out -
* outparam: output_enote_ephemeral_pubkeys_out -
*/
void make_v1_coinbase_outputs_v1(const std::vector<SpCoinbaseOutputProposalV1> &output_proposals,
    std::vector<SpCoinbaseEnoteV1> &outputs_out,
    std::vector<crypto::x25519_pubkey> &output_enote_ephemeral_pubkeys_out);
/**
* brief: make_v1_outputs_v1 - make v1 tx outputs
* param: output_proposals -
* outparam: outputs_out -
* outparam: output_amounts_out -
* outparam: output_amount_commitment_blinding_factors_out -
* outparam: output_enote_ephemeral_pubkeys_out -
*/
void make_v1_outputs_v1(const std::vector<SpOutputProposalV1> &output_proposals,
    std::vector<SpEnoteV1> &outputs_out,
    std::vector<rct::xmr_amount> &output_amounts_out,
    std::vector<crypto::secret_key> &output_amount_commitment_blinding_factors_out,
    std::vector<crypto::x25519_pubkey> &output_enote_ephemeral_pubkeys_out);
/**
* brief: finalize_v1_output_proposal_set_v1 - finalize a set of output proposals by adding 0-1 new proposals
*        (new proposals are appended)
*   - NOT FOR COINBASE OUTPUT SETS (coinbase output sets don't need to be finalized)
*   - add a flagging/hidden change/self-spend output if necessary
*   - All output sets will contain exactly 1 flagging self-send, plus any number of hidden self-sends, either from
*     the original set passed in, or by adding an flagging/hidden change enote here.
*     - The goal of this function is for all txs made from output sets produced by this function to be identifiable by view
*       tag checks. That way, a signer scanning for balance recovery only needs key images from txs that are flagged by a
*       view tag check in order to A) identify all spent enotes, B) identify all of their self-send enotes in txs that use
*       output sets from this function. This optimizes third-party view-tag scanning services, which only need to transmit
*       key images from txs with view tag matches to the local client. Txs with no user-specified selfsends that don't use
*       this function (or an equivalent) to define the output set WILL cause failures to identify spent enotes in that
*       workflow.
*   - All 2-output txs with both being self-sends should have 1 'change' and one 'self-spend' type enotes. This is to
*     ensure that the derivations for the 2 self-sends with a shared ephemeral pubkey will be unique.
* param: total_input_amount -
* param: transaction_fee -
* param: change_destination -
* param: jamtis_spend_pubkey -
* param: s_view_balance -
* inoutparam: normal_payment_proposals_inout -
* inoutparam: selfsend_payment_proposals_inout -
*/
boost::optional<OutputProposalSetExtraTypeV1> try_get_additional_output_type_for_output_set_v1(
    const std::size_t num_outputs,
    const std::vector<jamtis::JamtisSelfSendType> &self_send_output_types,
    const std::vector<bool> &self_send_output_is_hidden,
    const bool output_ephemeral_pubkeys_are_unique,
    const rct::xmr_amount change_amount);
void make_additional_output_v1(const OutputProposalSetExtraTypeV1 additional_output_type,
    const crypto::x25519_pubkey &first_enote_ephemeral_pubkey,
    const std::uint8_t num_primary_view_tag_bits,
    const jamtis::JamtisDestinationV1 &change_destination,
    const crypto::secret_key &s_view_balance,
    const rct::xmr_amount change_amount,
    const jamtis::JamtisOnetimeAddressFormat onetime_address_format,
    jamtis::JamtisPaymentProposalSelfSendV1 &selfsend_proposal_out);  //exposed for unit testing
void finalize_v1_output_proposal_set_v1(const boost::multiprecision::uint128_t &total_input_amount,
    const rct::xmr_amount transaction_fee,
    const jamtis::JamtisDestinationV1 &change_destination,
    const crypto::secret_key &s_view_balance,
    std::vector<jamtis::JamtisPaymentProposalV1> &normal_payment_proposals_inout,
    std::vector<jamtis::JamtisPaymentProposalSelfSendV1> &selfsend_payment_proposals_inout);
/**
* brief: finalize_tx_extra_v1 - combine partial memos into a complete tx extra field
* param: partial_memo -
* param: output_proposals -
* outparam: tx_extra_out -
*/
void finalize_tx_extra_v1(const TxExtra &partial_memo,
    const std::vector<SpCoinbaseOutputProposalV1> &output_proposals,
    TxExtra &tx_extra_out);
void finalize_tx_extra_v1(const TxExtra &partial_memo,
    const std::vector<SpOutputProposalV1> &output_proposals,
    TxExtra &tx_extra_out);
/**
* brief: check_v1_tx_supplement_semantics_v1 - check semantics of a tx supplement (v1)
*   - throws if a check fails
*   - check: num enote ephemeral pubkeys == num outputs
*   - check: all enote ephemeral pubkeys should be unique
* param: tx_supplement -
* param: num_outputs -
*/
void check_v1_tx_supplement_semantics_v1(const SpTxSupplementV1 &tx_supplement, const std::size_t num_outputs);
/**
* brief: check_v1_tx_supplement_semantics_v2 - check semantics of a tx supplement (v2)
*   - throws if a check fails
*   - check: if num outputs == 2, there should be 1 enote ephemeral pubkey
*   - check: otherwise, should be 'num_outputs' enote ephemeral pubkeys
*   - check: all enote ephemeral pubkeys should be unique
* param: tx_supplement -
* param: num_outputs -
*/
void check_v1_tx_supplement_semantics_v2(const SpTxSupplementV1 &tx_supplement, const std::size_t num_outputs);

} //namespace sp

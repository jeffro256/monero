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

// A 'payment proposal' is a proposal to make an enote sending funds to a Carrot address.
// Carrot: Cryptonote Address For Rerandomizable-RingCT-Output Transactions

#pragma once

//local headers
#include "cryptonote_basic/cryptonote_basic.h"
#include "cryptonote_basic/subaddress_index.h"
#include "jamtis_support_types.h"
#include "sp_core_types.h"
#include "tx_extra.h"

//third party headers

//standard headers
#include <optional>

//forward declarations


namespace sp
{
namespace jamtis
{

////
// CarrotPaymentProposalV1
// - for creating an output proposal to send an amount to someone
///
struct CarrotPaymentProposalV1 final
{
    /// user address
    cryptonote::account_public_address destination;
    /// is destination a subaddress?
    bool is_subaddress;
    /// legacy payment id pid: null for main addresses and subaddresses
    payment_id_t payment_id;
    /// b
    rct::xmr_amount amount;
    /// secret 16-byte randomness for Janus anchor
    carrot_anchor_t randomness;

    /// memo elements to add to the tx memo
    TxExtra partial_memo;
};

////
// CarrotPaymentProposalSelfSendV1
// - for creating an output proposal to send an change to yourself
///
struct CarrotPaymentProposalSelfSendV1 final
{
    /// subaddress index within account for destination of funds: j
    cryptonote::subaddress_index destination_index;
    /// b
    rct::xmr_amount amount;

    /// enote ephemeral pubkey: xr G
    crypto::x25519_pubkey enote_ephemeral_pubkey;

    /// memo elements to add to the tx memo
    TxExtra partial_memo;
};

/// equality operators
bool operator==(const CarrotPaymentProposalV1 &a, const CarrotPaymentProposalV1 &b);
/// equality operators
bool operator==(const CarrotPaymentProposalSelfSendV1 &a, const CarrotPaymentProposalSelfSendV1 &b);

/**
* brief: get_enote_ephemeral_pubkey - get the proposal's enote ephemeral pubkey D_e
* param: proposal -
* outparam: enote_ephemeral_pubkey_out -
*/
void get_enote_ephemeral_pubkey(const CarrotPaymentProposalV1 &proposal,
    crypto::x25519_pubkey &enote_ephemeral_pubkey_out);
/**
* brief: get_coinbase_output_proposal_v1 - convert the jamtis proposal to a coinbase output proposal
* param: proposal -
* param: block_height - height of the coinbase tx's block
* outparam: output_enote_core_out -
* outparam: enote_ephemeral_pubkey_out -
* outparam: addr_tag_enc_out -
* outparam: view_tag_out -
* outparam: partial_memo_out -
*/
void get_coinbase_output_proposal_v1(const CarrotPaymentProposalV1 &proposal,
    const std::uint64_t block_height,
    SpCoinbaseEnoteCore &output_enote_core_out,
    crypto::x25519_pubkey &enote_ephemeral_pubkey_out,
    encrypted_address_tag_t &addr_tag_enc_out,
    view_tag_t &view_tag_out,
    TxExtra &partial_memo_out);
/**
* brief: get_output_proposal_v1 - convert the jamtis proposal to an output proposal
* param: proposal -
* param: input_context -
* outparam: output_proposal_core_out -
* outparam: enote_ephemeral_pubkey_out -
* outparam: encrypted_payment_id_out -
* outparam: encrypted_amount_out -
* outparam: addr_tag_enc_out -
* outparam: view_tag_out -
* outparam: partial_memo_out -
*/
void get_output_proposal_v1(const CarrotPaymentProposalV1 &proposal,
    const rct::key &input_context,
    SpOutputProposalCore &output_proposal_core_out,
    crypto::x25519_pubkey &enote_ephemeral_pubkey_out,
    std::optional<encrypted_payment_id_t> &encrypted_payment_id_out,
    encrypted_amount_t &encrypted_amount_out,
    encrypted_address_tag_t &addr_tag_enc_out,
    view_tag_t &view_tag_out,
    TxExtra &partial_memo_out);
/**
* brief: get_output_proposal_v1 - convert the jamtis proposal to an output proposal
* param: proposal -
* param: k_view -
* param: primary_address_spend_pubkey -
* param: input_context -
* outparam: output_proposal_core_out -
* outparam: enote_ephemeral_pubkey_out -
* outparam: encrypted_amount_out -
* outparam: addr_tag_enc_out -
* outparam: view_tag_out -
* outparam: partial_memo_out -
*/
void get_output_proposal_v1(const CarrotPaymentProposalSelfSendV1 &proposal,
    const crypto::secret_key &k_view,
    const crypto::public_key &primary_address_spend_pubkey,
    const rct::key &input_context,
    SpOutputProposalCore &output_proposal_core_out,
    crypto::x25519_pubkey &enote_ephemeral_pubkey_out,
    encrypted_amount_t &encrypted_amount_out,
    encrypted_address_tag_t &addr_tag_enc_out,
    view_tag_t &view_tag_out,
    TxExtra &partial_memo_out);
/**
* brief: gen_jamtis_payment_proposal_v1 - generate a random proposal
* param: is_subaddress - whether to generate a proposal to subaddress
* param: has_payment_id - true to generate non-zero payment ID, false for null payment ID
* param: amount -
* param: num_random_memo_elements -
* return: a random proposal
*/
CarrotPaymentProposalV1 gen_carrot_payment_proposal_v1(const bool is_subaddress,
    const bool has_payment_id,
    const rct::xmr_amount amount,
    const std::size_t num_random_memo_elements);

} //namespace jamtis
} //namespace sp

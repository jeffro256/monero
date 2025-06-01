// Copyright (c) 2025, The Monero Project
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
#include "carrot_impl/address_device.h"
#include "carrot_impl/input_selection.h"
#include "fee_priority.h"
#include "fcmp_pp/tree_cache.h"
#include "wallet2_basic/wallet2_types.h"

//third party headers

//standard headers
#include <unordered_map>

//forward declarations

namespace tools
{
namespace wallet
{
struct multisig_sig
{
    rct::rctSig sigs;
    std::unordered_set<crypto::public_key> ignore;
    std::unordered_set<rct::key> used_L;
    std::unordered_set<crypto::public_key> signing_keys;
    rct::multisig_out msout;

    rct::keyM total_alpha_G;
    rct::keyM total_alpha_H;
    rct::keyV c_0;
    rct::keyV s;
};

struct PreCarrotTransactionProposal
{
    std::vector<cryptonote::tx_source_entry> sources;
    cryptonote::tx_destination_entry change_dts;
    std::vector<cryptonote::tx_destination_entry> splitted_dsts; // split, includes change
    std::vector<size_t> selected_transfers;
    std::vector<uint8_t> extra;
    uint64_t unlock_time;
    bool use_rct;
    rct::RCTConfig rct_config;
    bool use_view_tags;
    std::vector<cryptonote::tx_destination_entry> dests; // original setup, does not include change
    uint32_t subaddr_account;   // subaddress account of your wallet to be used in this transfer
    std::set<uint32_t> subaddr_indices;  // set of address indices used as inputs in this transfer

    enum construction_flags_ : uint8_t
    {
        _use_rct          = 1 << 0, // 00000001
        _use_view_tags    = 1 << 1  // 00000010
        // next flag      = 1 << 2  // 00000100
        // ...
        // final flag     = 1 << 7  // 10000000
    };
    uint8_t construction_flags;
};

using tx_reconstruct_variant_t = std::variant<
        PreCarrotTransactionProposal,
        carrot::CarrotTransactionProposalV1
    >;
std::vector<cryptonote::tx_destination_entry> finalized_destinations_ref(const tx_reconstruct_variant_t&,
    const carrot::view_incoming_key_device &k_view_dev);
cryptonote::tx_destination_entry change_destination_ref(const tx_reconstruct_variant_t&,
    const carrot::view_incoming_key_device &k_view_dev);
rct::xmr_amount fee_ref(const tx_reconstruct_variant_t&);
std::optional<crypto::hash8> short_payment_id_ref(const tx_reconstruct_variant_t&);
std::optional<crypto::hash> long_payment_id_ref(const tx_reconstruct_variant_t&);
std::vector<crypto::public_key> spent_onetime_addresses_ref(const tx_reconstruct_variant_t&);
boost::multiprecision::uint128_t input_amount_total_ref(const tx_reconstruct_variant_t&);
std::vector<std::uint64_t> ring_sizes_ref(const tx_reconstruct_variant_t&);
std::uint64_t unlock_time_ref(const tx_reconstruct_variant_t&);
const std::vector<std::uint8_t> &extra_ref(const tx_reconstruct_variant_t&);

// The convention for destinations is:
// dests does not include change
// splitted_dsts (in construction_data) does
struct pending_tx
{
    cryptonote::transaction tx;
    uint64_t dust, fee;
    bool dust_added_to_fee;
    cryptonote::tx_destination_entry change_dts;
    std::string key_images;
    crypto::secret_key tx_key;
    std::vector<crypto::secret_key> additional_tx_keys;
    std::vector<cryptonote::tx_destination_entry> dests;
    std::vector<multisig_sig> multisig_sigs;
    crypto::secret_key multisig_tx_key_entropy;
    uint32_t subaddr_account;            // subaddress account of your wallet to be used in this transfer
    std::set<uint32_t> subaddr_indices;  // set of address indices used as inputs in this transfer

    tx_reconstruct_variant_t construction_data;
};

/**
 * brief: collect_non_burned_transfers_by_onetime_address - index transfers by OTA, including a burning bug filter
 * param: transfers -
 */
std::unordered_map<crypto::public_key, size_t> collect_non_burned_transfers_by_onetime_address(
    const wallet2_basic::transfer_container &transfers);

/**
 * brief: collect_carrot_input_candidate_list - filter and convert wallet2 transfer contain into carrot input candidates
 * param: transfers - wallet2 incoming transfers list
 * param: from_subaddr_account - ignore transfers not addressed to this major account index
 * param: from_subaddr_indices - ignore transfers not addressed to one of these minor account indices, empty means all
 * param: ignore_above - ignore transfers with an amount greater than this limit
 * param: ignore_below - ignore transfers with an amount less than this limit
 * param: top_block_index - block index of current top known block in the chain
 * return: filtered carrot input candidate list derived from transfer container
 */
std::vector<carrot::InputCandidate> collect_carrot_input_candidate_list(
    const wallet2_basic::transfer_container &transfers,
    const std::uint32_t from_subaddr_account,
    const std::set<std::uint32_t> &from_subaddr_indices,
    const rct::xmr_amount ignore_above,
    const rct::xmr_amount ignore_below,
    const std::uint64_t top_block_index);

std::vector<carrot::CarrotTransactionProposalV1> make_carrot_transaction_proposals_wallet2_transfer(
    const wallet2_basic::transfer_container &transfers,
    const std::unordered_map<crypto::public_key, cryptonote::subaddress_index> &subaddress_map,
    const std::vector<cryptonote::tx_destination_entry> &dsts,
    const rct::xmr_amount fee_per_weight,
    std::vector<uint8_t> extra,
    const uint32_t subaddr_account,
    const std::set<uint32_t> &subaddr_indices,
    const rct::xmr_amount ignore_above,
    const rct::xmr_amount ignore_below,
    std::set<std::uint32_t> subtract_fee_from_outputs,
    const std::uint64_t top_block_index);

std::vector<carrot::CarrotTransactionProposalV1> make_carrot_transaction_proposals_wallet2_sweep(
    const wallet2_basic::transfer_container &transfers,
    const std::unordered_map<crypto::public_key, cryptonote::subaddress_index> &subaddress_map,
    const std::vector<crypto::key_image> &input_key_images,
    const cryptonote::account_public_address &address,
    const bool is_subaddress,
    const size_t n_dests_per_tx,
    const rct::xmr_amount fee_per_weight,
    std::vector<uint8_t> extra,
    const std::uint64_t top_block_index);

std::vector<carrot::CarrotTransactionProposalV1> make_carrot_transaction_proposals_wallet2_sweep_all(
    const wallet2_basic::transfer_container &transfers,
    const std::unordered_map<crypto::public_key, cryptonote::subaddress_index> &subaddress_map,
    const rct::xmr_amount only_below,
    const cryptonote::account_public_address &address,
    const bool is_subaddress,
    const size_t n_dests_per_tx,
    const rct::xmr_amount fee_per_weight,
    std::vector<uint8_t> extra,
    const std::uint32_t subaddr_account,
    const std::set<uint32_t> &subaddr_indices,
    const std::uint64_t top_block_index);

carrot::OutputOpeningHintVariant make_sal_opening_hint_from_transfer_details(const wallet2_basic::transfer_details &td);

/**
 * brief: collect_selected_transfer_indices - get index into transfers list of spent enotes in a potential transaction
 * param: tx_construction_data -
 * param: transfers -
 * return: list of spent input enotes indices in construction-specified order, not necessarily final transaction order
 *
 * WARNING: The indices returned assumes the best case scenario for burning bugs for pre-Carrot
 * transactions. If the transfers list contains multiple pre-Carrot enotes with the same onetime
 * address, this function returns the index of the best of the duplicates. If you do not trust the
 * originating source of this construction data, then this is not safe. Validating the amounts
 * actually line up with the best case, instead of trusting, would require tx_reconstruct_variant_t
 * to store openings for the pseudo output amount commitments. This isn't an issue w/ spending
 * Carrot enotes since Carrot mitigates the burning bug statelessly.
 */
std::vector<std::size_t> collect_selected_transfer_indices(const tx_reconstruct_variant_t &tx_construction_data,
    const wallet2_basic::transfer_container &transfers);

std::unordered_map<crypto::key_image, fcmp_pp::FcmpPpSalProof> sign_carrot_transaction_proposal(
    const carrot::CarrotTransactionProposalV1 &tx_proposal,
    const std::vector<FcmpRerandomizedOutputCompressed> &rerandomized_outputs,
    const carrot::cryptonote_hierarchy_address_device &addr_dev,
    const crypto::secret_key &k_spend);

cryptonote::transaction finalize_fcmps_and_range_proofs(
    const std::vector<crypto::key_image> &sorted_input_key_images,
    const std::vector<FcmpRerandomizedOutputCompressed> &sorted_rerandomized_outputs,
    const std::vector<fcmp_pp::FcmpPpSalProof> &sorted_sal_proofs,
    const std::vector<carrot::RCTOutputEnoteProposal> &output_enote_proposals,
    const carrot::encrypted_payment_id_t &encrypted_payment_id,
    const rct::xmr_amount fee,
    const fcmp_pp::curve_trees::TreeCacheV1 &tree_cache,
    const fcmp_pp::curve_trees::CurveTreesV1 &curve_trees);

//! @TODO: accept already-calculated rerandomized outputs and their blinds
//! @TODO: rename, there are not `transfer_details` structs required anymore
cryptonote::transaction finalize_all_proofs_from_transfer_details(
    const carrot::CarrotTransactionProposalV1 &tx_proposal,
    const fcmp_pp::curve_trees::TreeCacheV1 &tree_cache,
    const fcmp_pp::curve_trees::CurveTreesV1 &curve_trees,
    const cryptonote::account_keys &acc_keys);

pending_tx make_pending_carrot_tx(const carrot::CarrotTransactionProposalV1 &tx_proposal,
    const std::vector<crypto::key_image> &sorted_input_key_images,
    const carrot::view_incoming_key_device &k_view_incoming_dev);

crypto::hash8 get_pending_tx_payment_id(const pending_tx &ptx);

pending_tx finalize_all_proofs_from_transfer_details_as_pending_tx(
    const carrot::CarrotTransactionProposalV1 &tx_proposal,
    const fcmp_pp::curve_trees::TreeCacheV1 &tree_cache,
    const fcmp_pp::curve_trees::CurveTreesV1 &curve_trees,
    const cryptonote::account_keys &acc_keys);

} //namespace wallet
} //namespace tools

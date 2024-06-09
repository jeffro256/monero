// Copyright (c) 2024, The Monero Project
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

#include "common/container_helpers.h"
#include "crypto/crypto.h"
#include "crypto/generators.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_core/cryptonote_tx_utils.h"
#include "misc_log_ex.h"
#include "ringct/rctOps.h"
#include "seraphis_core/jamtis_account_secrets.h"
#include "seraphis_core/jamtis_enote_utils.h"
#include "seraphis_core/jamtis_payment_proposal.h"
#include "seraphis_main/tx_builders_outputs.h"
#include "seraphis_impl/seraphis_serialization.h"
#include "serialization/binary_utils.h"
#include "serialization/string.h"

#include "cryptonote_basic/tx_extra.h"//needs to be at that end

using namespace cryptonote;

static bool check_fcmppp_key_image(const crypto::secret_key &x,
    const crypto::secret_key &y,
    const rct::key &onetime_address,
    const crypto::key_image &key_image)
{
    // Check Ko' ?= x G + y T
    rct::key onetime_address_reproduced;
    rct::addKeys2(onetime_address_reproduced, rct::sk2rct(x), rct::sk2rct(y), rct::pk2rct(crypto::get_U()));//yes I know it says get_U()
    if (onetime_address_reproduced != onetime_address)
        return false;
    
    // Check L' = x Hp(Ko)
    crypto::key_image key_image_reproduced;
    crypto::generate_key_image(rct::rct2pk(onetime_address), x, key_image_reproduced);
    if (key_image_reproduced != key_image)
        return false;

    return true;
}

// sender account keys
// extra
// unlock_time=0
// rct=true
// rct_config{}
// sort outputs myself
// use_view_tags is irrelevant now
static void make_jamtis_rct_transaction_pruned(
    const std::vector<rct::xmr_amount>& inputs,
    const rct::xmr_amount fee,
    std::vector<sp::jamtis::JamtisPaymentProposalV1> normal_payment_proposals,
    const rct::key &rct_spend_pubkey,
    const crypto::secret_key &s_view_balance,
    cryptonote::transaction& tx)
{
    std::vector<rct::key> amount_keys;
    tx.set_null();
    amount_keys.clear();

    tx.version = 2;
    tx.unlock_time = 0;
    tx.vin.clear();

    tx.rct_signatures.type = rct::RCTTypeBulletproofPlus;

    tx.extra.clear();

    std::vector<crypto::key_image> legacy_key_images;
    rct::xmr_amount in_amount{0};
    for (const auto &i : inputs)
    {
        in_amount += i;
        legacy_key_images.emplace_back(rct::rct2ki(rct::pkGen()));
    }

    // derive account secrets
    crypto::x25519_secret_key d_unlock_received;
    crypto::x25519_secret_key d_identify_received;
    crypto::x25519_secret_key d_filter_assist;
    crypto::secret_key s_generate_address;
    crypto::x25519_pubkey exchangebase_pubkey;
    crypto::x25519_pubkey identify_received_pubkey;
    crypto::x25519_pubkey filter_assist_pubkey;
    sp::jamtis::make_jamtis_unlockreceived_key(s_view_balance, d_unlock_received);
    sp::jamtis::make_jamtis_identifyreceived_key(s_view_balance, d_identify_received);
    sp::jamtis::make_jamtis_filterassist_key(s_view_balance, d_filter_assist);
    sp::jamtis::make_jamtis_generateaddress_secret(s_view_balance, s_generate_address);
    sp::jamtis::make_jamtis_exchangebase_pubkey(d_unlock_received, exchangebase_pubkey);
    sp::jamtis::make_jamtis_identifyreceived_pubkey(d_identify_received, exchangebase_pubkey, identify_received_pubkey);
    sp::jamtis::make_jamtis_filterassist_pubkey(d_filter_assist, exchangebase_pubkey, filter_assist_pubkey);

    // make change destination
    const sp::jamtis::address_index_t change_address_index{sp::jamtis::gen_address_index()};
    sp::jamtis::JamtisDestinationV1 change_destination;
    sp::jamtis::make_jamtis_destination_v1_rct(rct_spend_pubkey,
        filter_assist_pubkey,
        identify_received_pubkey,
        exchangebase_pubkey,
        s_generate_address,
        change_address_index,
        change_destination);

    // finalize output proposals
    std::vector<sp::jamtis::JamtisPaymentProposalSelfSendV1> selfsend_payment_proposals;
    sp::finalize_v1_output_proposal_set_v1(in_amount,
        fee,
        change_destination,
        s_view_balance,
        normal_payment_proposals,
        selfsend_payment_proposals);
    
    const std::uint8_t num_primary_view_tag_bits{sp::get_shared_num_primary_view_tag_bits(
        normal_payment_proposals,
        selfsend_payment_proposals,
        {},
        {}
    )};

    // input context
    rct::key input_context;
    sp::jamtis::make_jamtis_input_context_standard(legacy_key_images, {}, input_context);

    // output proposals
    std::vector<sp::SpOutputProposalV1> output_proposals;
    output_proposals.reserve(normal_payment_proposals.size() +
        selfsend_payment_proposals.size());

    for (const sp::jamtis::JamtisPaymentProposalV1 &normal_payment_proposal : normal_payment_proposals)
        sp::make_v1_output_proposal_v1(normal_payment_proposal,
            input_context,
            tools::add_element(output_proposals));

    for (const sp::jamtis::JamtisPaymentProposalSelfSendV1 &selfsend_payment_proposal :
        selfsend_payment_proposals)
    {
        sp::make_v1_output_proposal_v1(selfsend_payment_proposal,
            s_view_balance,
            input_context,
            tools::add_element(output_proposals));
    }

    // sort output proposals
    std::sort(output_proposals.begin(), output_proposals.end(), tools::compare_func<sp::SpOutputProposalV1>(sp::compare_Ko));

    // make output enotes
    std::vector<sp::SpEnoteV1> sp_enotes;
    std::vector<rct::xmr_amount> output_amounts;
    std::vector<crypto::secret_key> output_amount_commitment_blinding_factors;
    std::vector<crypto::x25519_pubkey> output_enote_ephemeral_pubkeys;
    make_v1_outputs_v1(output_proposals,
        sp_enotes,
        output_amounts,
        output_amount_commitment_blinding_factors,
        output_enote_ephemeral_pubkeys);

    // fill in extra tx data and tx_outs
    cryptonote::tx_extra_jamtis_v1 jamtis_extra;
    for (const sp::SpEnoteV1 &sp_enote : sp_enotes)
    {
        cryptonote::tx_out &txout = tools::add_element(tx.vout);
        rct::ecdhTuple &ecdhtup = tools::add_element(tx.rct_signatures.ecdhInfo);
        rct::key &amount_commitment = tools::add_element(tx.rct_signatures.outPk).mask;
        cryptonote::tx_extra_jamtis_v1::enote_entry_t &jamtis_output = tools::add_element(jamtis_extra.output_info);

        txout.amount = 0;
        crypto::view_tag view_tag_byte1;
        memcpy(&view_tag_byte1, &sp_enote.view_tag, 1);
        txout.target = cryptonote::txout_to_tagged_key{rct::rct2pk(sp_enote.core.onetime_address), view_tag_byte1};

        memcpy(&ecdhtup.amount, &sp_enote.encrypted_amount, 8);

        amount_commitment = sp_enote.core.amount_commitment;

        memcpy(jamtis_output.addr_tag, sp_enote.addr_tag_enc.bytes, sp::jamtis::ADDRESS_INDEX_BYTES);
        memcpy(jamtis_output.view_tag_additional, sp_enote.view_tag.bytes + 1, 2);
    }

    // jamtis extra supplement
    jamtis_extra.num_primary_view_tag_bits = num_primary_view_tag_bits;
    jamtis_extra.enote_ephemeral_pubkeys = output_enote_ephemeral_pubkeys;

    // make input key images
    for (const crypto::key_image &ki : legacy_key_images)
        tx.vin.push_back({cryptonote::txin_to_key{0, {}, ki}});

    // add tx_extra into tx
    tx.extra.clear();
    std::string serialized_field;
    cryptonote::tx_extra_field extra_field{jamtis_extra};
    CHECK_AND_ASSERT_THROW_MES(::serialization::dump_binary(extra_field, serialized_field),
        "Failed to serialize tx extra");

    // Check that we can calculate the pruned hash
    tx.pruned = true;
    cryptonote::get_pruned_transaction_hash(tx, crypto::null_hash);
}

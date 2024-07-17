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

#include <gtest/gtest.h>

#include "common/apply_permutation.h"
#include "common/container_helpers.h"
#include "crypto/crypto.h"
extern "C"
{
#include "crypto/crypto-ops.h"
}
#include "crypto/generators.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_core/cryptonote_tx_utils.h"
#include "misc_log_ex.h"
#include "ringct/rctOps.h"
#include "seraphis_core/carrot_payment_proposal.h"
#include "seraphis_core/jamtis_account_secrets.h"
#include "seraphis_core/jamtis_enote_utils.h"
#include "seraphis_core/jamtis_payment_proposal.h"
#include "seraphis_main/enote_record_utils.h"
#include "seraphis_main/enote_record_utils_carrot.h"
#include "seraphis_main/tx_builders_outputs.h"
#include "seraphis_mocks/jamtis_mock_keys.h"
#include "seraphis_impl/seraphis_serialization.h"
#include "serialization/binary_utils.h"
#include "serialization/string.h"
#include "string_tools.h"

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

static void make_jamtis_rct_input_context(const cryptonote::transaction_prefix &tx_prefix,
    rct::key &input_context_out)
{
    std::vector<crypto::key_image> legacy_key_images;
    legacy_key_images.reserve(tx_prefix.vin.size());
    for (const cryptonote::txin_v &in_v : tx_prefix.vin)
        legacy_key_images.push_back(boost::get<cryptonote::txin_to_key>(in_v).k_image);
    
    sp::jamtis::make_jamtis_input_context_standard(legacy_key_images, {}, input_context_out);
}

static void make_jamtis_rct_transaction_pruned(
    const std::vector<rct::xmr_amount>& inputs,
    const rct::xmr_amount fee,
    std::vector<sp::jamtis::JamtisPaymentProposalV1> normal_payment_proposals,
    const rct::key &rct_spend_pubkey,
    const crypto::secret_key &s_view_balance,
    cryptonote::transaction& tx)
{
    tx.set_null();

    tx.version = 2;
    tx.unlock_time = 0;
    tx.vin.clear();

    tx.rct_signatures.type = rct::RCTTypeBulletproofPlus;

    tx.extra.clear();

    CHECK_AND_ASSERT_THROW_MES(inputs.size(), "no inputs");

    // make input key images and sum input amounts
    rct::xmr_amount in_amount{0};
    for (const auto &i : inputs)
    {
        in_amount += i;
        tx.vin.push_back({cryptonote::txin_to_key{0, {}, rct::rct2ki(rct::pkGen())}});
    }

    // sort ins by their key image
    std::vector<size_t> ins_order(inputs.size());
    for (size_t n = 0; n < inputs.size(); ++n)
      ins_order[n] = n;
    std::sort(ins_order.begin(), ins_order.end(), [&tx](const size_t i0, const size_t i1) {
      const txin_to_key &tk0 = boost::get<txin_to_key>(tx.vin[i0]);
      const txin_to_key &tk1 = boost::get<txin_to_key>(tx.vin[i1]);
      return tk0.k_image < tk1.k_image;
    });
    tools::apply_permutation(ins_order, [&tx] (size_t i0, size_t i1) {
      std::swap(tx.vin[i0], tx.vin[i1]);
    });

    // sum output amounts
    rct::xmr_amount out_amount{0};
    for (const auto &p : normal_payment_proposals)
        out_amount += p.amount;

    CHECK_AND_ASSERT_THROW_MES(out_amount + fee <= in_amount,
        "output amount sum plus fee is greater than input sum!");

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
    make_jamtis_rct_input_context(tx, input_context);

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

    // add jamtis_extra into tx.extra
    tx.extra.clear();
    std::string serialized_field;
    cryptonote::tx_extra_field extra_field{jamtis_extra};
    CHECK_AND_ASSERT_THROW_MES(::serialization::dump_binary(extra_field, serialized_field),
        "Failed to serialize tx extra");
    tx.extra.resize(serialized_field.size());
    memcpy(&tx.extra[0], serialized_field.data(), serialized_field.size());

    // Check that we can calculate the pruned hash
    tx.pruned = true;
    tx.invalidate_hashes();
    cryptonote::get_pruned_transaction_hash(tx, crypto::null_hash);
}

static void finalize_payment_proposal_set(const rct::xmr_amount in_amount,
    const rct::xmr_amount fee,
    std::vector<sp::jamtis::CarrotPaymentProposalV1> &payment_proposals_inout,
    std::vector<sp::jamtis::CarrotPaymentProposalSelfSendV1> &selfsend_proposals_inout)
{
    // @TODO: handle proposal amount overfloe

    CHECK_AND_ASSERT_THROW_MES(!payment_proposals_inout.empty(),
        "finalize payment proposal set: no payment proposals");

    rct::xmr_amount out_amount{0};
    for (const sp::jamtis::CarrotPaymentProposalV1 &payment_proposal : payment_proposals_inout)
        out_amount += payment_proposal.amount;

    CHECK_AND_ASSERT_THROW_MES(out_amount <= in_amount + fee,
        "finalize payment proposal set: proposals output amount is too high");

    const rct::xmr_amount change_remaining{in_amount - out_amount - fee};
    const bool missing_selfsend{selfsend_proposals_inout.empty()};
    const bool needs_selfsend{change_remaining || missing_selfsend};
    if (needs_selfsend)
    {
        crypto::x25519_pubkey enote_ephemeral_pubkey;
        if (payment_proposals_inout.size() == 1)
            sp::jamtis::get_enote_ephemeral_pubkey(payment_proposals_inout[0], enote_ephemeral_pubkey);
        else
            enote_ephemeral_pubkey = crypto::x25519_pubkey_gen();

        selfsend_proposals_inout.push_back(sp::jamtis::CarrotPaymentProposalSelfSendV1{
                .amount = change_remaining,
                .enote_ephemeral_pubkey = enote_ephemeral_pubkey,
                .partial_memo = {}
            });
    }
}

static constexpr std::uint8_t DUMMY_NPBITS{8};
static void make_carrot_rct_transaction_pruned(
    const std::vector<rct::xmr_amount>& inputs,
    const rct::xmr_amount fee,
    std::vector<sp::jamtis::CarrotPaymentProposalV1> payment_proposals,
    const crypto::public_key &primary_address_spend_pubkey,
    const crypto::secret_key &k_view,
    cryptonote::transaction& tx)
{
    tx.set_null();
    tx.version = 2;
    tx.rct_signatures.type = rct::RCTTypeBulletproofPlus;

    CHECK_AND_ASSERT_THROW_MES(inputs.size(), "no inputs");

    // make input key images and sum input amounts
    rct::xmr_amount in_amount{0};
    for (const auto &i : inputs)
    {
        in_amount += i;
        tx.vin.push_back({cryptonote::txin_to_key{0, {}, rct::rct2ki(rct::pkGen())}});
    }

    // sort ins by their key image
    std::vector<size_t> ins_order(inputs.size());
    for (size_t n = 0; n < inputs.size(); ++n)
      ins_order[n] = n;
    std::sort(ins_order.begin(), ins_order.end(), [&tx](const size_t i0, const size_t i1) {
      const txin_to_key &tk0 = boost::get<txin_to_key>(tx.vin[i0]);
      const txin_to_key &tk1 = boost::get<txin_to_key>(tx.vin[i1]);
      return tk0.k_image < tk1.k_image;
    });
    tools::apply_permutation(ins_order, [&tx] (size_t i0, size_t i1) {
      std::swap(tx.vin[i0], tx.vin[i1]);
    });

    // sum output amounts
    rct::xmr_amount out_amount{0};
    for (const auto &p : payment_proposals)
        out_amount += p.amount;

    CHECK_AND_ASSERT_THROW_MES(out_amount + fee <= in_amount,
        "output amount sum plus fee is greater than input sum!");

    // finalize output proposals
    std::vector<sp::jamtis::CarrotPaymentProposalSelfSendV1> selfsend_proposals;
    finalize_payment_proposal_set(in_amount,
        fee,
        payment_proposals,
        selfsend_proposals);

    // input context
    rct::key input_context;
    make_jamtis_rct_input_context(tx, input_context);

    // output proposals
    std::vector<sp::SpOutputProposalV1> output_proposals;
    output_proposals.reserve(payment_proposals.size() + 1);

    for (const sp::jamtis::CarrotPaymentProposalV1 &payment_proposal : payment_proposals)
        sp::make_v1_output_proposal_v1(payment_proposal,
            DUMMY_NPBITS,
            input_context,
            tools::add_element(output_proposals));
    
    for (const sp::jamtis::CarrotPaymentProposalSelfSendV1 &selfsend_proposal : selfsend_proposals)
        sp::make_v1_output_proposal_v1(selfsend_proposal,
            DUMMY_NPBITS,
            k_view,
            primary_address_spend_pubkey,
            input_context,
            tools::add_element(output_proposals));

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
    jamtis_extra.num_primary_view_tag_bits = 0;
    jamtis_extra.enote_ephemeral_pubkeys = output_enote_ephemeral_pubkeys;

    // add jamtis_extra into tx.extra
    tx.extra.clear();
    std::string serialized_field;
    cryptonote::tx_extra_field extra_field{jamtis_extra};
    CHECK_AND_ASSERT_THROW_MES(::serialization::dump_binary(extra_field, serialized_field),
        "Failed to serialize tx extra");
    tx.extra.resize(serialized_field.size());
    memcpy(&tx.extra[0], serialized_field.data(), serialized_field.size());

    // Check that we can calculate the pruned hash
    tx.pruned = true;
    tx.invalidate_hashes();
    cryptonote::get_pruned_transaction_hash(tx, crypto::null_hash);
}

static bool try_parse_jamtis_from_tx(const cryptonote::transaction &tx,
    std::vector<sp::SpEnoteV1> &enotes_out,
    std::vector<crypto::x25519_pubkey> &enote_ephemeral_pubkeys_out,
    std::uint8_t &num_primary_view_tag_bits_out)
{
    enotes_out.clear();
    enote_ephemeral_pubkeys_out.clear();
    num_primary_view_tag_bits_out = 0;

    const size_t nouts{tx.vout.size()};

    if (tx.version != 2)
        return false;
    else if (nouts < 2)
        return false;
    else if (tx.rct_signatures.outPk.size() != nouts)
        return false;
    else if (tx.rct_signatures.ecdhInfo.size() != nouts)
        return false;

    // assert all txouts are RingCT view tag outputs
    for (const auto &o : tx.vout)
        if (o.target.type() != typeid(cryptonote::txout_to_tagged_key) || o.amount)
            return false;

    // parse tx_extra
    std::vector<cryptonote::tx_extra_field> tx_extra_fields;
    if (!cryptonote::parse_tx_extra(tx.extra, tx_extra_fields))
        return false;

    // extra Jamtis info from extra
    cryptonote::tx_extra_jamtis_v1 jamtis_extra;
    bool found_jamtis{false};
    for (const cryptonote::tx_extra_field &extra_field : tx_extra_fields)
    {
        if (extra_field.type() == typeid(cryptonote::tx_extra_jamtis_v1))
        {
            jamtis_extra = boost::get<cryptonote::tx_extra_jamtis_v1>(extra_field);
            found_jamtis = true;
        }
    }
    if (!found_jamtis || jamtis_extra.output_info.size() != nouts)
        return false;

    // assert correct num ephem keys for num txouts
    const size_t nephems{jamtis_extra.enote_ephemeral_pubkeys.size()};
    if ((nouts == 2 && nephems != 1) || (nouts > 2 && nouts != nephems))
        return false;

    // reserve result space
    enotes_out.reserve(nouts);
    enote_ephemeral_pubkeys_out.reserve(nephems);

    // for each txout, construct sp enote
    for (size_t i = 0; i < nouts; ++i)
    {
        const cryptonote::txout_to_tagged_key &taggedkey{boost::get<cryptonote::txout_to_tagged_key>(tx.vout[i].target)};

        sp::SpEnoteV1 &enote_out = tools::add_element(enotes_out);

        enote_out.core = sp::SpEnoteCore{
            .onetime_address = rct::pk2rct(taggedkey.key),
            .amount_commitment = tx.rct_signatures.outPk[i].mask
        };

        memcpy(enote_out.addr_tag_enc.bytes, jamtis_extra.output_info[i].addr_tag, sp::jamtis::ADDRESS_INDEX_BYTES);
        memcpy(enote_out.encrypted_amount.bytes, tx.rct_signatures.ecdhInfo[i].amount.bytes, sp::jamtis::ENCRYPTED_AMOUNT_BYTES);
        memcpy(enote_out.view_tag.bytes, &taggedkey.view_tag.data, 1);
        memcpy(enote_out.view_tag.bytes + 1, jamtis_extra.output_info[i].view_tag_additional, 2);
    }

    enote_ephemeral_pubkeys_out = std::move(jamtis_extra.enote_ephemeral_pubkeys);
    num_primary_view_tag_bits_out = jamtis_extra.num_primary_view_tag_bits;

    return true;
}

static bool try_get_enote_records_rct_tx(const cryptonote::transaction &tx,
    const rct::key &jamtis_spend_pubkey,
    const crypto::secret_key &s_view_balance,
    std::vector<sp::SpEnoteRecordV1> &enote_records_out)
{
    enote_records_out.clear();

    std::vector<sp::SpEnoteV1> enotes;
    std::vector<crypto::x25519_pubkey> enote_ephemeral_pubkeys;
    std::uint8_t num_primary_view_tag_bits;
    if (!try_parse_jamtis_from_tx(tx, enotes, enote_ephemeral_pubkeys, num_primary_view_tag_bits))
        return false;
    else if (enote_ephemeral_pubkeys.empty())
        return false;

    rct::key input_context;
    make_jamtis_rct_input_context(tx, input_context);

    enote_records_out.reserve(enotes.size());

    for (size_t i = 0; i < enotes.size(); ++i)
    {
        const crypto::x25519_pubkey &enote_ephemeral_pubkey{
                enote_ephemeral_pubkeys[std::min(i, enote_ephemeral_pubkeys.size() - 1)]
            };

        sp::SpEnoteRecordV1 enote_record;
        if (sp::try_get_enote_record_v1(enotes[i],
                enote_ephemeral_pubkey,
                num_primary_view_tag_bits,
                input_context,
                jamtis_spend_pubkey,
                s_view_balance,
                enote_record,
                sp::jamtis::JamtisOnetimeAddressFormat::RINGCT_V2))
            enote_records_out.push_back(std::move(enote_record));
    }

    return !enote_records_out.empty();
}

static bool try_get_carrot_enote_records_rct_tx(const cryptonote::transaction &tx,
    const crypto::secret_key &k_view,
    const crypto::public_key &primary_recipient_spend_pubkey,
    std::vector<sp::CarrotIntermediateEnoteRecordV1> &enote_records_out)
{
    enote_records_out.clear();

    std::vector<sp::SpEnoteV1> enotes;
    std::vector<crypto::x25519_pubkey> enote_ephemeral_pubkeys;
    std::uint8_t num_primary_view_tag_bits;
    if (!try_parse_jamtis_from_tx(tx, enotes, enote_ephemeral_pubkeys, num_primary_view_tag_bits))
        return false;
    else if (enote_ephemeral_pubkeys.empty())
        return false;

    rct::key input_context;
    make_jamtis_rct_input_context(tx, input_context);

    enote_records_out.reserve(enotes.size());

    for (size_t i = 0; i < enotes.size(); ++i)
    {
        const crypto::x25519_pubkey &enote_ephemeral_pubkey{
                enote_ephemeral_pubkeys[std::min(i, enote_ephemeral_pubkeys.size() - 1)]
            };

        sp::CarrotIntermediateEnoteRecordV1 intermediate_enote_record;
        if (sp::try_get_carrot_intermediate_enote_record_v1(enotes[i],
                enote_ephemeral_pubkey,
                input_context,
                k_view,
                primary_recipient_spend_pubkey,
                intermediate_enote_record))
            enote_records_out.push_back(intermediate_enote_record);
    }

    return !enote_records_out.empty();
}

TEST(jamtis_rct, pruned_tx_enote_record_basic)
{
    // make jamtis keys
    sp::jamtis::mocks::jamtis_mock_keys keys;
    sp::jamtis::mocks::make_jamtis_mock_keys(sp::jamtis::JamtisOnetimeAddressFormat::RINGCT_V2, keys);

    // make destination for keys
    const sp::jamtis::address_index_t address_index{sp::jamtis::gen_address_index()};
    sp::jamtis::JamtisDestinationV1 destination;
    sp::jamtis::mocks::make_address_for_user(keys, address_index, destination);

    // make payment proposal
    const sp::jamtis::JamtisPaymentProposalV1 payment_proposal{
            .destination = destination,
            .amount = 4,
            .onetime_address_format = keys.onetime_address_format,
            .enote_ephemeral_privkey = crypto::x25519_secret_key_gen(),
            .num_primary_view_tag_bits = 8,
            .partial_memo = {}
        };

    // make transaction with payment proposal
    const std::vector<rct::xmr_amount> input_amounts{5, 6};
    const rct::xmr_amount fee{1};
    cryptonote::transaction tx;
    make_jamtis_rct_transaction_pruned(input_amounts, fee, {payment_proposal}, keys.K_s_base, keys.s_vb, tx);
    ASSERT_EQ(2, tx.version);
    ASSERT_EQ(2, tx.vout.size());
    ASSERT_EQ(2, tx.rct_signatures.outPk.size());
    ASSERT_EQ(2, tx.rct_signatures.ecdhInfo.size());

    // scan transaction
    std::vector<sp::SpEnoteRecordV1> enote_records;
    ASSERT_TRUE(try_get_enote_records_rct_tx(tx, keys.K_s_base, keys.s_vb, enote_records));
    ASSERT_EQ(2, enote_records.size());
    ASSERT_TRUE((enote_records[0].type == sp::jamtis::JamtisEnoteType::PLAIN && enote_records[1].type == sp::jamtis::JamtisEnoteType::CHANGE)
        || (enote_records[0].type == sp::jamtis::JamtisEnoteType::CHANGE && enote_records[1].type == sp::jamtis::JamtisEnoteType::PLAIN));

    // assert values of plain record
    const bool first_is_plain{enote_records[0].type == sp::jamtis::JamtisEnoteType::PLAIN};
    const sp::SpEnoteRecordV1 &plain_enote_record{first_is_plain ? enote_records[0] : enote_records[1]};
    EXPECT_EQ(payment_proposal.amount, plain_enote_record.amount);
    crypto::secret_key plain_x;
    crypto::secret_key plain_y;
    sc_add(to_bytes(plain_x), to_bytes(keys.k_gi), to_bytes(plain_enote_record.enote_view_extension_g)); // x = k_gi + k^view_g
    sc_add(to_bytes(plain_y), to_bytes(keys.k_ps), to_bytes(plain_enote_record.enote_view_extension_u)); // y = k_ps + k^view_u
    EXPECT_TRUE(check_fcmppp_key_image(plain_x, plain_y, onetime_address_ref(plain_enote_record.enote), plain_enote_record.key_image));

    // assert values of selfsend change record
    const sp::SpEnoteRecordV1 &change_enote_record{first_is_plain ? enote_records[1] : enote_records[0]};
    rct::xmr_amount in_amount{0};
    for (const auto &i : input_amounts) in_amount += i;
    const rct::xmr_amount expected_change{in_amount - payment_proposal.amount - fee};
    EXPECT_EQ(expected_change, change_enote_record.amount);
    crypto::secret_key change_x;
    crypto::secret_key change_y;
    sc_add(to_bytes(change_x), to_bytes(keys.k_gi), to_bytes(change_enote_record.enote_view_extension_g)); // x = k_gi + k^view_g
    sc_add(to_bytes(change_y), to_bytes(keys.k_ps), to_bytes(change_enote_record.enote_view_extension_u)); // y = k_ps + k^view_u
    EXPECT_TRUE(check_fcmppp_key_image(change_x, change_y, onetime_address_ref(change_enote_record.enote), change_enote_record.key_image));
}

TEST(jamtis_rct, pruned_tx_enote_record_basic_carrot)
{
    // make jamtis keys
    cryptonote::account_base account;
    account.generate();

    // make payment proposal
    const sp::jamtis::CarrotPaymentProposalV1 payment_proposal{
            .destination = account.get_keys().m_account_address,
            .is_subaddress = false,
            .payment_id = sp::jamtis::null_payment_id,
            .amount = 4,
            .randomness = sp::jamtis::gen_address_tag(),
            .partial_memo = {}
        };

    // make transaction with payment proposal
    const std::vector<rct::xmr_amount> input_amounts{5, 6};
    const rct::xmr_amount fee{1};
    cryptonote::transaction tx;
    make_carrot_rct_transaction_pruned(input_amounts,
        fee,
        {payment_proposal},
        account.get_keys().m_account_address.m_spend_public_key,
        account.get_keys().m_view_secret_key,
        tx);
    ASSERT_EQ(2, tx.version);
    ASSERT_EQ(2, tx.vout.size());
    ASSERT_EQ(2, tx.rct_signatures.outPk.size());
    ASSERT_EQ(2, tx.rct_signatures.ecdhInfo.size());

    // scan transaction
    std::vector<sp::CarrotIntermediateEnoteRecordV1> enote_records;
    ASSERT_TRUE(try_get_carrot_enote_records_rct_tx(tx,
        account.get_keys().m_view_secret_key,
        account.get_keys().m_account_address.m_spend_public_key,
        enote_records));
    ASSERT_EQ(2, enote_records.size());

    // assert values of plain record
    const bool first_is_plain{enote_records[0].nominal_address_spend_pubkey == account.get_keys().m_account_address.m_spend_public_key};
    const sp::CarrotIntermediateEnoteRecordV1 &plain_enote_record{first_is_plain ? enote_records[0] : enote_records[1]};
    EXPECT_EQ(payment_proposal.amount, plain_enote_record.amount);

    // assert values of change record
    const sp::CarrotIntermediateEnoteRecordV1 &change_enote_record{first_is_plain ? enote_records[1] : enote_records[0]};
    rct::xmr_amount in_amount{0};
    for (const auto &i : input_amounts) in_amount += i;
    const rct::xmr_amount expected_change{in_amount - payment_proposal.amount - fee};
    EXPECT_EQ(expected_change, change_enote_record.amount);
}

TEST(jamtis_rct, finalize_carrot_0_change)
{
    {
        const rct::xmr_amount in_amount{17};
        const rct::xmr_amount fee{1};
        std::vector<sp::jamtis::CarrotPaymentProposalV1> payment_proposals{
            sp::jamtis::CarrotPaymentProposalV1{
                .destination = {},
                .is_subaddress = true,
                .payment_id = sp::jamtis::null_payment_id,
                .amount = 6,
                .randomness = sp::jamtis::gen_address_tag(),
                .partial_memo = {}
            },
            sp::jamtis::CarrotPaymentProposalV1{
                .destination = {},
                .is_subaddress = true,
                .payment_id = sp::jamtis::null_payment_id,
                .amount = 10,
                .randomness = sp::jamtis::gen_address_tag(),
                .partial_memo = {}
            }
        };
        std::vector<sp::jamtis::CarrotPaymentProposalSelfSendV1> selfsend_proposals;
        finalize_payment_proposal_set(in_amount,
            fee,
            payment_proposals,
            selfsend_proposals);
        EXPECT_EQ(2, payment_proposals.size());
        ASSERT_EQ(1, selfsend_proposals.size());
        EXPECT_EQ(0, selfsend_proposals.front().amount);
    }
}

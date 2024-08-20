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
#include "seraphis_crypto/sp_crypto_utils.h"
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

static void instantiate_jamtis_tx(
    const std::vector<crypto::key_image> &key_images,
    const std::vector<sp::SpEnoteV1> &enotes,
    const std::vector<crypto::x25519_pubkey> &enote_ephemeral_pubkeys,
    const std::uint8_t num_primary_view_tag_bits,
    const std::optional<sp::jamtis::encrypted_payment_id_t> &payment_id_enc,
    cryptonote::transaction &tx_out)
{
    tx_out.version = 2;
    tx_out.unlock_time = 0;
    tx_out.vin.clear();
    tx_out.rct_signatures.type = rct::RCTTypeCLSAG;

    crypto::key_image prev_ki{};
    for (const crypto::key_image &ki : key_images)
    {
        CHECK_AND_ASSERT_THROW_MES(ki > prev_ki, "key images are not sorted");
        tx_out.vin.push_back({cryptonote::txin_to_key{0, {}, ki}});
        prev_ki = ki;
    }

    const std::size_t nouts{enotes.size()};

    cryptonote::tx_extra_field extra_field{cryptonote::tx_extra_jamtis_v1{}};
    cryptonote::tx_extra_jamtis_v1 &jamtis_field{boost::get<cryptonote::tx_extra_jamtis_v1>(extra_field)};

    tx_out.vout.resize(nouts);
    tx_out.rct_signatures.outPk.resize(nouts);
    tx_out.rct_signatures.ecdhInfo.resize(nouts);
    jamtis_field.output_info.resize(nouts);
    for (size_t out_idx = 0; out_idx < nouts; ++out_idx)
    {
        const sp::SpEnoteV1 &enote{enotes.at(out_idx)};
        tx_out.vout[out_idx] = cryptonote::tx_out{
                0,
                cryptonote::txout_to_key{rct::rct2pk(enote.core.onetime_address)}
            };
        tx_out.rct_signatures.outPk[out_idx].mask = enote.core.amount_commitment;
        tx_out.rct_signatures.ecdhInfo[out_idx] = rct::ecdhTuple{};
        memcpy(tx_out.rct_signatures.ecdhInfo[out_idx].amount.bytes,
            enote.encrypted_amount.bytes,
            sp::jamtis::ENCRYPTED_AMOUNT_BYTES);
        memcpy(jamtis_field.output_info[out_idx].addr_tag_enc,
            enote.addr_tag_enc.bytes,
            sp::jamtis::ADDRESS_INDEX_BYTES);
        memcpy(jamtis_field.output_info[out_idx].view_tag,
            enote.view_tag.bytes,
            sp::jamtis::VIEW_TAG_BYTES);
    }
    jamtis_field.enote_ephemeral_pubkeys = enote_ephemeral_pubkeys;
    jamtis_field.num_primary_view_tag_bits = num_primary_view_tag_bits;

    std::string jamtis_serialized;
    CHECK_AND_ASSERT_THROW_MES(::serialization::dump_binary(extra_field, jamtis_serialized),
        "tx_extra_jamtis_v1 write serialization failed");
    tx_out.extra.resize(jamtis_serialized.size());
    memcpy(tx_out.extra.data(), jamtis_serialized.data(), jamtis_serialized.size());

    if (payment_id_enc)
    {
        crypto::hash8 payment_id_enc_hash8;
        memcpy(payment_id_enc_hash8.data, payment_id_enc->bytes, sp::jamtis::PAYMENT_ID_BYTES);
        std::string extra_nonce_string;
        cryptonote::set_encrypted_payment_id_to_tx_extra_nonce(extra_nonce_string, payment_id_enc_hash8);
        CHECK_AND_ASSERT_THROW_MES(cryptonote::add_extra_nonce_to_tx_extra(tx_out.extra, extra_nonce_string),
            "failed to add encrypted payment id to tx extra");
    }

    CHECK_AND_ASSERT_THROW_MES(cryptonote::sort_tx_extra(tx_out.extra, tx_out.extra),
        "failed to sort tx extra");

    // Check that we can calculate the pruned hash
    tx_out.pruned = true;
    tx_out.invalidate_hashes();
    cryptonote::get_pruned_transaction_hash(tx_out, crypto::null_hash);
}

static void make_jamtis_rct_transaction_pruned(
    const std::vector<rct::xmr_amount>& inputs,
    const rct::xmr_amount fee,
    std::vector<sp::jamtis::JamtisPaymentProposalV1> normal_payment_proposals,
    const rct::key &rct_spend_pubkey,
    const crypto::secret_key &s_view_balance,
    cryptonote::transaction& tx)
{
    CHECK_AND_ASSERT_THROW_MES(inputs.size(), "no inputs");

    // make input key images and sum input amounts
    std::vector<crypto::key_image> key_images;
    rct::xmr_amount in_amount{0};
    for (const auto &i : inputs)
    {
        in_amount += i;
        key_images.push_back(rct::rct2ki(rct::pkGen()));
    }

    // sort ins by their key image
    std::sort(key_images.begin(), key_images.end());

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

    // input context
    rct::key input_context;
    sp::jamtis::make_jamtis_input_context_standard(key_images, {}, input_context);

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

    instantiate_jamtis_tx(key_images,
        sp_enotes,
        output_enote_ephemeral_pubkeys,
        sp::get_shared_num_primary_view_tag_bits({}, {}, {}, output_proposals),
        sp::jamtis::gen_payment_id(),
        tx);
}

static void finalize_payment_proposal_set(const rct::xmr_amount in_amount,
    const rct::xmr_amount fee,
    std::vector<sp::jamtis::CarrotPaymentProposalV1> &payment_proposals_inout,
    std::vector<sp::jamtis::CarrotPaymentProposalSelfSendV1> &selfsend_proposals_inout)
{
    // @TODO: handle proposal amount overflow

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

static std::optional<sp::jamtis::encrypted_payment_id_t> get_shared_pid_enc(
    const std::vector<sp::SpOutputProposalV1> &output_proposals)
{
    std::optional<sp::jamtis::encrypted_payment_id_t> res;
    for (const sp::SpOutputProposalV1 &output_proposal : output_proposals)
    {
        if (output_proposal.payment_id_enc)
        {
            CHECK_AND_ASSERT_THROW_MES(!res, "only one encrypted payment ID is allowed per transaction");
            res = output_proposal.payment_id_enc;
        }
    }
    return res;
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
    CHECK_AND_ASSERT_THROW_MES(inputs.size(), "no inputs");

    // make input key images and sum input amounts
    std::vector<crypto::key_image> key_images;
    rct::xmr_amount in_amount{0};
    for (const auto &i : inputs)
    {
        in_amount += i;
        key_images.push_back(rct::rct2ki(rct::pkGen()));
    }

    // sort ins by their key image
    std::sort(key_images.begin(), key_images.end());

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
    sp::jamtis::make_jamtis_input_context_standard(key_images, {}, input_context);

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

    instantiate_jamtis_tx(key_images,
        sp_enotes,
        output_enote_ephemeral_pubkeys,
        DUMMY_NPBITS,
        get_shared_pid_enc(output_proposals),
        tx);
}

static bool try_parse_jamtis_from_tx(const cryptonote::transaction &tx,
    std::vector<sp::SpEnoteV1> &enotes_out,
    std::vector<crypto::x25519_pubkey> &enote_ephemeral_pubkeys_out,
    std::optional<sp::jamtis::encrypted_payment_id_t> &payment_id_enc_out,
    std::uint8_t &num_primary_view_tag_bits_out)
{
    enotes_out.clear();
    enote_ephemeral_pubkeys_out.clear();
    payment_id_enc_out = std::nullopt;
    num_primary_view_tag_bits_out = 0;

    const size_t nouts{tx.vout.size()};

    if (tx.version != 2)
        return false;
    else if (nouts < 2)
        return false;
    else if (tx.rct_signatures.type < rct::RCTTypeCLSAG)
        return false;
    else if (tx.rct_signatures.outPk.size() != nouts)
        return false;
    else if (tx.rct_signatures.ecdhInfo.size() != nouts)
        return false;

    // assert all txouts are RingCT to_key outputs
    for (const auto &o : tx.vout)
        if (o.target.type() != typeid(cryptonote::txout_to_key) || o.amount)
            return false;

    // parse tx_extra
    std::vector<cryptonote::tx_extra_field> tx_extra_fields;
    if (!cryptonote::parse_tx_extra(tx.extra, tx_extra_fields))
        return false;

    // extra Jamtis info from extra
    cryptonote::tx_extra_jamtis_v1 jamtis_extra;
    if (!cryptonote::find_tx_extra_field_by_type(tx_extra_fields, jamtis_extra))
        return false;
    else if (jamtis_extra.output_info.size() != nouts)
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
        // @TODO: boost:get throws
        const cryptonote::txout_to_key &keytarg{boost::get<cryptonote::txout_to_key>(tx.vout[i].target)};

        sp::SpEnoteV1 &enote_out = tools::add_element(enotes_out);

        enote_out.core = sp::SpEnoteCore{
            .onetime_address = rct::pk2rct(keytarg.key),
            .amount_commitment = tx.rct_signatures.outPk[i].mask
        };

        memcpy(enote_out.addr_tag_enc.bytes, jamtis_extra.output_info[i].addr_tag_enc, sp::jamtis::ADDRESS_INDEX_BYTES);
        memcpy(enote_out.encrypted_amount.bytes, tx.rct_signatures.ecdhInfo[i].amount.bytes, sp::jamtis::ENCRYPTED_AMOUNT_BYTES);
        memcpy(enote_out.view_tag.bytes, jamtis_extra.output_info[i].view_tag, sp::jamtis::VIEW_TAG_BYTES);
    }

    enote_ephemeral_pubkeys_out = std::move(jamtis_extra.enote_ephemeral_pubkeys);
    num_primary_view_tag_bits_out = jamtis_extra.num_primary_view_tag_bits;

    tx_extra_nonce nonce_field;
    if (cryptonote::find_tx_extra_field_by_type(tx_extra_fields, nonce_field))
    {
        crypto::hash8 pid_hash8;
        if (cryptonote::get_encrypted_payment_id_from_tx_extra_nonce(nonce_field.nonce, pid_hash8))
        {
            sp::jamtis::encrypted_payment_id_t payment_id_enc;
            memcpy(payment_id_enc.bytes, pid_hash8.data, sp::jamtis::PAYMENT_ID_BYTES);
            payment_id_enc_out = payment_id_enc;
        }
    }

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
    std::optional<sp::jamtis::encrypted_payment_id_t> payment_id_enc;
    std::uint8_t num_primary_view_tag_bits;
    if (!try_parse_jamtis_from_tx(tx, enotes, enote_ephemeral_pubkeys, payment_id_enc, num_primary_view_tag_bits))
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
    const crypto::public_key &primary_address_spend_pubkey,
    std::vector<sp::CarrotIntermediateEnoteRecordV1> &enote_records_out)
{
    enote_records_out.clear();

    std::vector<sp::SpEnoteV1> enotes;
    std::vector<crypto::x25519_pubkey> enote_ephemeral_pubkeys;
    std::optional<sp::jamtis::encrypted_payment_id_t> payment_id_enc;
    std::uint8_t num_primary_view_tag_bits;
    if (!try_parse_jamtis_from_tx(tx, enotes, enote_ephemeral_pubkeys, payment_id_enc, num_primary_view_tag_bits))
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
                payment_id_enc,
                input_context,
                k_view,
                primary_address_spend_pubkey,
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

TEST(jamtis_rct, pruned_tx_enote_record_pid_carrot)
{
    // make jamtis keys
    cryptonote::account_base account;
    account.generate();

    const sp::jamtis::payment_id_t payment_id{sp::jamtis::gen_payment_id()};

    // make payment proposal
    const sp::jamtis::CarrotPaymentProposalV1 payment_proposal{
            .destination = account.get_keys().m_account_address,
            .is_subaddress = false,
            .payment_id = payment_id,
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
    EXPECT_EQ(payment_id, plain_enote_record.payment_id);

    // make secret change spend pubkey
    crypto::public_key secret_change_spend_pubkey;
    sp::jamtis::make_carrot_secret_change_spend_pubkey(account.get_keys().m_account_address.m_spend_public_key,
        account.get_keys().m_view_secret_key,
        secret_change_spend_pubkey);

    // assert values of change record
    const sp::CarrotIntermediateEnoteRecordV1 &change_enote_record{first_is_plain ? enote_records[1] : enote_records[0]};
    rct::xmr_amount in_amount{0};
    for (const auto &i : input_amounts) in_amount += i;
    const rct::xmr_amount expected_change{in_amount - payment_proposal.amount - fee};
    ASSERT_NE(payment_proposal.amount, expected_change); // makes testing ambiguous
    EXPECT_EQ(secret_change_spend_pubkey, change_enote_record.nominal_address_spend_pubkey);
    EXPECT_EQ(expected_change, change_enote_record.amount);
    EXPECT_EQ(sp::jamtis::null_payment_id, change_enote_record.payment_id);
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

TEST(jamtis_rct, janus_attack_stupid)
{
    // make jamtis keys
    cryptonote::account_base account;
    account.generate();
    hw::device &hwdev{hw::get_device("default")};

    // make subaddresses
    const cryptonote::account_public_address subaddress_1{
            hwdev.get_subaddress(account.get_keys(), cryptonote::subaddress_index{0, 1})
        };
    const cryptonote::account_public_address subaddress_2{
            hwdev.get_subaddress(account.get_keys(), cryptonote::subaddress_index{0, 2})
        };

    // test case core
    const auto construct_enote_and_scan = [&account, &subaddress_1, &subaddress_2](
        const cryptonote::account_public_address &dest,
        const bool treat_as_subaddr
    ) -> bool {
        // 1. payment proposal
        const sp::jamtis::CarrotPaymentProposalV1 payment_proposal{
                .destination = dest,
                .is_subaddress = treat_as_subaddr,
                .payment_id = sp::jamtis::null_payment_id,
                .amount = 69,
                .randomness = sp::jamtis::gen_address_tag(),
                .partial_memo = {}
            };
        // 2. output proposal
        const rct::key input_context{};
        sp::SpOutputProposalV1 output_proposal;
        sp::make_v1_output_proposal_v1(payment_proposal,
            DUMMY_NPBITS,
            input_context,
            output_proposal);
        // 3. enote
        sp::SpEnoteV1 enote;
        get_enote_v1(output_proposal, enote);
        // 4. scan enote and return false on scan failure
        sp::CarrotIntermediateEnoteRecordV1 enote_record;
        if (!sp::try_get_carrot_intermediate_enote_record_v1(enote,
                output_proposal.enote_ephemeral_pubkey,
                std::nullopt,
                input_context,
                account.get_keys().m_view_secret_key,
                account.get_keys().m_account_address.m_spend_public_key,
                enote_record))
            return false;
        // 5. check to see if nominal address spend pubkey is one already generated
        //    (this is basically a subaddress table lookup)
        return enote_record.nominal_address_spend_pubkey == account.get_keys().m_account_address.m_spend_public_key
            || enote_record.nominal_address_spend_pubkey == subaddress_1.m_spend_public_key
            || enote_record.nominal_address_spend_pubkey == subaddress_2.m_spend_public_key;
    };

    // control group test case instances
    EXPECT_TRUE(construct_enote_and_scan(account.get_keys().m_account_address, false)); // main address with normal D_e
    EXPECT_TRUE(construct_enote_and_scan(subaddress_1, true)); // subaddress 1 address with normal D_e
    EXPECT_TRUE(construct_enote_and_scan(subaddress_2, true)); // subaddress 2 address with normal D_e
    EXPECT_FALSE(construct_enote_and_scan(account.get_keys().m_account_address, true)); // main address with funky D_e
    EXPECT_FALSE(construct_enote_and_scan(subaddress_1, false)); // subaddress 1 address with funky D_e
    EXPECT_FALSE(construct_enote_and_scan(subaddress_2, false)); // subaddress 2 address with funky D_e

    // mix all addresses together
    const std::vector<crypto::public_key> spendpubs{
        account.get_keys().m_account_address.m_spend_public_key,
        subaddress_1.m_spend_public_key,
        subaddress_2.m_spend_public_key,
    };
    const std::vector<crypto::public_key> viewpubs{
        account.get_keys().m_account_address.m_view_public_key,
        subaddress_1.m_view_public_key,
        subaddress_2.m_view_public_key,
    };
    std::vector<cryptonote::account_public_address> mixed_addresses;
    for (int i = 0; i < spendpubs.size(); ++i)
    {
        for (int j = 0; j < viewpubs.size(); ++j)
        {
            if (i == j) continue; // skip correct addresses
            mixed_addresses.push_back({spendpubs[i], viewpubs[j]});
        }
    }

    // run Janus tests on mixed addresses
    for (const cryptonote::account_public_address &mixed_address : mixed_addresses)
    {
        EXPECT_FALSE(construct_enote_and_scan(mixed_address, true)); // mixed janus address with subaddress D_e
        EXPECT_FALSE(construct_enote_and_scan(mixed_address, false)); // mixed janus address with main D_e
    }
}

static void get_output_proposal_janus(const sp::jamtis::CarrotPaymentProposalV1 &proposal,
    const rct::key &input_context,
    const crypto::public_key &second_address_spend_pubkey,
    sp::SpOutputProposalCore &output_proposal_core_out,
    crypto::x25519_pubkey &enote_ephemeral_pubkey_out,
    sp::jamtis::encrypted_amount_t &encrypted_amount_out,
    sp::jamtis::encrypted_address_tag_t &addr_tag_enc_out,
    sp::jamtis::view_tag_t &view_tag_out,
    sp::TxExtra &partial_memo_out)
{
    // 1. sanity checks
    CHECK_AND_ASSERT_THROW_MES(proposal.randomness != sp::jamtis::carrot_randomness_t{},
        "jamtis payment proposal: invalid enote ephemeral privkey randomness (zero).");

    // 2. enote ephemeral privkey
    crypto::secret_key enote_ephemeral_privkey;
    sp::jamtis::make_carrot_enote_ephemeral_privkey(proposal.randomness,
        proposal.amount,
        proposal.destination.m_spend_public_key,
        proposal.destination.m_view_public_key,
        proposal.payment_id,
        enote_ephemeral_privkey);

    // 3. enote ephemeral pubkey
    sp::jamtis::make_carrot_enote_ephemeral_pubkey(enote_ephemeral_privkey,
        proposal.destination.m_spend_public_key,
        proposal.is_subaddress,
        enote_ephemeral_pubkey_out);

    // 4. enote ephemeral pubkey
    crypto::public_key x_all{rct::rct2pk(
            rct::scalarmult8(rct::scalarmultKey(rct::pk2rct(proposal.destination.m_view_public_key),
                rct::sk2rct(enote_ephemeral_privkey)))
        )};
    sp::normalize_x(x_all);

    // 5. sender receiver secret
    rct::key sender_receiver_secret;
    sp::jamtis::make_jamtis_sender_receiver_secret(to_bytes(x_all),
        to_bytes(x_all),
        to_bytes(x_all),
        enote_ephemeral_pubkey_out,
        input_context,
        sender_receiver_secret);

    // 6. amount blinding factor: y = Hn(q, enote_type)
    sp::jamtis::make_jamtis_amount_blinding_factor(sender_receiver_secret,
        sp::jamtis::JamtisEnoteType::PLAIN,
        output_proposal_core_out.amount_blinding_factor);

    // 7. ATTACK: make onetime address by adding different address spend pubkey
    sp::jamtis::make_jamtis_onetime_address_rct(rct::pk2rct(second_address_spend_pubkey),
        sender_receiver_secret,
        rct::commit(proposal.amount, rct::sk2rct(output_proposal_core_out.amount_blinding_factor)),
        output_proposal_core_out.onetime_address);

    // 8. make encrypted address tag
    addr_tag_enc_out = encrypt_jamtis_address_tag(proposal.randomness,
        to_bytes(x_all),
        to_bytes(x_all),
        output_proposal_core_out.onetime_address);

    // 9. view tag
    sp::jamtis::make_jamtis_view_tag(to_bytes(x_all),
        to_bytes(x_all),
        output_proposal_core_out.onetime_address,
        /*num_primary_view_tag_bits=*/0,
        view_tag_out);

    // 10. make encrypted amount
    encrypted_amount_out = sp::jamtis::encrypt_jamtis_amount(proposal.amount,
        sender_receiver_secret,
        output_proposal_core_out.onetime_address);

    // 11. save the amount and partial memo
    output_proposal_core_out.amount = proposal.amount;
    partial_memo_out                = proposal.partial_memo;
}

TEST(jamtis_rct, janus_attack_actual)
{
    // make jamtis keys
    cryptonote::account_base account;
    account.generate();
    hw::device &hwdev{hw::get_device("default")};

    const cryptonote::account_public_address primary_address{account.get_keys().m_account_address};

    // make subaddresses
    const cryptonote::account_public_address subaddress_1{
            hwdev.get_subaddress(account.get_keys(), cryptonote::subaddress_index{0, 1})
        };
    const cryptonote::account_public_address subaddress_2{
            hwdev.get_subaddress(account.get_keys(), cryptonote::subaddress_index{0, 2})
        };

    // test case core
    const auto construct_enote_and_scan = [&account, &subaddress_1, &subaddress_2](
        const cryptonote::account_public_address &dest_one,
        const crypto::public_key &second_address_spend_pubkey
    ) -> bool {
        // 1. payment proposal
        const bool treat_as_subaddress{
                dest_one.m_view_public_key != account.get_keys().m_account_address.m_view_public_key
            };
        const sp::jamtis::CarrotPaymentProposalV1 payment_proposal{
                .destination = dest_one,
                .is_subaddress = treat_as_subaddress,
                .payment_id = sp::jamtis::null_payment_id,
                .amount = 69,
                .randomness = sp::jamtis::gen_address_tag(),
                .partial_memo = {}
            };
        // 2. output proposal
        const rct::key input_context{};
        sp::SpOutputProposalV1 output_proposal;
        get_output_proposal_janus(payment_proposal,
            input_context,
            second_address_spend_pubkey,
            output_proposal.core,
            output_proposal.enote_ephemeral_pubkey,
            output_proposal.encrypted_amount,
            output_proposal.addr_tag_enc,
            output_proposal.view_tag,
            output_proposal.partial_memo);
        output_proposal.num_primary_view_tag_bits = DUMMY_NPBITS;
        // 3. enote
        sp::SpEnoteV1 enote;
        get_enote_v1(output_proposal, enote);
        // 4. scan enote and return false on scan failure
        sp::CarrotIntermediateEnoteRecordV1 enote_record;
        if (!sp::try_get_carrot_intermediate_enote_record_v1(enote,
                output_proposal.enote_ephemeral_pubkey,
                std::nullopt,
                input_context,
                account.get_keys().m_view_secret_key,
                account.get_keys().m_account_address.m_spend_public_key,
                enote_record))
            return false;
        // 5. check to see if nominal address spend pubkey is one already generated
        //    (this is basically a subaddress table lookup)
        return enote_record.nominal_address_spend_pubkey == account.get_keys().m_account_address.m_spend_public_key
            || enote_record.nominal_address_spend_pubkey == subaddress_1.m_spend_public_key
            || enote_record.nominal_address_spend_pubkey == subaddress_2.m_spend_public_key;
    };

    // control group test case instances
    EXPECT_TRUE(construct_enote_and_scan(primary_address, primary_address.m_spend_public_key));
    EXPECT_TRUE(construct_enote_and_scan(subaddress_1, subaddress_1.m_spend_public_key));
    EXPECT_TRUE(construct_enote_and_scan(subaddress_2, subaddress_2.m_spend_public_key));

    // list of addresses
    const std::vector<cryptonote::account_public_address> addresses{
        primary_address,
        subaddress_1,
        subaddress_2,
    };

    // run Janus tests on combinations of different addresses
    for (int i = 0; i < addresses.size(); ++i)
    {
        for (int j = 0; j < addresses.size(); ++j)
        {
            // NOTE TO READER: use a debugger to check that the enote scanning is failing on verify_carrot_janus_protection()
            if (i == j) continue;
            EXPECT_FALSE(construct_enote_and_scan(addresses[i], addresses[j].m_spend_public_key));
        }
    }
}

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
#include "scan_balance_recovery_utils.h"

//local headers
#include "contextual_enote_record_types.h"
#include "contextual_enote_record_utils.h"
#include "crypto/crypto.h"
#include "crypto/x25519.h"
#include "cryptonote_basic/subaddress_index.h"
#include "device/device.hpp"
#include "enote_record_types.h"
#include "enote_record_utils.h"
#include "enote_record_utils_legacy.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "seraphis_core/jamtis_account_secrets.h"
#include "seraphis_core/jamtis_enote_utils.h"
#include "seraphis_core/legacy_core_utils.h"
#include "seraphis_core/legacy_enote_types.h"
#include "seraphis_core/legacy_enote_utils.h"
#include "seraphis_core/tx_extra.h"
#include "seraphis_crypto/sp_crypto_utils.h"
#include "tx_component_types.h"

//third party headers

//standard headers
#include <algorithm>
#include <functional>
#include <list>
#include <unordered_map>
#include <unordered_set>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis"

namespace sp
{
namespace scanning
{
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static bool try_view_scan_legacy_enote_v1(const rct::key &legacy_base_spend_pubkey,
    const std::unordered_map<rct::key, cryptonote::subaddress_index> &legacy_subaddress_map,
    const std::uint64_t block_index,
    const std::uint64_t block_timestamp,
    const rct::key &transaction_id,
    const sp::legacy_output_index_t &legacy_ledger_enote_index,
    const std::uint64_t enote_tx_index,
    const std::uint64_t unlock_time,
    const TxExtra &tx_memo,
    const LegacyEnoteVariant &legacy_enote,
    const crypto::public_key &legacy_enote_ephemeral_pubkey,
    const crypto::key_derivation &DH_derivation,
    const SpEnoteOriginStatus origin_status,
    hw::device &hwdev,
    LegacyContextualBasicEnoteRecordV1 &contextual_record_out)
{
    // 1. view scan the enote (in try block in case the enote is malformed)
    try
    {
        if (!try_get_legacy_basic_enote_record(legacy_enote,
                rct::pk2rct(legacy_enote_ephemeral_pubkey),
                enote_tx_index,
                unlock_time,
                DH_derivation,
                legacy_base_spend_pubkey,
                legacy_subaddress_map,
                hwdev,
                contextual_record_out.record))
            return false;
    } catch (...) { return false; }

    // 2. set the origin context
    contextual_record_out.origin_context =
        LegacyEnoteOriginContext{
                .block_index               = block_index,
                .block_timestamp           = block_timestamp,
                .transaction_id            = transaction_id,
                .enote_tx_index            = enote_tx_index,
                .legacy_enote_ledger_index = legacy_ledger_enote_index,
                .origin_status             = origin_status,
                .memo                      = tx_memo
            };

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void update_with_new_intermediate_record_legacy(const LegacyIntermediateEnoteRecord &new_enote_record,
    const LegacyEnoteOriginContext &new_record_origin_context,
    std::unordered_map<rct::key, LegacyContextualIntermediateEnoteRecordV1> &found_enote_records_inout)
{
    // 1. add new intermediate legacy record to found enotes (or refresh if already there)
    rct::key new_record_identifier;
    get_legacy_enote_identifier(onetime_address_ref(new_enote_record.enote),
        new_enote_record.amount,
        new_record_identifier);

    found_enote_records_inout[new_record_identifier].record = new_enote_record;

    // 2. update the record's origin context
    try_update_enote_origin_context_v1(new_record_origin_context,
        found_enote_records_inout[new_record_identifier].origin_context);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void update_with_new_record_legacy(const LegacyEnoteRecord &new_enote_record,
    const LegacyEnoteOriginContext &new_record_origin_context,
    const std::list<SpContextualKeyImageSetV1> &chunk_contextual_key_images,
    std::unordered_map<rct::key, LegacyContextualEnoteRecordV1> &found_enote_records_inout,
    std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> &found_spent_key_images_inout)
{
    // 1. add new legacy record to found enotes (or refresh if already there)
    rct::key new_record_identifier;
    get_legacy_enote_identifier(onetime_address_ref(new_enote_record.enote),
        new_enote_record.amount,
        new_record_identifier);

    found_enote_records_inout[new_record_identifier].record = new_enote_record;

    // 2. if the enote is spent in this chunk, update its spent context
    const crypto::key_image &new_record_key_image{new_enote_record.key_image};
    SpEnoteSpentContextV1 spent_context_update{};

    auto contextual_key_images_of_record_spent_in_this_chunk =
        std::find_if(
            chunk_contextual_key_images.begin(),
            chunk_contextual_key_images.end(),
            [&new_record_key_image](const SpContextualKeyImageSetV1 &contextual_key_image_set) -> bool
            {
                return has_key_image(contextual_key_image_set, new_record_key_image);
            }
        );

    if (contextual_key_images_of_record_spent_in_this_chunk != chunk_contextual_key_images.end())
    {
        // a. record that the enote is spent in this chunk
        found_spent_key_images_inout[new_record_key_image];

        // b. update its spent context (update instead of assignment in case of duplicates)
        try_update_enote_spent_context_v1(
            contextual_key_images_of_record_spent_in_this_chunk->spent_context,
            found_spent_key_images_inout[new_record_key_image]);

        // c. save the record's current spent context
        spent_context_update = found_spent_key_images_inout[new_record_key_image];
    }

    // 3. update the record's contexts
    // note: multiple legacy enotes can have the same key image but different amounts; only one of those can be spent,
    //       so we should expect all of them to end up referencing the same spent context
    update_contextual_enote_record_contexts_v1(new_record_origin_context,
        spent_context_update,
        found_enote_records_inout[new_record_identifier].origin_context,
        found_enote_records_inout[new_record_identifier].spent_context);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void update_with_new_intermediate_record_sp(const SpIntermediateEnoteRecordV1 &new_enote_record,
    const SpEnoteOriginContextV1 &new_record_origin_context,
    std::unordered_map<rct::key, SpContextualIntermediateEnoteRecordV1> &found_enote_records_inout)
{
    // 1. add new seraphis record to found enotes (or refresh if already there)
    const rct::key &new_record_onetime_address{onetime_address_ref(new_enote_record.enote)};

    found_enote_records_inout[new_record_onetime_address].record = new_enote_record;

    // 2. update the record's origin context
    try_update_enote_origin_context_v1(new_record_origin_context,
        found_enote_records_inout[new_record_onetime_address].origin_context);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static rct::key& key_by_index_ref(rct::key_keyV_variant &variant, size_t index)
{
    struct visitor final : public tools::variant_static_visitor<rct::key&>
    {
        visitor(size_t index) : id{index} {}
        size_t id;

        using variant_static_visitor::operator();  //for blank overload
        rct::key& operator()(rct::key &key_variant) const
        {
            CHECK_AND_ASSERT_THROW_MES(id == 0, "invalid index for rct::key.");
            return key_variant;
        }
        rct::key& operator()(rct::keyV &key_variant) const
        {
            CHECK_AND_ASSERT_THROW_MES(id < key_variant.size(), "index greater than vector size.");
            return key_variant[id];
        }
    };

    return variant.visit(visitor{index});
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
bool try_find_legacy_enotes_in_tx(const rct::key &legacy_base_spend_pubkey,
    const std::unordered_map<rct::key, cryptonote::subaddress_index> &legacy_subaddress_map,
    const crypto::secret_key &legacy_view_privkey,
    const std::uint64_t block_index,
    const std::uint64_t block_timestamp,
    const rct::key &transaction_id,
    const std::vector<legacy_output_index_t> &legacy_output_index_per_enote,
    const std::uint64_t unlock_time,
    const TxExtra &tx_memo,
    const std::vector<LegacyEnoteVariant> &enotes_in_tx,
    const SpEnoteOriginStatus origin_status,
    hw::device &hwdev,
    std::list<ContextualBasicRecordVariant> &basic_records_in_tx_out)
{
    basic_records_in_tx_out.clear();

    if (legacy_output_index_per_enote.size() != enotes_in_tx.size())
        return false;

    // 1. extract enote ephemeral pubkeys from the memo
    rct::key_keyV_variant legacy_main_enote_ephemeral_pubkeys = rct::key{};
    std::vector<crypto::public_key> legacy_additional_enote_ephemeral_pubkeys;

    extract_legacy_enote_ephemeral_pubkeys_from_tx_extra(tx_memo,
        legacy_main_enote_ephemeral_pubkeys,
        legacy_additional_enote_ephemeral_pubkeys);

    // 2. scan each enote in the tx using the 'additional enote ephemeral pubkeys'
    // - this step is automatically skipped if legacy_additional_enote_ephemeral_pubkeys.size() == 0
    crypto::key_derivation temp_DH_derivation;
    LegacyContextualBasicEnoteRecordV1 temp_contextual_record{};
    bool found_an_enote{false};

    for (std::size_t enote_index{0}; enote_index < legacy_additional_enote_ephemeral_pubkeys.size() &&
            enote_index < enotes_in_tx.size();
            ++enote_index)
    {
        // a. compute the DH derivation for this enote ephemeral pubkey
        hwdev.generate_key_derivation(legacy_additional_enote_ephemeral_pubkeys[enote_index],
            legacy_view_privkey,
            temp_DH_derivation);

        // b. try to recover a contextual basic record from the enote
        if (!try_view_scan_legacy_enote_v1(legacy_base_spend_pubkey,
                legacy_subaddress_map,
                block_index,
                block_timestamp,
                transaction_id,
                legacy_output_index_per_enote[enote_index],
                enote_index,
                unlock_time,
                tx_memo,
                enotes_in_tx[enote_index],
                legacy_additional_enote_ephemeral_pubkeys[enote_index],
                temp_DH_derivation,
                origin_status,
                hwdev,
                temp_contextual_record))
            continue;

        // c. save the contextual basic record
        // note: it is possible for enotes with duplicate onetime addresses to be added here; it is assumed the
        //       upstream caller will be able to handle those without problems
        basic_records_in_tx_out.emplace_back(temp_contextual_record);

        // d. record that an owned enote has been found
        found_an_enote = true;
    }

    // 3. check if there is a main enote ephemeral pubkey
    if (legacy_main_enote_ephemeral_pubkeys.is_type<rct::key>() &&
            legacy_main_enote_ephemeral_pubkeys.unwrap<rct::key>() == rct::I)
        return found_an_enote;

    // 4. compute the key derivations for all main enote ephemeral pubkeys
    rct::key_keyV_variant temp_DH_derivations = rct::key{};
    const auto pubkeys = legacy_main_enote_ephemeral_pubkeys.try_unwrap<rct::keyV>();
    if (pubkeys)
    {
        rct::keyV temp{};
        temp.reserve(pubkeys->size());
        for (const rct::key &enote_ephemeral_pubkey : *pubkeys) {
            hwdev.generate_key_derivation(rct::rct2pk(enote_ephemeral_pubkey), legacy_view_privkey, temp_DH_derivation);
            temp.emplace_back((rct::key &) temp_DH_derivation);
        }
        temp_DH_derivations = temp;
    }
    else
    {
        hwdev.generate_key_derivation(rct::rct2pk(legacy_main_enote_ephemeral_pubkeys.unwrap<rct::key>()), legacy_view_privkey, temp_DH_derivation);
        temp_DH_derivations = (rct::key &) temp_DH_derivation;
    }

    // 5. scan all enotes using key derivations for every ephemeral pub key
    for (std::size_t enote_index{0}; enote_index < enotes_in_tx.size(); ++enote_index)
    {
        // all ephemeral pub key - DH_derivation pairs
        for (std::size_t pk_index{0};
                (temp_DH_derivations.is_type<rct::keyV>() && pk_index < temp_DH_derivations.unwrap<rct::keyV>().size()) ||
                (temp_DH_derivations.is_type<rct::key>() && pk_index < 1);
                ++pk_index)
        {
            crypto::public_key temp_legacy_main_enote_ephemeral_pubkey = rct2pk(key_by_index_ref(legacy_main_enote_ephemeral_pubkeys, pk_index));
            temp_DH_derivation = (crypto::key_derivation &) key_by_index_ref(temp_DH_derivations, pk_index);
            // a. try to recover a contextual basic record from the enote
            if (!try_view_scan_legacy_enote_v1(legacy_base_spend_pubkey,
                    legacy_subaddress_map,
                    block_index,
                    block_timestamp,
                    transaction_id,
                    legacy_output_index_per_enote[enote_index],
                    enote_index,
                    unlock_time,
                    tx_memo,
                    enotes_in_tx[enote_index],
                    temp_legacy_main_enote_ephemeral_pubkey,
                    temp_DH_derivation,
                    origin_status,
                    hwdev,
                    temp_contextual_record))
                continue;

            // b. save the contextual basic record
            // note: it is possible for enotes with duplicate onetime addresses to be added here; it is assumed the
            //       upstream caller will be able to handle those without problems
            basic_records_in_tx_out.emplace_back(temp_contextual_record);

            // c. record that an owned enote has been found
            found_an_enote = true;
        }
    }

    return found_an_enote;
}
//-------------------------------------------------------------------------------------------------------------------
std::uint64_t filter_assist_scan_64(const crypto::x25519_secret_key &d_filter_assist,
    const epee::span<const crypto::x25519_pubkey> enote_ephemeral_pubkeys,
    const std::uint8_t num_primary_view_tag_bits,
    const epee::span<const SpEnoteVariant> enotes)
{
    CHECK_AND_ASSERT_THROW_MES(enotes.size() <= 64,
        "filter_assist_scan_64(): cannot scan more than 64 enotes at a time");

    // 1. check if any enotes can be scanned
    if (enote_ephemeral_pubkeys.size() == 0 || enotes.size() == 0
            || num_primary_view_tag_bits > 8 * jamtis::VIEW_TAG_BYTES)
        return false;

    // 2. filter-assist scan each enote in the tx
    crypto::x25519_pubkey temp_DH_derivation;
    std::uint64_t pvt_matched_mask{0};

    for (std::size_t enote_index{0}; enote_index < enotes.size(); ++enote_index)
    {
        // a. get the next Diffie-Hellman derivation
        // - there can be fewer ephemeral pubkeys than enotes; when we get to the end, keep using the last one
        if (enote_index < enote_ephemeral_pubkeys.size())
        {
            crypto::x25519_scmul_key(d_filter_assist,
                enote_ephemeral_pubkeys[enote_index],
                temp_DH_derivation);
        }

        // b. filter-assist scan the enote (in try block in case enote is malformed)
        try
        {
            if (jamtis::test_jamtis_primary_view_tag(temp_DH_derivation.data,
                    onetime_address_ref(enotes[enote_index]),
                    view_tag_ref(enotes[enote_index]),
                    num_primary_view_tag_bits))
                pvt_matched_mask |= (1 << enote_index);
        } catch (...) { continue; }
    }

    return pvt_matched_mask;
}
//-------------------------------------------------------------------------------------------------------------------
bool try_find_sp_enotes_in_tx(const crypto::x25519_secret_key &d_filter_assist,
    const std::uint64_t block_index,
    const std::uint64_t block_timestamp,
    const rct::key &transaction_id,
    const std::uint64_t total_enotes_before_tx,
    const rct::key &input_context,
    const SpTxSupplementV1 &tx_supplement,
    const std::vector<SpEnoteVariant> &enotes_in_tx,
    const SpEnoteOriginStatus origin_status,
    std::list<ContextualBasicRecordVariant> &basic_records_in_tx_out)
{
    basic_records_in_tx_out.clear();

    // 1. filter-assist scan all enotes in tx
    bool one_enote_matched{false};
    std::vector<bool> enote_passed_exclusive_check;
    enote_passed_exclusive_check.reserve(enotes_in_tx.size());
    auto ephemeral_pubkeys_span{epee::to_span(tx_supplement.output_enote_ephemeral_pubkeys)};

    for (size_t enote_index = 0; enote_index < enotes_in_tx.size();)
    {
        // a. calc chunk size
        const size_t scan_chunk_size = std::min<size_t>(enotes_in_tx.size() - enote_index, 64);

        // b. do filter-assist scannning of chunk
        const std::uint64_t pvt_matched_mask = filter_assist_scan_64(d_filter_assist,
            ephemeral_pubkeys_span,
            tx_supplement.num_primary_view_tag_bits,
            {enotes_in_tx.data() + enote_index, scan_chunk_size});
        if (pvt_matched_mask)
        {
            one_enote_matched = true;
            for (size_t i = 0; i < scan_chunk_size; ++i)
                enote_passed_exclusive_check.push_back((pvt_matched_mask >> i) & 1);
        }

        // c. update iterators
        enote_index += scan_chunk_size;
        ephemeral_pubkeys_span.remove_prefix(scan_chunk_size);
    }

    // 2. if no primary view tag matched, return false
    if (!one_enote_matched)
        return false;

    // 3. create basic enote records
    const crypto::x25519_pubkey *pephemeral_pubkey{};
    for (size_t enote_index = 0; enote_index < enotes_in_tx.size(); ++enote_index)
    {
        // a. make enote origin context
        const SpEnoteOriginContextV1 origin_context = SpEnoteOriginContextV1 {
            .block_index = block_index,
            .block_timestamp = block_timestamp,
            .transaction_id = transaction_id,
            .enote_tx_index = enote_index,
            .enote_ledger_index = total_enotes_before_tx + enote_index,
            .origin_status = origin_status,
            .memo = tx_supplement.tx_extra
        };

        // b. set associated enote ephemeral pubkey
        if (enote_index < tx_supplement.output_enote_ephemeral_pubkeys.size())
            pephemeral_pubkey = &tx_supplement.output_enote_ephemeral_pubkeys[enote_index];

        // c. make the record
        const SpBasicEnoteRecordV1 basic_enote_record{
                .enote = enotes_in_tx[enote_index],
                .enote_ephemeral_pubkey = *pephemeral_pubkey,
                .num_primary_view_tag_bits = tx_supplement.num_primary_view_tag_bits,
                .input_context = input_context,
                .primary_vt_matches = enote_passed_exclusive_check[enote_index],
            };

        basic_records_in_tx_out.push_back(SpContextualBasicEnoteRecordV1{
            .record = basic_enote_record,
            .origin_context = origin_context
        });
    }

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
void collect_key_images_from_tx(const std::uint64_t block_index,
    const std::uint64_t block_timestamp,
    const rct::key &transaction_id,
    std::vector<crypto::key_image> legacy_key_images_in_tx,
    std::vector<crypto::key_image> sp_key_images_in_tx,
    const SpEnoteSpentStatus spent_status,
    SpContextualKeyImageSetV1 &contextual_key_images_out)
{
    contextual_key_images_out = SpContextualKeyImageSetV1{
            .legacy_key_images = std::move(legacy_key_images_in_tx),
            .sp_key_images     = std::move(sp_key_images_in_tx),
            .spent_context     =
                SpEnoteSpentContextV1{
                    .block_index     = block_index,
                    .block_timestamp = block_timestamp,
                    .transaction_id  = transaction_id,
                    .spent_status    = spent_status
                }
        };
}
//-------------------------------------------------------------------------------------------------------------------
void process_chunk_intermediate_legacy(const rct::key &legacy_base_spend_pubkey,
    const crypto::secret_key &legacy_view_privkey,
    const std::function<bool(const crypto::key_image&)> &check_key_image_is_known_func,
    const std::unordered_map<rct::key, std::list<ContextualBasicRecordVariant>> &chunk_basic_records_per_tx,
    const std::list<SpContextualKeyImageSetV1> &chunk_contextual_key_images,
    hw::device &hwdev,
    std::unordered_map<rct::key, LegacyContextualIntermediateEnoteRecordV1> &found_enote_records_out,
    std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> &found_spent_key_images_out)
{
    found_enote_records_out.clear();
    found_spent_key_images_out.clear();

    // 1. check if any legacy owned enotes have been spent in this chunk (key image matches)
    auto key_image_handler =
        [&](const SpEnoteSpentContextV1 &spent_context, const crypto::key_image &key_image)
        {
            // ask callback if key image is known (i.e. if the key image is attached to an owned enote acquired before
            //    this chunk)
            if (check_key_image_is_known_func(key_image))
            {
                // a. record the found spent key image
                found_spent_key_images_out[key_image];

                // b. update its spent context (use update instead of assignment in case of duplicates)
                try_update_enote_spent_context_v1(spent_context, found_spent_key_images_out[key_image]);
            }
        };

    for (const SpContextualKeyImageSetV1 &contextual_key_image_set : chunk_contextual_key_images)
    {
        for (const crypto::key_image &key_image : contextual_key_image_set.legacy_key_images)
            key_image_handler(contextual_key_image_set.spent_context, key_image);
    }

    // 2. check for legacy owned enotes in this chunk
    LegacyIntermediateEnoteRecord new_enote_record;

    for (const auto &tx_basic_records : chunk_basic_records_per_tx)
    {
        for (const ContextualBasicRecordVariant &contextual_basic_record : tx_basic_records.second)
        {
            const auto * const legacy_contextual_basic_record{
                    contextual_basic_record.try_unwrap<LegacyContextualBasicEnoteRecordV1>()
                };
            if (legacy_contextual_basic_record == nullptr)
                continue;

            try
            {
                // a. check if we own the enote by attempting to convert it to an intermediate enote record
                if (!try_get_legacy_intermediate_enote_record(
                        legacy_contextual_basic_record->record,
                        legacy_base_spend_pubkey,
                        legacy_view_privkey,
                        hwdev,
                        new_enote_record))
                    continue;

                // b. we found an owned enote, so handle it
                update_with_new_intermediate_record_legacy(new_enote_record,
                    legacy_contextual_basic_record->origin_context,
                    found_enote_records_out);
            } catch (...) {}
        }
    }
}
//-------------------------------------------------------------------------------------------------------------------
void process_chunk_full_legacy(const rct::key &legacy_base_spend_pubkey,
    const crypto::secret_key &legacy_spend_privkey,
    const crypto::secret_key &legacy_view_privkey,
    const std::function<bool(const crypto::key_image&)> &check_key_image_is_known_func,
    const std::unordered_map<rct::key, std::list<ContextualBasicRecordVariant>> &chunk_basic_records_per_tx,
    const std::list<SpContextualKeyImageSetV1> &chunk_contextual_key_images,
    hw::device &hwdev,
    std::unordered_map<rct::key, LegacyContextualEnoteRecordV1> &found_enote_records_out,
    std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> &found_spent_key_images_out)
{
    found_enote_records_out.clear();
    found_spent_key_images_out.clear();

    // 1. check if any legacy owned enotes acquired before this chunk were spent in this chunk (key image matches)
    auto key_image_handler =
        [&](const SpEnoteSpentContextV1 &spent_context, const crypto::key_image &key_image)
        {
            // a. ask callback if key image is known (i.e. if the key image is attached to an owned enote acquired before
            //    this chunk)
            if (check_key_image_is_known_func(key_image))
            {
                // i. record the found spent key image
                found_spent_key_images_out[key_image];

                // ii. update its spent context (use update instead of assignment in case of duplicates)
                try_update_enote_spent_context_v1(spent_context, found_spent_key_images_out[key_image]);
            }
        };

    for (const SpContextualKeyImageSetV1 &contextual_key_image_set : chunk_contextual_key_images)
    {
        for (const crypto::key_image &key_image : contextual_key_image_set.legacy_key_images)
            key_image_handler(contextual_key_image_set.spent_context, key_image);
    }

    // 2. check for legacy owned enotes in this chunk
    LegacyEnoteRecord new_enote_record;

    for (const auto &tx_basic_records : chunk_basic_records_per_tx)
    {
        for (const ContextualBasicRecordVariant &contextual_basic_record : tx_basic_records.second)
        {
            const auto * const legacy_contextual_basic_record{
                    contextual_basic_record.try_unwrap<LegacyContextualBasicEnoteRecordV1>()
                };
            if (legacy_contextual_basic_record == nullptr)
                continue;

            try
            {
                // a. check if we own the enote by attempting to convert it to a full enote record
                if (!try_get_legacy_enote_record(
                        legacy_contextual_basic_record->record,
                        legacy_base_spend_pubkey,
                        legacy_spend_privkey,
                        legacy_view_privkey,
                        hwdev,
                        new_enote_record))
                    continue;

                // b. we found an owned enote, so handle it
                update_with_new_record_legacy(new_enote_record,
                    legacy_contextual_basic_record->origin_context,
                    chunk_contextual_key_images,
                    found_enote_records_out,
                    found_spent_key_images_out);
            } catch (...) {}
        }
    }
}
//-------------------------------------------------------------------------------------------------------------------
void process_chunk_intermediate_sp(const rct::key &jamtis_spend_pubkey,
    const crypto::x25519_secret_key &d_unlock_received,
    const crypto::x25519_secret_key &d_identify_received,
    const crypto::x25519_secret_key &d_filter_assist,
    const crypto::secret_key &s_generate_address,
    const jamtis::jamtis_address_tag_cipher_context &cipher_context,
    const std::unordered_map<rct::key, std::list<ContextualBasicRecordVariant>> &chunk_basic_records_per_tx,
    std::unordered_map<rct::key, SpContextualIntermediateEnoteRecordV1> &found_enote_records_out)
{
    found_enote_records_out.clear();

    // check for owned enotes in this chunk (non-self-send intermediate scanning pass)
    SpIntermediateEnoteRecordV1 new_enote_record;

    for (const auto &tx_basic_records : chunk_basic_records_per_tx)
    {
        for (const ContextualBasicRecordVariant &contextual_basic_record : tx_basic_records.second)
        {
            const auto * const sp_contextual_basic_record{
                    contextual_basic_record.try_unwrap<SpContextualBasicEnoteRecordV1>()
                };
            if (sp_contextual_basic_record == nullptr)
                continue;

            try
            {
                // a. check if we own the enote by attempting to convert it to an intermediate enote record
                if (!try_get_intermediate_enote_record_v1(
                        sp_contextual_basic_record->record,
                        jamtis_spend_pubkey,
                        d_unlock_received,
                        d_identify_received,
                        d_filter_assist,
                        s_generate_address,
                        cipher_context,
                        new_enote_record))
                    continue;

                // b. we found an owned enote, so handle it
                update_with_new_intermediate_record_sp(new_enote_record,
                    sp_contextual_basic_record->origin_context,
                    found_enote_records_out);
            } catch (...) {}
        }
    }
}
//-------------------------------------------------------------------------------------------------------------------
void process_chunk_full_sp(const rct::key &jamtis_spend_pubkey,
    const crypto::secret_key &s_view_balance,
    const crypto::secret_key &k_generate_image,
    const crypto::x25519_secret_key &d_unlock_received,
    const crypto::x25519_secret_key &d_identify_received,
    const crypto::x25519_secret_key &d_filter_assist,
    const crypto::secret_key &s_generate_address,
    const jamtis::jamtis_address_tag_cipher_context &cipher_context,
    const std::unordered_map<rct::key, std::list<ContextualBasicRecordVariant>> &chunk_basic_records_per_tx,
    const std::list<SpContextualKeyImageSetV1> &chunk_contextual_key_images,
    std::unordered_map<crypto::key_image, SpContextualEnoteRecordV1> &found_enote_records_out,
    std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> &sp_key_images_in_sp_selfsends_out,
    std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> &legacy_key_images_in_sp_selfsends_out)
{
    found_enote_records_out.clear();
    sp_key_images_in_sp_selfsends_out.clear();
    legacy_key_images_in_sp_selfsends_out.clear();

    // this lambda adds an enote record to found_enote_records_out, updating existing origin
    // contexts if applicable
    const auto add_contextual_enote_record = [&found_enote_records_out]
        (const SpEnoteRecordV1 &new_enote_record, const SpEnoteOriginContextV1 &origin_context)
    {
        const auto record_it = found_enote_records_out.find(new_enote_record.key_image);
        if (record_it == found_enote_records_out.end())
        {
            // if no other existing enote with key image, simply insert
            found_enote_records_out.emplace(new_enote_record.key_image,
                SpContextualEnoteRecordV1 {
                    .record = new_enote_record,
                    .origin_context = origin_context,
                    .spent_context = {} // handled later
                });
        }
        else
        {
            // if another record with the same key image exists, try updating origin ctx
            try_update_enote_origin_context_v1(origin_context, record_it->second.origin_context);
        }
    };

    // 1. build a map of txid -> contextual key image set
    std::unordered_map<rct::key, const SpContextualKeyImageSetV1*> key_image_sets_by_txid;
    for (const auto &key_image_set : chunk_contextual_key_images)
        key_image_sets_by_txid.emplace(key_image_set.spent_context.transaction_id, &key_image_set);

    // 2. go thru all basic and auxiliary records in this chunk and try converting to full records.
    //    if any record within a certain transaction is a self send record, then add its key images
    //    to the output.
    for (const auto &tx_basic_records : chunk_basic_records_per_tx)
    {
        try
        {
            bool found_self_send_in_tx = false;

            // a. for all basic enote records...
            for (const auto &contextual_basic_record : tx_basic_records.second)
            {
                const auto * const sp_contextual_basic_record{
                    contextual_basic_record.try_unwrap<SpContextualBasicEnoteRecordV1>()
                };
                if (sp_contextual_basic_record == nullptr)
                    continue;

                // i. check if we own the enote by attempting to convert it to a full enote record
                SpEnoteRecordV1 new_enote_record;
                if (!try_get_enote_record_v1(
                            sp_contextual_basic_record->record,
                            jamtis_spend_pubkey,
                            s_view_balance,
                            k_generate_image,
                            d_unlock_received,
                            d_identify_received,
                            d_filter_assist,
                            s_generate_address,
                            cipher_context,
                            new_enote_record))
                    continue;

                // ii. we found an owned enote. update found contexualized enote record set
                add_contextual_enote_record(new_enote_record, sp_contextual_basic_record->origin_context);

                // iii. if new enote record is a self-send, flag this transaction as containing a self send
                jamtis::JamtisSelfSendType dummy_type;
                if (jamtis::try_get_jamtis_self_send_type(new_enote_record.type, dummy_type))
                    found_self_send_in_tx = true;
            }

            // c. if we found at least one self send enote in this transaction, then add the
            //    seraphis and legacy key images to the output
            if (found_self_send_in_tx)
            {
                const auto &key_image_set = *key_image_sets_by_txid.at(tx_basic_records.first);

                for (const auto &sp_key_image : key_image_set.sp_key_images)
                    sp_key_images_in_sp_selfsends_out.emplace(sp_key_image,
                        key_image_set.spent_context);

                for (const auto &legacy_key_image : key_image_set.legacy_key_images)
                    legacy_key_images_in_sp_selfsends_out.emplace(legacy_key_image,
                        key_image_set.spent_context);
            }
        }
        catch (...) {}
    }

    // 1. go thru every key image in transactions with seraphis self sends and update the spent
    //    context of new enotes scanned in this chunk
    for (const auto &sp_key_image_in_sp_selfsend_info : sp_key_images_in_sp_selfsends_out)
    {
        const auto &sp_key_image_in_sp_selfsend = sp_key_image_in_sp_selfsend_info.first;
        const auto &sp_selfsend_context = sp_key_image_in_sp_selfsend_info.second;

        const auto record_with_image_it = found_enote_records_out.find(sp_key_image_in_sp_selfsend);
        if (record_with_image_it != found_enote_records_out.end())
            try_update_enote_spent_context_v1(sp_selfsend_context,
                record_with_image_it->second.spent_context);
    }
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace scanning
} //namespace sp

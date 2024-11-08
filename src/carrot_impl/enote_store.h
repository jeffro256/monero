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

// Enote store that supports full-featured balance recovery by managing enote-related caches.

#pragma once

//local headers
#include "checkpoint_cache.h"
#include "expect.h"
#include "enote_store_event_types.h"
#include "seraphis_main/contextual_enote_record_types.h"

//third party headers

//standard headers
#include <optional>

//forward declarations


namespace sp
{


struct CarrotBaseDBInterface
{
    virtual expect<void> sync() = 0;

    virtual ~CarrotBaseDBInterface() = default;
};

struct CarrotEnoteDBInterface: CarrotBaseDBInterface
{
    virtual expect<bool> update_enote_record(
        const MinimalIntermediateEnoteRecordVariant &enote_record,
        const LegacyEnoteOriginContext &origin_context) = 0;

    virtual expect<size_t> remove_records_with_txid(const crypto::hash &txid) = 0;
    virtual expect<size_t> remove_non_ledger_records() = 0;
    virtual expect<size_t> remove_ledger_records_before(const uint64_t block_index) = 0;
    virtual expect<size_t> clear() = 0;

    virtual expect<void> get_all_record_identifiers(std::vector<crypto::hash> &record_identifiers_out) const = 0;

    virtual expect<void> get_record(const crypto::hash &record_identifier,
        MinimalIntermediateEnoteRecordVariant &enote_record_out,
        LegacyEnoteOriginContext &origin_context_out) const = 0;

    virtual expect<bool> has_enote_at_global_index(const legacy_output_index_t &output_index) const = 0;
};

class CarrotEnoteRamDB: public CarrotEnoteDBInterface
{
public:
///CarrotEnoteDBInterface
    expect<bool> update_enote_record(
        const MinimalIntermediateEnoteRecordVariant &enote_record,
        const LegacyEnoteOriginContext &origin_context) override;

    expect<size_t> remove_records_with_txid(const crypto::hash &txid) override;
    expect<size_t> remove_non_ledger_records() override;
    expect<size_t> remove_ledger_records_before(const uint64_t block_index) override;
    expect<size_t> clear() override;

    expect<void> get_all_record_identifiers(std::vector<crypto::hash> &record_identifiers_out) const override;

    expect<void> get_record(const crypto::hash &record_identifier,
        MinimalIntermediateEnoteRecordVariant &enote_record_out,
        LegacyEnoteOriginContext &origin_context_out) const override;

    expect<bool> has_enote_at_global_index(const legacy_output_index_t &output_index) const override;

///CarrotBaseDBInterface
    expect<void> sync() override {}

private:
///member variables
    std::unordered_map<crypto::hash,
            std::pair<MinimalIntermediateEnoteRecordVariant, LegacyEnoteOriginContext>
        > m_records;
    std::unordered_set<legacy_output_index_t> m_owned_enote_indices;
};

expect<bool> CarrotEnoteRamDB::update_enote_record(
    const MinimalIntermediateEnoteRecordVariant &enote_record,
    const LegacyEnoteOriginContext &origin_context) override
{
}

struct CarrotKeyImageDBInterface: CarrotBaseDBInterface
{
    virtual expect<bool> add_key_image(
        const crypto::key_image &key_image,
        const SpEnoteSpentContextV1 &spent_context) = 0;

    virtual expect<bool> associate_key_image(const crypto::key_image &key_image,
        const crypto::public_key &onetime_address) = 0;

    virtual expect<size_t> remove_key_images_with_txid(const crypto::hash &txid) = 0;
    virtual expect<size_t> remove_non_ledger_key_images() = 0;
    virtual expect<size_t> remove_key_images_before(const uint64_t block_index) = 0;
    virtual expect<size_t> clear() = 0;

    virtual expect<void> get_all_key_images(std::vector<crypto::key_image> &key_images_out) const = 0;

    virtual expect<void> get_key_image_info(const crypto::key_image &key_image,
        SpEnoteSpentContextV1 &spent_context_out,
        std::optional<crypto::public_key> &associated_onetime_address_out) const = 0;
};

struct CarrotBalanceDBInterface: CarrotEnoteDBInterface, CarrotKeyImageDBInterface
{
    virtual expect<void> get_all_spendable_enote_identifiers(
        std::vector<crypto::hash> &enote_identifiers_out) const = 0;

    virtual expect<void> get_all_spendable_unspent_enote_identifiers(
        std::vector<crypto::hash> &enote_identifiers_out) const = 0;
};

struct CarrotScanStateDBInterface: CarrotBaseDBInterface
{
    virtual expect<bool> extend_chain(
        const crypto::hash &alignment_block_id,
        const std::vector<crypto::hash> &new_block_ids) = 0;

    virtual expect<bool> rollback_chain(const crypto::hash &block_id) = 0;

    virtual expect<void> trim_chain() = 0;

    virtual expect<void> set_genesis_block_id(const crypto::hash &genesis_block_id) = 0;

    virtual expect<void> set_restore_index(const uint64_t restore_block_index) = 0;

    virtual expect<void> mark_region_legacy_view_scanned(const uint64_t start_index, const uint64_t stop_index) = 0;
    virtual expect<void> mark_region_carrot_external_scanned(const uint64_t start_index, const uint64_t stop_index) = 0;
    virtual expect<void> mark_region_carrot_internal_scanned(const uint64_t start_index, const uint64_t stop_index) = 0;
};

////
// CarrotEnoteStore
// - tracks legacy and carrot enotes
///
class CarrotBalanceStore final
{
public:
    /// config: get index of the first block the enote store cares about
    std::uint64_t get_restore_index() const;

    /// get index of the highest recorded block (legacy refresh index - 1 if no recorded blocks)
    std::uint64_t top_block_index() const;
    /// get index of the highest block that was legacy partialscanned (view-scan only)
    std::uint64_t top_legacy_partialscanned_block_index() const { return m_legacy_partialscan_index; }
    /// get index of the highest block that was legacy fullscanned (view-scan + comprehensive key image checks)
    std::uint64_t top_legacy_fullscanned_block_index()    const { return m_legacy_fullscan_index;    }
    /// get index of the highest block that was seraphis view-balance scanned
    std::uint64_t top_sp_scanned_block_index()            const { return m_sp_scanned_index;         }

    /// get the next cached block index > the requested index (-1 on failure)
    std::uint64_t next_legacy_partialscanned_block_index(const std::uint64_t block_index) const;
    std::uint64_t next_legacy_fullscanned_block_index   (const std::uint64_t block_index) const;
    std::uint64_t next_sp_scanned_block_index           (const std::uint64_t block_index) const;
    /// get the nearest cached block index <= the requested index (refresh index - 1 on failure)
    std::uint64_t nearest_legacy_partialscanned_block_index(const std::uint64_t block_index) const;
    std::uint64_t nearest_legacy_fullscanned_block_index   (const std::uint64_t block_index) const;
    std::uint64_t nearest_sp_scanned_block_index           (const std::uint64_t block_index) const;
    /// try to get the cached block id for a given index and specified scan mode
    /// note: during scanning, different scan modes are assumed to 'not see' block ids obtained by a different scan mode;
    ///       this is necessary to reliably recover from reorgs involving multiple scan modes
    bool try_get_block_id_for_legacy_partialscan(const std::uint64_t block_index, rct::key &block_id_out) const;
    bool try_get_block_id_for_legacy_fullscan   (const std::uint64_t block_index, rct::key &block_id_out) const;
    bool try_get_block_id_for_sp                (const std::uint64_t block_index, rct::key &block_id_out) const;
    /// try to get the cached block id for a given index (checks legacy block ids then seraphis block ids)
    bool try_get_block_id(const std::uint64_t block_index, rct::key &block_id_out) const;
    /// check if any stored enote has a given key image
    bool has_enote_with_key_image(const crypto::key_image &key_image) const;
    /// get the legacy [ legacy identifier : legacy intermediate record ] map
    /// - note: useful for collecting onetime addresses and viewkey extensions for key image recovery
    const std::unordered_map<rct::key, LegacyContextualIntermediateEnoteRecordV1>& legacy_intermediate_records() const
    { return m_legacy_intermediate_contextual_enote_records; }
    /// get the legacy [ legacy identifier : legacy record ] map
    const std::unordered_map<rct::key, LegacyContextualEnoteRecordV1>& legacy_records() const
    { return m_legacy_contextual_enote_records; }
    /// get the legacy [ Ko : [ legacy identifier ] ] map
    const std::unordered_map<rct::key, std::unordered_set<rct::key>>& legacy_onetime_address_identifier_map() const
    { return m_tracked_legacy_onetime_address_duplicates; }
    /// get the legacy [ KI : Ko ] map
    const std::unordered_map<crypto::key_image, rct::key>& legacy_key_images() const
    { return m_legacy_key_images; }
    /// get the seraphis [ KI : sp record ] map
    const std::unordered_map<crypto::key_image, SpContextualEnoteRecordV1>& sp_records() const
    { return m_sp_contextual_enote_records; }
    /// try to get the legacy enote with a specified key image
    /// - will only return the highest-amount legacy enote among duplicates, and will return false if the
    ///   highest-amount legacy enote is currently in the intermediate records map
    bool try_get_legacy_enote_record(const crypto::key_image &key_image,
        LegacyContextualEnoteRecordV1 &contextual_record_out) const;
    /// try to get the seraphis enote with a specified key image
    bool try_get_sp_enote_record(const crypto::key_image &key_image,
        SpContextualEnoteRecordV1 &contextual_record_out) const;

    /// try to import a legacy key image
    /// - PRECONDITION1: the legacy key image was computed from/for the input onetime address
    /// - returns false if the onetime address is unknown (e.g. due to a reorg that removed the corresponding record)
    bool try_import_legacy_key_image(const crypto::key_image &legacy_key_image,
        const rct::key &onetime_address,
        std::list<EnoteStoreEvent> &events_inout);
    /// update the legacy fullscan index as part of a legacy key image import cycle
    void update_legacy_fullscan_index_for_import_cycle(const std::uint64_t saved_index);

    /// setters for scan indices
    /// WARNING: misuse of these will mess up the enote store's state (to recover: set index below problem then rescan)
    /// note: to repair the enote store in case of an exception or other error during an update, save all of the last
    ///       scanned indices from before the update, reset the enote store with them (after the failure), and then
    ///       re-scan to repair
    void set_last_legacy_partialscan_index(const std::uint64_t new_index);
    void set_last_legacy_fullscan_index   (const std::uint64_t new_index);
    void set_last_sp_scanned_index        (const std::uint64_t new_index);

    /// update the store with legacy enote records and associated context
    void update_with_intermediate_legacy_records_from_nonledger(const SpEnoteOriginStatus nonledger_origin_status,
        const std::unordered_map<rct::key, LegacyContextualIntermediateEnoteRecordV1> &found_enote_records,
        const std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> &found_spent_key_images,
        std::list<EnoteStoreEvent> &events_inout);
    void update_with_intermediate_legacy_records_from_ledger(const rct::key &alignment_block_id,
        const std::uint64_t first_new_block,
        const std::vector<rct::key> &new_block_ids,
        const std::unordered_map<rct::key, LegacyContextualIntermediateEnoteRecordV1> &found_enote_records,
        const std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> &found_spent_key_images,
        std::list<EnoteStoreEvent> &events_inout);
    void update_with_intermediate_legacy_found_spent_key_images(
        const std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> &found_spent_key_images,
        std::list<EnoteStoreEvent> &events_inout);
    void update_with_legacy_records_from_nonledger(const SpEnoteOriginStatus nonledger_origin_status,
        const std::unordered_map<rct::key, LegacyContextualEnoteRecordV1> &found_enote_records,
        const std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> &found_spent_key_images,
        std::list<EnoteStoreEvent> &events_inout);
    void update_with_legacy_records_from_ledger(const rct::key &alignment_block_id,
        const std::uint64_t first_new_block,
        const std::vector<rct::key> &new_block_ids,
        const std::unordered_map<rct::key, LegacyContextualEnoteRecordV1> &found_enote_records,
        const std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> &found_spent_key_images,
        std::list<EnoteStoreEvent> &events_inout);

    /// update the store with seraphis enote records and associated context
    void update_with_sp_records_from_nonledger(const SpEnoteOriginStatus nonledger_origin_status,
        const std::unordered_map<crypto::key_image, SpContextualEnoteRecordV1> &found_enote_records,
        const std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> &found_spent_key_images,
        const std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> &legacy_key_images_in_sp_selfsends,
        std::list<EnoteStoreEvent> &events_inout);
    void update_with_sp_records_from_ledger(const rct::key &alignment_block_id,
        const std::uint64_t first_new_block,
        const std::vector<rct::key> &new_block_ids,
        const std::unordered_map<crypto::key_image, SpContextualEnoteRecordV1> &found_enote_records,
        const std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> &found_spent_key_images,
        const std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> &legacy_key_images_in_sp_selfsends,
        std::list<EnoteStoreEvent> &events_inout);

private:
    std::unique_ptr<CarrotBalanceDBInterface> m_external_balance_db;
    std::unique_ptr<CarrotBalanceDBInterface> m_internal_balance_db;
    std::unique_ptr<CarrotScanStateDBInterface> m_scan_state_db;
};

} //namespace sp

// Copyright (c) 2014-2024, The Monero Project
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
// 
// Parts of this file are originally copyright (c) 2012-2013 The Cryptonote developers

#include "chaingen.h"
#include "device/device.hpp"
#include "enote_scanning.h"
#include "ringct/rctSigs.h"
#include "seraphis_core/legacy_enote_types.h"
#include "seraphis_main/enote_record_utils_legacy.h"

using namespace epee;
using namespace crypto;
using namespace cryptonote;

//----------------------------------------------------------------------------------------------------------------------
// Helpers
//----------------------------------------------------------------------------------------------------------------------
bool gen_enote_tx_validation_base::generate_with_full(std::vector<test_event_entry>& events,
    size_t mixin, uint64_t amount_paid, uint8_t hf_version, bool use_rct, const rct::RCTConfig &rct_config, bool use_view_tags,
    const std::function<bool(const cryptonote::transaction&)> &post_tx) const
{
  uint64_t ts_start = 1338224400;

  GENERATE_ACCOUNT(miner_account);
  MAKE_GENESIS_BLOCK(events, blk_0, miner_account, ts_start);

  // create 1 miner account, and have it mine the next block
  const cryptonote::block *prev_block = &blk_0;
  const size_t num_blocks = 1 + CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW + mixin;
  std::vector<cryptonote::block> blocks;
  blocks.resize(num_blocks);
  CHECK_AND_ASSERT_MES(generator.construct_block_manually(blocks[0], *prev_block, miner_account,
      test_generator::bf_major_ver | test_generator::bf_minor_ver | test_generator::bf_timestamp | test_generator::bf_hf_version,
      2, 2, prev_block->timestamp + DIFFICULTY_BLOCKS_ESTIMATE_TIMESPAN * 2, // v2 has blocks twice as long
        crypto::hash(), 0, transaction(), std::vector<crypto::hash>(), 0, 0, 2),
      false, "Failed to generate block");
  events.push_back(blocks[0]);

  // mine enough blocks to be able to spend
  cryptonote::block blk_r, blk_last;
  {
    blk_last = blocks[0];
    for (size_t i = 1; i < num_blocks; ++i)
    {
      CHECK_AND_ASSERT_MES(generator.construct_block_manually(blocks[i], blk_last, miner_account,
          test_generator::bf_major_ver | test_generator::bf_minor_ver | test_generator::bf_timestamp | test_generator::bf_hf_version,
          2, 2, blk_last.timestamp + DIFFICULTY_BLOCKS_ESTIMATE_TIMESPAN * 2, // v2 has blocks twice as long
          crypto::hash(), 0, cryptonote::transaction(), std::vector<crypto::hash>(), 0, 0, 2),
          false, "Failed to generate block");
      events.push_back(blocks[i]);
      blk_last = blocks[i];
    }
    blk_r = blk_last;
  }

  // create tx from this miner in another block
  static const uint64_t input_amounts_available[] = {5000000000000, 30000000000000, 100000000000, 80000000000};
  std::vector<tx_source_entry> sources;

  sources.resize(1);
  tx_source_entry& src = sources.back();

  const uint64_t needed_amount = src.amount = input_amounts_available[0];

  size_t real_index_in_tx = 0;
  for (size_t m = 0; m <= mixin; ++m) {
    size_t index_in_tx = 0;
    for (size_t i = 0; i < blocks[m].miner_tx.vout.size(); ++i)
      if (blocks[m].miner_tx.vout[i].amount == needed_amount)
        index_in_tx = i;
    CHECK_AND_ASSERT_MES(blocks[m].miner_tx.vout[index_in_tx].amount == needed_amount, false, "Expected amount not found");
    src.push_output(m, boost::get<txout_to_key>(blocks[m].miner_tx.vout[index_in_tx].target).key, src.amount);
    if (m == 0)
      real_index_in_tx = index_in_tx;
  }
  src.real_out_tx_key = cryptonote::get_tx_pub_key_from_extra(blocks[0].miner_tx);
  src.real_output = 0;
  src.real_output_in_tx_index = real_index_in_tx;
  src.mask = rct::identity();
  src.rct = false;

  cryptonote::transaction tx;
  cryptonote::block blk_txes;

  // fill outputs entry
  tx_destination_entry td;
  td.addr = miner_account.get_keys().m_account_address;
  std::vector<tx_destination_entry> destinations;
  td.amount = amount_paid;
  destinations.push_back(td);
  destinations.push_back(td);

  crypto::secret_key tx_key;
  std::vector<crypto::secret_key> additional_tx_keys;
  std::unordered_map<crypto::public_key, cryptonote::subaddress_index> subaddresses;
  subaddresses[miner_account.get_keys().m_account_address.m_spend_public_key] = {0,0};
  bool r = construct_tx_and_get_tx_key(
    miner_account.get_keys(),
    subaddresses,
    sources,
    destinations,
    cryptonote::account_public_address{},
    std::vector<uint8_t>(),
    tx,
    tx_key,
    additional_tx_keys,
    use_rct,
    rct_config,
    use_view_tags);
  CHECK_AND_ASSERT_MES(r, false, "failed to construct transaction");

  if (post_tx && !post_tx(tx))
  {
    MDEBUG("post_tx returned failure");
    return false;
  }

  LOG_PRINT_L0("Test tx: " << obj_to_json_str(tx));
  events.push_back(tx);

  CHECK_AND_ASSERT_MES(generator.construct_block_manually(blk_txes, blocks.back(), miner_account,
      test_generator::bf_major_ver | test_generator::bf_minor_ver | test_generator::bf_timestamp | test_generator::bf_tx_hashes | test_generator::bf_hf_version | test_generator::bf_max_outs | test_generator::bf_tx_fees,
      hf_version, hf_version, blocks.back().timestamp + DIFFICULTY_BLOCKS_ESTIMATE_TIMESPAN * 2, // v2 has blocks twice as long
      crypto::hash(), 0, cryptonote::transaction(), std::vector<crypto::hash>{cryptonote::get_transaction_hash(tx)}, 0, 6, hf_version, get_tx_fee(tx)),
      false, "Failed to generate block");
  events.push_back(blk_txes);

  return true;
}
//----------------------------------------------------------------------------------------------------------------------
template<typename T>
static bool check_enotes(const cryptonote::transaction &tx)
{
  CHECK_AND_ASSERT_MES(tx.vout.size() > 0, false, "unexpected number of tx outs");

  std::vector<sp::LegacyEnoteVariant> enotes;
  sp::legacy_outputs_to_enotes(tx, enotes);

  CHECK_AND_ASSERT_MES(tx.vout.size() == enotes.size(), false, "outputs <> enotes size doesn't match");

  // Assert the enotes are the expected type
  for (const auto &enote : enotes)
  {
    const T *enote_ptr = enote.try_unwrap<T>();
    CHECK_AND_ASSERT_MES(enote_ptr, false, "unexpected enote type");
  }

  return true;
}
//----------------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------------
// Tests
//----------------------------------------------------------------------------------------------------------------------
bool gen_enote_v1_pre_rct::generate(std::vector<test_event_entry>& events) const
{
  const int mixin = 2;
  const uint64_t amount_paid = 10000;

  bool use_rct = false;
  bool use_view_tags = false;
  auto post_tx = [](const cryptonote::transaction &tx)
  {
    return check_enotes<sp::LegacyEnoteV1>(tx);
  };

  return generate_with_full(events, mixin, amount_paid, 4, use_rct, {}, use_view_tags, post_tx);
}
//----------------------------------------------------------------------------------------------------------------------
bool gen_enote_v1_coinbase::generate(std::vector<test_event_entry>& events) const
{
  uint64_t ts_start = 1338224400;

  GENERATE_ACCOUNT(miner_account);
  MAKE_GENESIS_BLOCK(events, blk_0, miner_account, ts_start);

  const cryptonote::block *prev_block = &blk_0;
  cryptonote::block block;
  CHECK_AND_ASSERT_MES(generator.construct_block_manually(block, *prev_block, miner_account,
      test_generator::bf_major_ver | test_generator::bf_minor_ver | test_generator::bf_timestamp | test_generator::bf_hf_version,
      2, 2, prev_block->timestamp + DIFFICULTY_BLOCKS_ESTIMATE_TIMESPAN * 2, // v2 has blocks twice as long
      crypto::hash(), 0, transaction(), std::vector<crypto::hash>(), 0, 0, 2),
      false, "Failed to generate block");
  events.push_back(block);

  return check_enotes<sp::LegacyEnoteV1>(block.miner_tx);
}
//----------------------------------------------------------------------------------------------------------------------
bool gen_enote_v2_rct_full_size_encoded_amount::generate(std::vector<test_event_entry>& events) const
{
  const int mixin = 2;
  const uint64_t amount_paid = 10000;

  bool use_rct = true;
  const rct::RCTConfig rct_config { rct::RangeProofBorromean, 0 };
  bool use_view_tags = false;

  auto post_tx = [](const cryptonote::transaction &tx)
  {
    return check_enotes<sp::LegacyEnoteV2>(tx);
  };

  return generate_with_full(events, mixin, amount_paid, 4, use_rct, rct_config, use_view_tags, post_tx);
}
//----------------------------------------------------------------------------------------------------------------------
bool gen_enote_v3_rct_compact_encoded_amount::generate(std::vector<test_event_entry>& events) const
{
  const int mixin = 10;
  const uint64_t amount_paid = 10000;

  bool use_rct = true;
  const rct::RCTConfig rct_config { rct::RangeProofPaddedBulletproof, 2 };
  bool use_view_tags = false;

  auto post_tx = [](const cryptonote::transaction &tx)
  {
    return check_enotes<sp::LegacyEnoteV3>(tx);
  };

  return generate_with_full(events, mixin, amount_paid, 11, use_rct, rct_config, use_view_tags, post_tx);
}
//----------------------------------------------------------------------------------------------------------------------
bool gen_enote_v4_coinbase_view_tags::generate(std::vector<test_event_entry>& events) const
{
  uint64_t ts_start = 1338224400;

  GENERATE_ACCOUNT(miner_account);
  MAKE_GENESIS_BLOCK(events, blk_0, miner_account, ts_start);

  const cryptonote::block *prev_block = &blk_0;
  cryptonote::block block;
  CHECK_AND_ASSERT_MES(generator.construct_block_manually(block, *prev_block, miner_account,
      test_generator::bf_major_ver | test_generator::bf_minor_ver | test_generator::bf_timestamp | test_generator::bf_hf_version,
      HF_VERSION_VIEW_TAGS, HF_VERSION_VIEW_TAGS, prev_block->timestamp + DIFFICULTY_BLOCKS_ESTIMATE_TIMESPAN * 2, // v2 has blocks twice as long
      crypto::hash(), 0, transaction(), std::vector<crypto::hash>(), 0, 0, HF_VERSION_VIEW_TAGS),
      false, "Failed to generate block");
  events.push_back(block);

  return check_enotes<sp::LegacyEnoteV4>(block.miner_tx);
}
//----------------------------------------------------------------------------------------------------------------------
bool gen_enote_v5_rct_view_tags::generate(std::vector<test_event_entry>& events) const
{
  const int mixin = 15;
  const uint64_t amount_paid = 10000;

  bool use_rct = true;
  const rct::RCTConfig rct_config { rct::RangeProofPaddedBulletproof, 4 };
  bool use_view_tags = true;

  auto post_tx = [](const cryptonote::transaction &tx)
  {
    return check_enotes<sp::LegacyEnoteV5>(tx);
  };

  return generate_with_full(events, mixin, amount_paid, HF_VERSION_VIEW_TAGS, use_rct, rct_config, use_view_tags, post_tx);
}

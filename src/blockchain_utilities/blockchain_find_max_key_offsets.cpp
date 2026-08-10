// Copyright (c) 2026, The Monero Project
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

#include <filesystem>
#include <iomanip>

#include "common/command_line.h"
#include "cryptonote_core/cryptonote_core.h"
#include "blockchain_db/lmdb/db_lmdb.h"
#include "version.h"

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "bcutil"

namespace po = boost::program_options;
using namespace cryptonote;

// see db_lmdb.cpp, must touch these cursors before hand ;(
#define RCURSOR(name) \
  CHECK_AND_ASSERT_MES(m_cur_ ## name, 1, "Cursor " #name " hasn't been touched yet"); \
  CHECK_AND_ASSERT_MES(mdb_cursor_renew(txn, m_cur_ ## name) == 0, 1, "Failed to renew cursor " #name); \

int main(int argc, char* argv[])
{
  TRY_ENTRY();

  epee::string_tools::set_module_name_and_folder(argv[0]);

  tools::on_startup();

  po::options_description desc_cmd_only("Command line options");
  po::options_description desc_cmd_sett("Command line options and settings options");
  const command_line::arg_descriptor<std::string> arg_log_level  = {"log-level",  "0-4 or categories", ""};

  command_line::add_arg(desc_cmd_sett, cryptonote::arg_data_dir);
  command_line::add_arg(desc_cmd_sett, cryptonote::arg_testnet_on);
  command_line::add_arg(desc_cmd_sett, cryptonote::arg_stagenet_on);
  command_line::add_arg(desc_cmd_sett, cryptonote::arg_regtest_on);
  command_line::add_arg(desc_cmd_sett, arg_log_level);
  command_line::add_arg(desc_cmd_only, command_line::arg_help);

  po::options_description desc_options("Allowed options");
  desc_options.add(desc_cmd_only).add(desc_cmd_sett);

  po::variables_map vm;
  bool r = command_line::handle_error_helper(desc_options, [&]()
  {
    auto parser = po::command_line_parser(argc, argv).options(desc_options);
    po::store(parser.run(), vm);
    po::notify(vm);
    return true;
  });
  if (! r)
    return 1;

  if (command_line::get_arg(vm, command_line::arg_help))
  {
    std::cout << "Monero '" << MONERO_RELEASE_NAME << "' (v" << MONERO_VERSION_FULL << ")" << ENDL << ENDL;
    std::cout << desc_options << std::endl;
    return 1;
  }

  mlog_configure(mlog_get_default_log_path("monero-find-max-key-offsets.log"), true);
  if (!command_line::is_arg_defaulted(vm, arg_log_level))
    mlog_set_log(command_line::get_arg(vm, arg_log_level).c_str());
  else
    mlog_set_log("0,bcutil:INFO");

  LOG_PRINT_L0("Starting...");

  std::string opt_data_dir = command_line::get_arg(vm, cryptonote::arg_data_dir);
  const network_type net_type = core::get_network_type_from_args(vm);

  LOG_PRINT_L0("Initializing source blockchain (BlockchainDB)");
  std::unique_ptr<BlockchainAndPool> core_storage = std::make_unique<BlockchainAndPool>();

  BlockchainDB *db = new_db();
  if (db == NULL)
  {
    LOG_ERROR("Failed to initialize a database");
    throw std::runtime_error("Failed to initialize a database");
  }

  const std::string filename = (std::filesystem::path(opt_data_dir) / db->get_db_name()).string();
  LOG_PRINT_L0("Loading blockchain from folder " << filename << " ...");

  // Open DB
  try
  {
    db->open(filename, DBF_RDONLY);
  }
  catch (const std::exception& e)
  {
    LOG_PRINT_L0("Error opening database: " << e.what());
    return 1;
  }
  r = core_storage->blockchain.init(db, net_type);
  CHECK_AND_ASSERT_MES(r, 1, "Failed to initialize source blockchain storage");
  LOG_PRINT_L0("Source blockchain storage initialized OK");

  // Ctrl-C handler
  std::atomic<bool> stop_requested;
  tools::signal_handler::install([&stop_requested](int type) {
    stop_requested.store(true);
  });

  // Get chain height
  const uint64_t db_height = core_storage->blockchain.get_current_blockchain_height();
  CHECK_AND_ASSERT_THROW_MES(db_height >= 1, "No chain");
  MINFO("Starting from height " << 0 << ", stopping at height " << (db_height - 1));

  // Setup LMDB
  BlockchainLMDB *lmdb = dynamic_cast<BlockchainLMDB*>(&core_storage->blockchain.get_db());
  MDB_txn *txn = nullptr;
  mdb_txn_cursors *m_cursors = nullptr;
  const bool started_read = lmdb->block_rtxn_start(&txn, &m_cursors);
  CHECK_AND_ASSERT_MES(started_read && txn && m_cursors, 1, "Could not start LMDB read txn");

  // Touch certain functions to "wake up" read cursors for this thread (this is horrible, I'm sorry)
  {
    const crypto::hash some_txid =
      get_transaction_hash(core_storage->blockchain.get_db().get_top_block().miner_tx);
    std::vector<crypto::hash> a{some_txid};
    std::vector<std::tuple<crypto::hash, cryptonote::blobdata, crypto::hash, cryptonote::blobdata>> b;
    std::vector<crypto::hash> c;
    core_storage->blockchain.get_split_transactions_blobs(a, b, c);
  }

  RCURSOR(tx_indices);
  RCURSOR(txs_pruned);
  RCURSOR(txs_prunable_hash);

  // Subroutine for TXID of txindex at `k` with given base blob
  MDB_val k, v;
  const auto curr_txid = [&k, &v, &m_cursors](const blobdata_ref tx_base_blob) -> crypto::hash
  {
    transaction tx;
    crypto::hash txid = crypto::null_hash;

    int result = mdb_cursor_get(m_cur_txs_prunable_hash, &k, &v, MDB_SET);

    if (result == 0 && v.mv_size == 32 && memcmp(v.mv_data, crypto::null_hash.data, 32))
    {
      // Calculate TXID from pruned blob and prunable hash
      crypto::hash prunable_hash = crypto::null_hash;
      memcpy(prunable_hash.data, v.mv_data, crypto::HASH_SIZE);
      CHECK_AND_ASSERT_THROW_MES(parse_and_validate_tx_base_from_blob(tx_base_blob, tx),
        "Could not parse transaction base");
      CHECK_AND_ASSERT_THROW_MES(get_pruned_transaction_hash(tx, prunable_hash, txid),
        "Could not calculate pruned transaction hash");
    }
    else
    {
      // Calculate TXID from combined full tx blob
      result = mdb_cursor_get(m_cur_txs_prunable, &k, &v, MDB_SET);
      CHECK_AND_ASSERT_THROW_MES(result == 0, "Could not fetch tx prunable data");
      blobdata full_tx_blob(tx_base_blob);
      full_tx_blob.append(reinterpret_cast<const char*>(v.mv_data), v.mv_size);
      CHECK_AND_ASSERT_THROW_MES(parse_and_validate_tx_from_blob(full_tx_blob, tx, txid),
        "Could not parse and hash full tx from blob");
    }

    return txid;
  };

  // Loop through all txs on the chain, keeping a running `max_ring_size` and `max_total_ring_size`
  MDB_cursor_op op = MDB_FIRST;
  uint64_t max_ring_size = 16;
  crypto::hash txid_for_max_ring_size = crypto::null_hash;
  uint64_t max_total_ring_size = max_ring_size;
  crypto::hash txid_for_max_total_ring_size = txid_for_max_ring_size;
  transaction_prefix tx_prefix;
  for (uint64_t i = 0; !stop_requested.load(); ++i)
  {
    if (i % 10000 == 0)
    {
      const float progress = 100.0f * i / lmdb->get_tx_count();
      std::cout << std::fixed << std::setprecision(1) << progress << "%      \r";
      std::cout.flush();
    }

    int result = mdb_cursor_get(m_cur_txs_pruned, &k, &v, op);
    op = MDB_NEXT;
    if (result == MDB_NOTFOUND)
    {
      CHECK_AND_ASSERT_MES(i == lmdb->get_tx_count(), 1, "Ended on unexpected tx index");
      break;
    }
    CHECK_AND_ASSERT_MES(result == 0, 1, "Failed tx pruned lookup");
    CHECK_AND_ASSERT_MES(k.mv_size == sizeof(uint64_t), 1, "Wrong tx index key size");
    CHECK_AND_ASSERT_MES(0 == memcmp(k.mv_data, &i, sizeof(i)), 1, "Unexpected tx index key");

    const blobdata_ref tx_base_blob{reinterpret_cast<const char*>(v.mv_data), v.mv_size};
    CHECK_AND_ASSERT_MES(parse_and_validate_tx_prefix_from_blob(tx_base_blob, tx_prefix),
      1, "Failed to parse tx prefix");
    CHECK_AND_ASSERT_MES(!tx_prefix.vin.empty(), 1, "tx prefix has no inputs");
    uint64_t total_ring_size = 0;
    uint64_t ring_size = 0;
    for (const txin_v &in : tx_prefix.vin)
    {
      const txin_to_key *non_miner_in = boost::strict_get<txin_to_key>(&in);
      if (!non_miner_in)
        continue;
      const uint64_t this_ring_size = non_miner_in->key_offsets.size();
      ring_size = std::max(this_ring_size, ring_size);
      total_ring_size += this_ring_size;
    }

    if (ring_size <= max_ring_size && total_ring_size <= max_total_ring_size)
      continue; // small ring tx, continue to next tx

    crypto::hash txid;
    try { txid = curr_txid(tx_base_blob); } catch (...) { return 1; }

    if (ring_size > max_ring_size)
    {
      // Print and update results
      std::cout << "New maximum ring size found in TX " << txid << ": " << ring_size << std::endl;
      max_ring_size = ring_size;
      txid_for_max_ring_size = txid;
      if (max_ring_size > max_total_ring_size)
      {
        max_total_ring_size = max_ring_size;
        txid_for_max_total_ring_size = txid_for_max_ring_size;
      }
    }
  
    if (total_ring_size > max_total_ring_size)
    {
      // Print and update results
      std::cout << "New maximum *total* ring members found in TX " << txid << ": " << total_ring_size << std::endl;
      max_total_ring_size = total_ring_size;
      txid_for_max_total_ring_size = txid;
    }
  }

  // Print summary
  std::cout << "         " << std::endl;
  std::cout << "Results:" << std::endl;
  std::cout << "  Max ring size (" << max_ring_size << ") in TX " << txid_for_max_ring_size << std::endl;
  std::cout << "  Max total ring members (" << max_total_ring_size << ") in TX " << txid_for_max_total_ring_size << std::endl;

  // Deinit
  lmdb->block_rtxn_stop();
  core_storage->blockchain.deinit();
  return 0;

  CATCH_ENTRY("Stats reporting error", 1);
}

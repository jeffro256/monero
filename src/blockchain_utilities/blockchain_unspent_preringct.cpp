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

#include <filesystem>

#include "blockchain_db/lmdb/db_lmdb.h"
#include "common/command_line.h"
#include "cryptonote_core/blockchain_and_pool.h"
#include "cryptonote_core/cryptonote_core.h"
#include "hardforks/hardforks.h"
#include "version.h"

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "bcutil"

namespace po = boost::program_options;
using namespace epee;
using namespace cryptonote;

static std::atomic<bool> stop_requested = false;

#define TXN_PREFIX_RDONLY() \
  MDB_txn *m_txn; \
  mdb_txn_cursors *m_cursors; \
  mdb_txn_safe auto_txn; \
  bool my_rtxn = block_rtxn_start(&m_txn, &m_cursors); \
  if (my_rtxn) auto_txn.m_tinfo = m_tinfo.get(); \
  else auto_txn.uncheck()
#define TXN_POSTFIX_RDONLY()

#define RCURSOR(name) \
	if (!m_cur_ ## name) { \
	  int result = mdb_cursor_open(m_txn, m_ ## name, (MDB_cursor **)&m_cur_ ## name); \
	  if (result) \
        throw0(DB_ERROR(lmdb_error("Failed to open cursor: ", result).c_str())); \
	  if (m_cursors != &m_wcursors) \
	    m_tinfo->m_ti_rflags.m_rf_ ## name = true; \
	} else if (m_cursors != &m_wcursors && !m_tinfo->m_ti_rflags.m_rf_ ## name) { \
	  int result = mdb_cursor_renew(m_txn, m_cur_ ## name); \
      if (result) \
        throw0(DB_ERROR(lmdb_error("Failed to renew cursor: ", result).c_str())); \
	  m_tinfo->m_ti_rflags.m_rf_ ## name = true; \
	}

static std::string lmdb_error(const std::string& error_string, int mdb_res)
{
  const std::string full_string = error_string + mdb_strerror(mdb_res);
  return full_string;
}

template <typename T>
inline void throw0(const T &e)
{
  LOG_PRINT_L0(e.what());
  throw e;
}

class UnspentPreRingCTBlockchain: public cryptonote::BlockchainLMDB
{
public:
  void report_unspent_preringct(std::map<rct::xmr_amount, std::pair<uint32_t, uint32_t>> &report) const
  {
    LOG_PRINT_L3("UnspentPreRingCTBlockchain::" << __func__);
    if (!m_open)
      throw0(DB_ERROR("DB operation attempted on a not-open DB instance"));

    TXN_PREFIX_RDONLY();
    RCURSOR(txs_pruned);

    MDB_val k;
    MDB_val v;

    transaction tx;

    MDB_cursor_op op = MDB_FIRST;
    while (!stop_requested.load())
    {
      int ret = mdb_cursor_get(m_cur_txs_pruned, &k, &v, op);
      op = MDB_NEXT;
      if (ret == MDB_NOTFOUND)
        break;
      if (ret)
        throw0(DB_ERROR(lmdb_error("Failed to enumerate transactions: ", ret).c_str()));

      blobdata_ref bd{reinterpret_cast<char*>(v.mv_data), v.mv_size};
      if (!parse_and_validate_tx_base_from_blob(bd, tx))
        throw0(DB_ERROR("Failed to parse tx from blob retrieved from the db"));

      for (const cryptonote::txin_v &in : tx.vin)
      {
        if (in.type() == typeid(cryptonote::txin_gen))
        {
          const uint64_t block_height = boost::get<txin_gen>(in).height;
          if (block_height % 10000 == 0)
          {
            std::cout << block_height << '\r';
            std::cout.flush();
          }
          break;
        }

        const rct::xmr_amount amount_spent = boost::get<cryptonote::txin_to_key>(in).amount;
        if (amount_spent)
          ++report[amount_spent].second;
      }

      if (tx.version == 1) // i.e. NOT RingCT
      {
        for (const cryptonote::tx_out &out : tx.vout)
          ++report[out.amount].first;
      }
    }

    TXN_POSTFIX_RDONLY();
  }
};

int main(int argc, char* argv[])
{
  epee::string_tools::set_module_name_and_folder(argv[0]);

  uint32_t log_level = 0;

  tools::on_startup();

  tools::signal_handler::install([](int type) {
    stop_requested.store(true);
  });

  po::options_description desc_cmd_only("Command line options");
  po::options_description desc_cmd_sett("Command line options and settings options");
  const command_line::arg_descriptor<std::string> arg_log_level = {"log-level",  "0-4 or categories", ""};
  const command_line::arg_descriptor<std::string> arg_output_file = {"output-file", "path to CSV output file", "blockchain-unspent-preringct-output.csv"};

  command_line::add_arg(desc_cmd_sett, cryptonote::arg_data_dir);
  command_line::add_arg(desc_cmd_sett, cryptonote::arg_testnet_on);
  command_line::add_arg(desc_cmd_sett, cryptonote::arg_stagenet_on);
  command_line::add_arg(desc_cmd_sett, arg_log_level);
  command_line::add_arg(desc_cmd_sett, arg_output_file);
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

  mlog_configure(mlog_get_default_log_path("monero-blockchain-unspent-preringct.log"), true);
  if (!command_line::is_arg_defaulted(vm, arg_log_level))
    mlog_set_log(command_line::get_arg(vm, arg_log_level).c_str());
  else
    mlog_set_log(std::string(std::to_string(log_level) + ",bcutil:INFO").c_str());

  LOG_PRINT_L0("Starting...");

  std::string opt_data_dir = command_line::get_arg(vm, cryptonote::arg_data_dir);
  const bool opt_testnet = command_line::get_arg(vm, cryptonote::arg_testnet_on);
  const bool opt_stagenet = command_line::get_arg(vm, cryptonote::arg_stagenet_on);
  network_type net_type = opt_testnet ? TESTNET : opt_stagenet ? STAGENET : MAINNET;
  const std::string opt_output_file = command_line::get_arg(vm, arg_output_file);

  if (std::filesystem::exists(opt_output_file))
  {
    LOG_ERROR("Output file already exists");
    throw std::runtime_error("Output file already exists");
  }

  // If we wanted to use the memory pool, we would set up a fake_core.

  // Use Blockchain instead of lower-level BlockchainDB for ona main reason:
  //     Blockchain has the init() method for easy setup
  //
  // cannot match blockchain_storage setup above with just one line,
  // e.g.
  //   Blockchain* core_storage = new Blockchain(NULL);
  // because unlike blockchain_storage constructor, which takes a pointer to
  // tx_memory_pool, Blockchain's constructor takes tx_memory_pool object.
  LOG_PRINT_L0("Initializing source blockchain (BlockchainDB)");
  std::unique_ptr<BlockchainAndPool> core_storage = std::make_unique<BlockchainAndPool>();
  UnspentPreRingCTBlockchain *db = new UnspentPreRingCTBlockchain();
  if (db == NULL)
  {
    LOG_ERROR("Failed to initialize a database");
    throw std::runtime_error("Failed to initialize a database");
  }
  LOG_PRINT_L0("database: LMDB");

  const std::string filename = (std::filesystem::path(opt_data_dir) / db->get_db_name()).string();
  LOG_PRINT_L0("Loading blockchain from folder " << filename << " ...");

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

  //       amount:                    #created  #spent
  std::map<rct::xmr_amount, std::pair<uint32_t, uint32_t>> report_by_amount;

  LOG_PRINT_L0("Opening output file: " << opt_output_file);
  std::ofstream report_ofs;
  report_ofs.open(opt_output_file);
  CHECK_AND_ASSERT_THROW_MES(!report_ofs.fail(),
    "Could not open file '" << opt_output_file << "' for writing");

  // get number of blocks and resize standard_cache_updates accordingly
  const uint32_t db_height = db->height();

  LOG_PRINT_L0("Blockchain height: " << db_height);

  LOG_PRINT_L0("Starting main output iteration loop...");

  // perform main data processing on all outputs
  db->report_unspent_preringct(report_by_amount);

  LOG_PRINT_L0("Writing report to CSV file...");

  for (const auto &p : report_by_amount)
  {
    report_ofs << p.first << '\t' << p.second.first << '\t' << p.second.second << '\n';
  }

  CHECK_AND_ASSERT_THROW_MES(!report_ofs.fail(), "writing CSV to output file failed");

  LOG_PRINT_L0("Saved report.... Done!");

  return 0;
}

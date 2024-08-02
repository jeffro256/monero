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

#include <chrono>
#include <memory>

#include <boost/regex.hpp>

#include "common/util.h"
#include "common/command_line.h"
#include "performance_tests.h"
#include "performance_utils.h"

// tests
#include "async.h"
#include "balance_check.h"
#include "blake2b.h"
#include "construct_tx.h"
#include "check_tx_signature.h"
#include "check_hash.h"
#include "cn_slow_hash.h"
#include "derive_public_key.h"
#include "derive_secret_key.h"
#include "derive_view_tag.h"
#include "ge_frombytes_vartime.h"
#include "ge_tobytes.h"
#include "generate_key_derivation.h"
#include "generate_key_image.h"
#include "generate_key_image_helper.h"
#include "generate_keypair.h"
#include "signature.h"
#include "is_out_to_acc.h"
#include "out_can_be_to_acc.h"
#include "subaddress_expand.h"
#include "sc_reduce32.h"
#include "sc_check.h"
#include "cn_fast_hash.h"
#include "rct_mlsag.h"
#include "equality.h"
#include "range_proof.h"
#include "bulletproof.h"
#include "bulletproof_plus.h"
#include "crypto_ops.h"
#include "multiexp.h"
#include "sig_mlsag.h"
#include "sig_clsag.h"
#include "seraphis_tx.h"
#include "grootle.h"
#include "view_scan.h"

namespace po = boost::program_options;

int main(int argc, char** argv)
{
  TRY_ENTRY();
  tools::on_startup();
  set_process_affinity(1);
  set_thread_high_priority();

  mlog_configure(mlog_get_default_log_path("performance_tests.log"), true);

  po::options_description desc_options("Command line options");
  const command_line::arg_descriptor<std::string> arg_filter = { "filter", "Regular expression filter for which tests to run" };
  const command_line::arg_descriptor<bool> arg_verbose = { "verbose", "Verbose output", false };
  const command_line::arg_descriptor<bool> arg_stats = { "stats", "Including statistics (min/median)", false };
  const command_line::arg_descriptor<unsigned> arg_loop_multiplier = { "loop-multiplier", "Run for that many times more loops", 1 };
  const command_line::arg_descriptor<std::string> arg_timings_database = { "timings-database", "Keep timings history in a file" };
  command_line::add_arg(desc_options, arg_filter);
  command_line::add_arg(desc_options, arg_verbose);
  command_line::add_arg(desc_options, arg_stats);
  command_line::add_arg(desc_options, arg_loop_multiplier);
  command_line::add_arg(desc_options, arg_timings_database);

  po::variables_map vm;
  bool r = command_line::handle_error_helper(desc_options, [&]()
  {
    po::store(po::parse_command_line(argc, argv, desc_options), vm);
    po::notify(vm);
    return true;
  });
  if (!r)
    return 1;

  const std::string filter = tools::glob_to_regex(command_line::get_arg(vm, arg_filter));
  const std::string timings_database = command_line::get_arg(vm, arg_timings_database);
  ParamsShuttle p;
  if (!timings_database.empty())
    p.core_params.td = std::make_shared<TimingsDatabase>(timings_database);
  p.core_params.verbose = command_line::get_arg(vm, arg_verbose);
  p.core_params.stats = command_line::get_arg(vm, arg_stats);
  p.core_params.loop_multiplier = command_line::get_arg(vm, arg_loop_multiplier);

  performance_timer timer;
  timer.start();


  // test threadpools
  ParamsShuttleAsync p_async;
  p_async.core_params = p.core_params;

  p_async.description = "async: main thread, 1 task @ 100us";
  p_async.num_extra_threads          = 0;
  p_async.num_tasks                  = 1;
  p_async.sleepy_task_cadence        = 0;
  p_async.task_duration              = std::chrono::microseconds{100};
  p_async.sleepy_task_sleep_duration = std::chrono::microseconds{0};
  TEST_PERFORMANCE0(filter, p_async, test_common_threadpool); p_async.description = "";
  TEST_PERFORMANCE0(filter, p_async, test_async_threadpool);
  TEST_PERFORMANCE0(filter, p_async, test_async_threadpool_with_fanout);
  TEST_PERFORMANCE0(filter, p_async, test_parent_threadpool);

  p_async.description = "async: main thread, 100 tasks @ 100us";
  p_async.num_extra_threads          = 0;
  p_async.num_tasks                  = 100;
  p_async.sleepy_task_cadence        = 0;
  p_async.task_duration              = std::chrono::microseconds{100};
  p_async.sleepy_task_sleep_duration = std::chrono::microseconds{0};
  TEST_PERFORMANCE0(filter, p_async, test_common_threadpool); p_async.description = "";
  TEST_PERFORMANCE0(filter, p_async, test_async_threadpool);
  TEST_PERFORMANCE0(filter, p_async, test_async_threadpool_with_fanout);
  TEST_PERFORMANCE0(filter, p_async, test_parent_threadpool);

  p_async.description = "async: main thread + 1, 100 tasks @ 100us";
  p_async.num_extra_threads          = 1;
  p_async.num_tasks                  = 100;
  p_async.sleepy_task_cadence        = 0;
  p_async.task_duration              = std::chrono::microseconds{100};
  p_async.sleepy_task_sleep_duration = std::chrono::microseconds{0};
  TEST_PERFORMANCE0(filter, p_async, test_common_threadpool); p_async.description = "";
  TEST_PERFORMANCE0(filter, p_async, test_async_threadpool);
  TEST_PERFORMANCE0(filter, p_async, test_async_threadpool_with_fanout);
  TEST_PERFORMANCE0(filter, p_async, test_parent_threadpool);

  p_async.description = "async: main thread + 2, 100 tasks @ 100us";
  p_async.num_extra_threads          = 2;
  p_async.num_tasks                  = 100;
  p_async.sleepy_task_cadence        = 0;
  p_async.task_duration              = std::chrono::microseconds{100};
  p_async.sleepy_task_sleep_duration = std::chrono::microseconds{0};
  TEST_PERFORMANCE0(filter, p_async, test_common_threadpool); p_async.description = "";
  TEST_PERFORMANCE0(filter, p_async, test_async_threadpool);
  TEST_PERFORMANCE0(filter, p_async, test_async_threadpool_with_fanout);
  TEST_PERFORMANCE0(filter, p_async, test_parent_threadpool);

  p_async.description = "async: main thread + 2, 100 tasks @ 1000us";
  p_async.num_extra_threads          = 2;
  p_async.num_tasks                  = 100;
  p_async.sleepy_task_cadence        = 0;
  p_async.task_duration              = std::chrono::microseconds{1000};
  p_async.sleepy_task_sleep_duration = std::chrono::microseconds{0};
  TEST_PERFORMANCE0(filter, p_async, test_common_threadpool); p_async.description = "";
  TEST_PERFORMANCE0(filter, p_async, test_async_threadpool);
  TEST_PERFORMANCE0(filter, p_async, test_async_threadpool_with_fanout);
  TEST_PERFORMANCE0(filter, p_async, test_parent_threadpool);

  p_async.description = "async: main thread + 6, 100 tasks @ 1000us";
  p_async.num_extra_threads          = 6;
  p_async.num_tasks                  = 100;
  p_async.sleepy_task_cadence        = 0;
  p_async.task_duration              = std::chrono::microseconds{1000};
  p_async.sleepy_task_sleep_duration = std::chrono::microseconds{0};
  TEST_PERFORMANCE0(filter, p_async, test_common_threadpool); p_async.description = "";
  TEST_PERFORMANCE0(filter, p_async, test_async_threadpool);
  TEST_PERFORMANCE0(filter, p_async, test_async_threadpool_with_fanout);
  TEST_PERFORMANCE0(filter, p_async, test_parent_threadpool);

  p_async.description = "async: main thread + 6, 10000 tasks @ 1us";
  p_async.num_extra_threads          = 6;
  p_async.num_tasks                  = 10000;
  p_async.sleepy_task_cadence        = 0;
  p_async.task_duration              = std::chrono::microseconds{1};
  p_async.sleepy_task_sleep_duration = std::chrono::microseconds{0};
  TEST_PERFORMANCE0(filter, p_async, test_common_threadpool); p_async.description = "";
  TEST_PERFORMANCE0(filter, p_async, test_async_threadpool);
  TEST_PERFORMANCE0(filter, p_async, test_async_threadpool_with_fanout);
  TEST_PERFORMANCE0(filter, p_async, test_parent_threadpool);

  p_async.description = "async: main thread + 6, 100000 tasks @ 0us";
  p_async.num_extra_threads          = 6;
  p_async.num_tasks                  = 100000;
  p_async.sleepy_task_cadence        = 0;
  p_async.task_duration              = std::chrono::microseconds{0};
  p_async.sleepy_task_sleep_duration = std::chrono::microseconds{0};
  TEST_PERFORMANCE0(filter, p_async, test_common_threadpool); p_async.description = "";
  TEST_PERFORMANCE0(filter, p_async, test_async_threadpool);
  TEST_PERFORMANCE0(filter, p_async, test_async_threadpool_with_fanout);
  TEST_PERFORMANCE0(filter, p_async, test_parent_threadpool);

  p_async.description = "async: main thread + 2, 100000 task @ 0us";
  p_async.num_extra_threads          = 2;
  p_async.num_tasks                  = 100000;
  p_async.sleepy_task_cadence        = 0;
  p_async.task_duration              = std::chrono::microseconds{0};
  p_async.sleepy_task_sleep_duration = std::chrono::microseconds{0};
  TEST_PERFORMANCE0(filter, p_async, test_common_threadpool); p_async.description = "";
  TEST_PERFORMANCE0(filter, p_async, test_async_threadpool);
  TEST_PERFORMANCE0(filter, p_async, test_async_threadpool_with_fanout);
  TEST_PERFORMANCE0(filter, p_async, test_parent_threadpool);

  p_async.description = "async: main thread + 1, 100000 task @ 0us";
  p_async.num_extra_threads          = 1;
  p_async.num_tasks                  = 100000;
  p_async.sleepy_task_cadence        = 0;
  p_async.task_duration              = std::chrono::microseconds{0};
  p_async.sleepy_task_sleep_duration = std::chrono::microseconds{0};
  TEST_PERFORMANCE0(filter, p_async, test_common_threadpool); p_async.description = "";
  TEST_PERFORMANCE0(filter, p_async, test_async_threadpool);
  TEST_PERFORMANCE0(filter, p_async, test_async_threadpool_with_fanout);
  TEST_PERFORMANCE0(filter, p_async, test_parent_threadpool);

  p_async.description = "async: main thread, 100000 task @ 0us";
  p_async.num_extra_threads          = 0;
  p_async.num_tasks                  = 100000;
  p_async.sleepy_task_cadence        = 0;
  p_async.task_duration              = std::chrono::microseconds{0};
  p_async.sleepy_task_sleep_duration = std::chrono::microseconds{0};
  TEST_PERFORMANCE0(filter, p_async, test_common_threadpool); p_async.description = "";
  TEST_PERFORMANCE0(filter, p_async, test_async_threadpool);
  TEST_PERFORMANCE0(filter, p_async, test_async_threadpool_with_fanout);
  TEST_PERFORMANCE0(filter, p_async, test_parent_threadpool);

  p_async.description = "async: main thread + 6, 1000 tasks @ 100us, sleep every 5th for 100us";
  p_async.num_extra_threads          = 6;
  p_async.num_tasks                  = 1000;
  p_async.sleepy_task_cadence        = 5;
  p_async.task_duration              = std::chrono::microseconds{100};
  p_async.sleepy_task_sleep_duration = std::chrono::microseconds{100};
  TEST_PERFORMANCE0(filter, p_async, test_common_threadpool); p_async.description = "";
  TEST_PERFORMANCE0(filter, p_async, test_async_threadpool);
  TEST_PERFORMANCE0(filter, p_async, test_async_threadpool_with_fanout);
  TEST_PERFORMANCE0(filter, p_async, test_parent_threadpool);

  p_async.description = "async: main thread + 6, 1000 tasks @ 10us, sleep every 5th for 1000us";
  p_async.num_extra_threads          = 6;
  p_async.num_tasks                  = 1000;
  p_async.sleepy_task_cadence        = 5;
  p_async.task_duration              = std::chrono::microseconds{10};
  p_async.sleepy_task_sleep_duration = std::chrono::microseconds{1000};
  TEST_PERFORMANCE0(filter, p_async, test_common_threadpool); p_async.description = "";
  TEST_PERFORMANCE0(filter, p_async, test_async_threadpool);
  TEST_PERFORMANCE0(filter, p_async, test_async_threadpool_with_fanout);
  TEST_PERFORMANCE0(filter, p_async, test_parent_threadpool);

  // test done, save results
  if (p.core_params.td.get())
    p.core_params.td->save(false);


  // test deciphering address tags
  ParamsShuttleAddressTagDecipher p_address_tag_decipher;
  p_address_tag_decipher.core_params = p.core_params;
  p_address_tag_decipher.mode = AddressTagDecipherModes::ALL_SUCCESSFUL_DECIPHER;
  TEST_PERFORMANCE0(filter, p_address_tag_decipher, test_jamtis_address_tag_decipher_sp);
  p_address_tag_decipher.mode = AddressTagDecipherModes::NO_SUCCESSFUL_DECIPHER;
  TEST_PERFORMANCE0(filter, p_address_tag_decipher, test_jamtis_address_tag_decipher_sp);

  // test client-side scanning in a seraphis remote-scanning workflow
  ParamsShuttleScannerClient p_client_scan;
  p_client_scan.core_params = p.core_params;
  p_client_scan.mode = ScannerClientModes::ALL_FAKE;
  TEST_PERFORMANCE0(filter, p_client_scan, test_remote_scanner_client_scan_sp);
  p_client_scan.mode = ScannerClientModes::ONE_FAKE_TAG_MATCH;
  TEST_PERFORMANCE0(filter, p_client_scan, test_remote_scanner_client_scan_sp);
  p_client_scan.mode = ScannerClientModes::ONE_OWNED;
  TEST_PERFORMANCE0(filter, p_client_scan, test_remote_scanner_client_scan_sp);

  // test done, save results
  if (p.core_params.td.get())
    p.core_params.td->save(false);


  // test blake2b
  TEST_PERFORMANCE2(filter, p, test_blake2b, 32, false);
  TEST_PERFORMANCE2(filter, p, test_blake2b, 32, true);
  TEST_PERFORMANCE2(filter, p, test_blake2b, 200, false);
  TEST_PERFORMANCE2(filter, p, test_blake2b, 200, true);
  TEST_PERFORMANCE2(filter, p, test_blake2b, 2000, false);
  TEST_PERFORMANCE2(filter, p, test_blake2b, 2000, true);
  TEST_PERFORMANCE2(filter, p, test_blake2b, 16384, false);
  TEST_PERFORMANCE2(filter, p, test_blake2b, 16384, true);

  TEST_PERFORMANCE2(filter, p, test_blake2b_streaming, 32, false);
  TEST_PERFORMANCE2(filter, p, test_blake2b_streaming, 32, true);
  TEST_PERFORMANCE2(filter, p, test_blake2b_streaming, 200, false);
  TEST_PERFORMANCE2(filter, p, test_blake2b_streaming, 200, true);
  TEST_PERFORMANCE2(filter, p, test_blake2b_streaming, 2000, false);
  TEST_PERFORMANCE2(filter, p, test_blake2b_streaming, 2000, true);
  TEST_PERFORMANCE2(filter, p, test_blake2b_streaming, 16384, false);
  TEST_PERFORMANCE2(filter, p, test_blake2b_streaming, 16384, true);

  // test done, save results
  if (p.core_params.td.get())
    p.core_params.td->save(false);


  // test view scan performance with view tags
  ParamsShuttleViewScan p_view_scan;
  p_view_scan.core_params = p.core_params;

  TEST_PERFORMANCE0(filter, p_view_scan, test_view_scan_cn);
  TEST_PERFORMANCE0(filter, p_view_scan, test_view_scan_cn_optimized);
  TEST_PERFORMANCE0(filter, p_view_scan, test_view_scan_sp);
  p_view_scan.test_view_tag_check = true;
  TEST_PERFORMANCE0(filter, p_view_scan, test_view_scan_cn);
  TEST_PERFORMANCE0(filter, p_view_scan, test_view_scan_cn_optimized);
  TEST_PERFORMANCE0(filter, p_view_scan, test_view_scan_sp);

  // test done, save results
  if (p.core_params.td.get())
    p.core_params.td->save(false);


  /// BP/BP+ tests for comparisons with zkcrypto benchmarks
  TEST_PERFORMANCE6(filter, p, test_aggregated_bulletproof, true, 1, 1, 1, 0, 1); // 1x 1
  TEST_PERFORMANCE6(filter, p, test_aggregated_bulletproof, true, 2, 1, 1, 0, 1); // 1x 2
  TEST_PERFORMANCE6(filter, p, test_aggregated_bulletproof, true, 4, 1, 1, 0, 1); // 1x 4
  TEST_PERFORMANCE6(filter, p, test_aggregated_bulletproof, true, 8, 1, 1, 0, 1); // 1x 8
  TEST_PERFORMANCE6(filter, p, test_aggregated_bulletproof, true, 16, 1, 1, 0, 1); // 1x 16

  ParamsShuttleBPPAgg p_bpp_agg;
  p_bpp_agg = {p.core_params, true, {1}, {1}};
  TEST_PERFORMANCE0(filter, p_bpp_agg, test_aggregated_bulletproof_plus);  // 1x 1
  p_bpp_agg = {p.core_params, true, {2}, {1}};
  TEST_PERFORMANCE0(filter, p_bpp_agg, test_aggregated_bulletproof_plus);  // 1x 2
  p_bpp_agg = {p.core_params, true, {4}, {1}};
  TEST_PERFORMANCE0(filter, p_bpp_agg, test_aggregated_bulletproof_plus);  // 1x 4
  p_bpp_agg = {p.core_params, true, {8}, {1}};
  TEST_PERFORMANCE0(filter, p_bpp_agg, test_aggregated_bulletproof_plus);  // 1x 8
  p_bpp_agg = {p.core_params, true, {16}, {1}};
  TEST_PERFORMANCE0(filter, p_bpp_agg, test_aggregated_bulletproof_plus);  // 1x 16


/*
  /// BP+ tests, looking at DDOS risks
  /// - does adding one large aggregate proof among many small aggregation proofs cause worse average verification
  //    performance when batching than if the large proof were validated separately?
  ParamsShuttleBPPAgg p_bpp_agg;
  std::size_t max_bpp_size{32};

  p_bpp_agg = {p.core_params, true, {2}, {8}};
  TEST_PERFORMANCE0(filter, p_bpp_agg, test_aggregated_bulletproof_plus);  // 8x 2
  p_bpp_agg = {p.core_params, true, {max_bpp_size}, {8}};
  TEST_PERFORMANCE0(filter, p_bpp_agg, test_aggregated_bulletproof_plus);  // 8x 32
  p_bpp_agg = {p.core_params, true, {max_bpp_size}, {1}};
  TEST_PERFORMANCE0(filter, p_bpp_agg, test_aggregated_bulletproof_plus);  // 1x 32
  p_bpp_agg = {p.core_params, true, {2,max_bpp_size}, {7,1}};
  TEST_PERFORMANCE0(filter, p_bpp_agg, test_aggregated_bulletproof_plus);  // 7x 2, 1x 32
  p_bpp_agg = {p.core_params, true, {2,max_bpp_size}, {8,8}};
  TEST_PERFORMANCE0(filter, p_bpp_agg, test_aggregated_bulletproof_plus);  // 8x 2, 8x 32
  p_bpp_agg = {p.core_params, true, {2}, {16}};
  TEST_PERFORMANCE0(filter, p_bpp_agg, test_aggregated_bulletproof_plus);  // 16x 2
  p_bpp_agg = {p.core_params, true, {max_bpp_size}, {16}};
  TEST_PERFORMANCE0(filter, p_bpp_agg, test_aggregated_bulletproof_plus);  // 16x 32
  p_bpp_agg = {p.core_params, true, {2,max_bpp_size}, {15,1}};
  TEST_PERFORMANCE0(filter, p_bpp_agg, test_aggregated_bulletproof_plus);  // 15x 2, 1x 32

  p_bpp_agg = {p.core_params, true, {16}, {16}};
  TEST_PERFORMANCE0(filter, p_bpp_agg, test_aggregated_bulletproof_plus);  // 16x 16
  p_bpp_agg = {p.core_params, true, {max_bpp_size}, {16}};
  TEST_PERFORMANCE0(filter, p_bpp_agg, test_aggregated_bulletproof_plus);  // 16x 32
  p_bpp_agg = {p.core_params, true, {16,max_bpp_size}, {16,16}};
  TEST_PERFORMANCE0(filter, p_bpp_agg, test_aggregated_bulletproof_plus);  // 16x 16, 16x 32
*/

  /// mock tx performance tests
  SpTxPerfIncrementer incrementer;
  ParamsShuttleSpTx p_seraphis_tx;
  p_seraphis_tx.core_params = p.core_params;


  /// TEST: SpTxSquashedV1
  // notes:
  // - legacy inputs are not batched in any way
  // - seraphis input membership proofs and range proofs can be batched with output range proofs

  // TEST 1: SpTxSquashedV1 {legacy inputs}
  incrementer = {
      {1}, //batch sizes
      {1, 2, 4, 7, 12, 16}, //legacy in counts
      {0}, //sp in counts
      {2}, //out counts
      {16}, //legacy ring size
      {2}, //decomp n
      {2} //decomp m limits
    };
  while (incrementer.next(p_seraphis_tx))
  {
    // ignore n^m
    if (p_seraphis_tx.n != 2 || p_seraphis_tx.m != 2)
      continue;

    TEST_PERFORMANCE1(filter, p_seraphis_tx, test_seraphis_tx, sp::SpTxSquashedV1);
  }
  // test done, save results
  if (p.core_params.td.get())
    p.core_params.td->save(false);

  // TEST 2: SpTxSquashedV1 {legacy ring size}
  incrementer = {
      {1}, //batch sizes
      {1}, //legacy in counts
      {0}, //sp in counts
      {2}, //out counts
      {1, 2, 4, 7, 12, 16, 25}, //legacy ring size
      {2}, //decomp n
      {2} //decomp m limits
    };
  while (incrementer.next(p_seraphis_tx))
  {
    // ignore n^m
    if (p_seraphis_tx.n != 2 || p_seraphis_tx.m != 2)
      continue;

    TEST_PERFORMANCE1(filter, p_seraphis_tx, test_seraphis_tx, sp::SpTxSquashedV1);
  }
  // test done, save results
  if (p.core_params.td.get())
    p.core_params.td->save(false);

  // TEST 3: SpTxSquashedV1 {sp inputs}
  incrementer = {
      {1}, //batch sizes
      {0}, //legacy in counts
      {1, 2, 4, 7, 12, 16}, //seraphis in counts
      {2}, //out counts
      {2}, //legacy ring size
      {2}, //decomp n
      {7} //decomp m limits
    };
  while (incrementer.next(p_seraphis_tx))
  {
    // only decomp 2^7
    if (p_seraphis_tx.n >= 2 && p_seraphis_tx.m == 7)
      TEST_PERFORMANCE1(filter, p_seraphis_tx, test_seraphis_tx, sp::SpTxSquashedV1);
  }
  // test done, save results
  if (p.core_params.td.get())
    p.core_params.td->save(false);

  // TEST 4: SpTxSquashedV1 {decomp}
  incrementer = {
      {1}, //batch sizes
      {0}, //legacy in counts
      {2}, //seraphis in counts
      {2}, //out counts
      {2}, //legacy ring size
      {2, 3}, //decomp n
      {12, 7} //decomp m limits
    };
  while (incrementer.next(p_seraphis_tx))
  {
    if (p_seraphis_tx.n >= 2 && p_seraphis_tx.m >= 2)
      TEST_PERFORMANCE1(filter, p_seraphis_tx, test_seraphis_tx, sp::SpTxSquashedV1);
  }
  // test done, save results
  if (p.core_params.td.get())
    p.core_params.td->save(false);

  // TEST 5: SpTxSquashedV1 {decomp 2-series, batch size 25}
  incrementer = {
      {25}, //batch sizes
      {0}, //legacy in counts
      {2}, //seraphis in counts
      {2}, //out counts
      {2}, //legacy ring size
      {2}, //decomp n
      {12} //decomp m limits
    };
  while (incrementer.next(p_seraphis_tx))
  {
    if (p_seraphis_tx.n >= 2 && p_seraphis_tx.m >= 2)
      TEST_PERFORMANCE1(filter, p_seraphis_tx, test_seraphis_tx, sp::SpTxSquashedV1);
  }
  // test done, save results
  if (p.core_params.td.get())
    p.core_params.td->save(false);

  // TEST 6: SpTxSquashedV1 {outputs, batch size 1}
  incrementer = {
      {1}, //batch sizes
      {0}, //legacy in counts
      {1, 2, 4, 7, 12, 16}, //seraphis in counts
      {1, 2, 4, 7, 12, 16}, //out counts
      {2}, //legacy ring size
      {2}, //decomp n
      {7} //decomp m limits
    };
  while (incrementer.next(p_seraphis_tx))
  {
    // only decomp 2^7
    if (p_seraphis_tx.n >= 2 && p_seraphis_tx.m == 7)
      TEST_PERFORMANCE1(filter, p_seraphis_tx, test_seraphis_tx, sp::SpTxSquashedV1);
  }
  // test done, save results
  if (p.core_params.td.get())
    p.core_params.td->save(false);

  // TEST 7: SpTxSquashedV1 {16in/out, batch sizes 7, 15}
  incrementer = {
      {7, 15}, //batch sizes
      {0}, //legacy in counts
      {16}, //seraphis in counts
      {16}, //out counts
      {2}, //legacy ring size
      {2}, //decomp n
      {7} //decomp m limits
    };
  while (incrementer.next(p_seraphis_tx))
  {
    // only decomp 2^7
    if (p_seraphis_tx.n >= 2 && p_seraphis_tx.m == 7)
      TEST_PERFORMANCE1(filter, p_seraphis_tx, test_seraphis_tx, sp::SpTxSquashedV1);
  }
  // test done, save results
  if (p.core_params.td.get())
    p.core_params.td->save(false);

  // TEST 8: SpTxSquashedV1 {outputs, batch size 25}
  incrementer = {
      {25}, //batch sizes
      {0}, //legacy in counts
      {1, 2, 4, 7, 12, 16}, //seraphis in counts
      {1, 2, 4, 7, 12, 16}, //out counts
      {2}, //legacy ring size
      {2}, //decomp n
      {7} //decomp m limits
    };
  while (incrementer.next(p_seraphis_tx))
  {
    // only decomp 2^7
    if (p_seraphis_tx.n >= 2 && p_seraphis_tx.m == 7)
      TEST_PERFORMANCE1(filter, p_seraphis_tx, test_seraphis_tx, sp::SpTxSquashedV1);
  }
  // test done, save results
  if (p.core_params.td.get())
    p.core_params.td->save(false);
  /// TEST: SpTxSquashedV1 (end)


/*
  TEST_PERFORMANCE3(filter, p, test_balance_check, BalanceCheckType::MultiexpSub, 1, 1);
  TEST_PERFORMANCE3(filter, p, test_balance_check, BalanceCheckType::MultiexpComp, 1, 1);
  TEST_PERFORMANCE3(filter, p, test_balance_check, BalanceCheckType::Rctops, 1, 1);
  TEST_PERFORMANCE3(filter, p, test_balance_check, BalanceCheckType::MultiexpSub, 1, 2);
  TEST_PERFORMANCE3(filter, p, test_balance_check, BalanceCheckType::MultiexpComp, 1, 2);
  TEST_PERFORMANCE3(filter, p, test_balance_check, BalanceCheckType::Rctops, 1, 2);
  TEST_PERFORMANCE3(filter, p, test_balance_check, BalanceCheckType::MultiexpSub, 2, 1);
  TEST_PERFORMANCE3(filter, p, test_balance_check, BalanceCheckType::MultiexpComp, 2, 1);
  TEST_PERFORMANCE3(filter, p, test_balance_check, BalanceCheckType::Rctops, 2, 1);
  TEST_PERFORMANCE3(filter, p, test_balance_check, BalanceCheckType::MultiexpSub, 16, 16);
  TEST_PERFORMANCE3(filter, p, test_balance_check, BalanceCheckType::MultiexpComp, 16, 16);
  TEST_PERFORMANCE3(filter, p, test_balance_check, BalanceCheckType::Rctops, 16, 16);


  // test groth/bootle proofs

  TEST_PERFORMANCE4(filter, p, test_grootle, 2, 3, 2, false);
  TEST_PERFORMANCE4(filter, p, test_grootle, 2, 3, 2, true);
  TEST_PERFORMANCE4(filter, p, test_grootle, 2, 4, 2, false);
  TEST_PERFORMANCE4(filter, p, test_grootle, 2, 5, 2, false);
  TEST_PERFORMANCE4(filter, p, test_grootle, 2, 6, 2, true);
  TEST_PERFORMANCE4(filter, p, test_grootle, 2, 6, 2, false);
  TEST_PERFORMANCE4(filter, p, test_grootle, 2, 7, 2, false);
  TEST_PERFORMANCE4(filter, p, test_grootle, 2, 8, 2, false);

  TEST_PERFORMANCE4(filter, p, test_grootle, 3, 3, 2, false);
  TEST_PERFORMANCE4(filter, p, test_grootle, 3, 4, 2, false);
  TEST_PERFORMANCE4(filter, p, test_grootle, 3, 5, 2, false);



  TEST_PERFORMANCE3(filter, p, test_construct_tx, 1, 1, false);
  TEST_PERFORMANCE3(filter, p, test_construct_tx, 1, 2, false);
  TEST_PERFORMANCE3(filter, p, test_construct_tx, 1, 10, false);
  TEST_PERFORMANCE3(filter, p, test_construct_tx, 1, 100, false);
  TEST_PERFORMANCE3(filter, p, test_construct_tx, 1, 1000, false);

  TEST_PERFORMANCE3(filter, p, test_construct_tx, 2, 1, false);
  TEST_PERFORMANCE3(filter, p, test_construct_tx, 2, 2, false);
  TEST_PERFORMANCE3(filter, p, test_construct_tx, 2, 10, false);
  TEST_PERFORMANCE3(filter, p, test_construct_tx, 2, 100, false);

  TEST_PERFORMANCE3(filter, p, test_construct_tx, 10, 1, false);
  TEST_PERFORMANCE3(filter, p, test_construct_tx, 10, 2, false);
  TEST_PERFORMANCE3(filter, p, test_construct_tx, 10, 10, false);
  TEST_PERFORMANCE3(filter, p, test_construct_tx, 10, 100, false);

  TEST_PERFORMANCE3(filter, p, test_construct_tx, 100, 1, false);
  TEST_PERFORMANCE3(filter, p, test_construct_tx, 100, 2, false);
  TEST_PERFORMANCE3(filter, p, test_construct_tx, 100, 10, false);
  TEST_PERFORMANCE3(filter, p, test_construct_tx, 100, 100, false);

  TEST_PERFORMANCE3(filter, p, test_construct_tx, 2, 1, true);
  TEST_PERFORMANCE3(filter, p, test_construct_tx, 2, 2, true);
  TEST_PERFORMANCE3(filter, p, test_construct_tx, 2, 10, true);

  TEST_PERFORMANCE3(filter, p, test_construct_tx, 10, 1, true);
  TEST_PERFORMANCE3(filter, p, test_construct_tx, 10, 2, true);
  TEST_PERFORMANCE3(filter, p, test_construct_tx, 10, 10, true);

  TEST_PERFORMANCE3(filter, p, test_construct_tx, 100, 1, true);
  TEST_PERFORMANCE3(filter, p, test_construct_tx, 100, 2, true);
  TEST_PERFORMANCE3(filter, p, test_construct_tx, 100, 10, true);

  TEST_PERFORMANCE5(filter, p, test_construct_tx, 2, 1, true, rct::RangeProofPaddedBulletproof, 2);
  TEST_PERFORMANCE5(filter, p, test_construct_tx, 2, 2, true, rct::RangeProofPaddedBulletproof, 2);
  TEST_PERFORMANCE5(filter, p, test_construct_tx, 2, 10, true, rct::RangeProofPaddedBulletproof, 2);

  TEST_PERFORMANCE5(filter, p, test_construct_tx, 10, 1, true, rct::RangeProofPaddedBulletproof, 2);
  TEST_PERFORMANCE5(filter, p, test_construct_tx, 10, 2, true, rct::RangeProofPaddedBulletproof, 2);
  TEST_PERFORMANCE5(filter, p, test_construct_tx, 10, 10, true, rct::RangeProofPaddedBulletproof, 2);

  TEST_PERFORMANCE5(filter, p, test_construct_tx, 100, 1, true, rct::RangeProofPaddedBulletproof, 2);
  TEST_PERFORMANCE5(filter, p, test_construct_tx, 100, 2, true, rct::RangeProofPaddedBulletproof, 2);
  TEST_PERFORMANCE5(filter, p, test_construct_tx, 100, 10, true, rct::RangeProofPaddedBulletproof, 2);

  TEST_PERFORMANCE3(filter, p, test_check_tx_signature, 1, 2, false);
  TEST_PERFORMANCE3(filter, p, test_check_tx_signature, 2, 2, false);
  TEST_PERFORMANCE3(filter, p, test_check_tx_signature, 10, 2, false);
  TEST_PERFORMANCE3(filter, p, test_check_tx_signature, 100, 2, false);
  TEST_PERFORMANCE3(filter, p, test_check_tx_signature, 2, 10, false);

  TEST_PERFORMANCE4(filter, p, test_check_tx_signature, 2, 2, true, rct::RangeProofBorromean);
  TEST_PERFORMANCE4(filter, p, test_check_tx_signature, 10, 2, true, rct::RangeProofBorromean);
  TEST_PERFORMANCE4(filter, p, test_check_tx_signature, 100, 2, true, rct::RangeProofBorromean);
  TEST_PERFORMANCE4(filter, p, test_check_tx_signature, 2, 10, true, rct::RangeProofBorromean);

  TEST_PERFORMANCE5(filter, p, test_check_tx_signature, 2, 2, true, rct::RangeProofPaddedBulletproof, 2);
  TEST_PERFORMANCE5(filter, p, test_check_tx_signature, 2, 2, true, rct::RangeProofMultiOutputBulletproof, 2);
  TEST_PERFORMANCE5(filter, p, test_check_tx_signature, 10, 2, true, rct::RangeProofPaddedBulletproof, 2);
  TEST_PERFORMANCE5(filter, p, test_check_tx_signature, 10, 2, true, rct::RangeProofMultiOutputBulletproof, 2);
  TEST_PERFORMANCE5(filter, p, test_check_tx_signature, 100, 2, true, rct::RangeProofPaddedBulletproof, 2);
  TEST_PERFORMANCE5(filter, p, test_check_tx_signature, 100, 2, true, rct::RangeProofMultiOutputBulletproof, 2);
  TEST_PERFORMANCE5(filter, p, test_check_tx_signature, 2, 10, true, rct::RangeProofPaddedBulletproof, 2);
  TEST_PERFORMANCE5(filter, p, test_check_tx_signature, 2, 10, true, rct::RangeProofMultiOutputBulletproof, 2);

  TEST_PERFORMANCE3(filter, p, test_check_tx_signature_aggregated_bulletproofs, 2, 2, 64);
  TEST_PERFORMANCE3(filter, p, test_check_tx_signature_aggregated_bulletproofs, 10, 2, 64);
  TEST_PERFORMANCE3(filter, p, test_check_tx_signature_aggregated_bulletproofs, 100, 2, 64);
  TEST_PERFORMANCE3(filter, p, test_check_tx_signature_aggregated_bulletproofs, 2, 10, 64);

  TEST_PERFORMANCE4(filter, p, test_check_tx_signature_aggregated_bulletproofs, 2, 2, 62, 4);
  TEST_PERFORMANCE4(filter, p, test_check_tx_signature_aggregated_bulletproofs, 10, 2, 62, 4);
  TEST_PERFORMANCE4(filter, p, test_check_tx_signature_aggregated_bulletproofs, 2, 2, 56, 16);
  TEST_PERFORMANCE4(filter, p, test_check_tx_signature_aggregated_bulletproofs, 10, 2, 56, 16);

  TEST_PERFORMANCE4(filter, p, test_check_hash, 0, 1, 0, 1);
  TEST_PERFORMANCE4(filter, p, test_check_hash, 0, 0xffffffffffffffff, 0, 0xffffffffffffffff);
  TEST_PERFORMANCE4(filter, p, test_check_hash, 0, 0xffffffffffffffff, 0, 1);
  TEST_PERFORMANCE4(filter, p, test_check_hash, 1, 0, 1, 0);
  TEST_PERFORMANCE4(filter, p, test_check_hash, 1, 0, 0, 1);
  TEST_PERFORMANCE4(filter, p, test_check_hash, 0xffffffffffffffff, 0xffffffffffffffff, 0, 1);
  TEST_PERFORMANCE4(filter, p, test_check_hash, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff);

  TEST_PERFORMANCE0(filter, p, test_is_out_to_acc);
  TEST_PERFORMANCE0(filter, p, test_is_out_to_acc_precomp);
  TEST_PERFORMANCE2(filter, p, test_out_can_be_to_acc, false, true); // no view tag, owned
  TEST_PERFORMANCE2(filter, p, test_out_can_be_to_acc, true, false); // use view tag, not owned
  TEST_PERFORMANCE2(filter, p, test_out_can_be_to_acc, true, true); // use view tag, owned
  TEST_PERFORMANCE0(filter, p, test_generate_key_image_helper);
  TEST_PERFORMANCE0(filter, p, test_generate_key_derivation);
  TEST_PERFORMANCE0(filter, p, test_generate_key_image);
  TEST_PERFORMANCE0(filter, p, test_derive_public_key);
  TEST_PERFORMANCE0(filter, p, test_derive_secret_key);
  TEST_PERFORMANCE0(filter, p, test_ge_frombytes_vartime);
  TEST_PERFORMANCE0(filter, p, test_ge_tobytes);
  TEST_PERFORMANCE0(filter, p, test_generate_keypair);
  TEST_PERFORMANCE0(filter, p, test_sc_reduce32);
  TEST_PERFORMANCE0(filter, p, test_sc_check);
  TEST_PERFORMANCE1(filter, p, test_signature, false);
  TEST_PERFORMANCE1(filter, p, test_signature, true);
  TEST_PERFORMANCE0(filter, p, test_derive_view_tag);

  TEST_PERFORMANCE2(filter, p, test_wallet2_expand_subaddresses, 50, 200);

  TEST_PERFORMANCE1(filter, p, test_cn_slow_hash, 0);
  TEST_PERFORMANCE1(filter, p, test_cn_slow_hash, 1);
  TEST_PERFORMANCE1(filter, p, test_cn_slow_hash, 2);
  TEST_PERFORMANCE1(filter, p, test_cn_slow_hash, 4);
  TEST_PERFORMANCE1(filter, p, test_cn_fast_hash, 32);
  TEST_PERFORMANCE1(filter, p, test_cn_fast_hash, 16384);

  TEST_PERFORMANCE3(filter, p, test_sig_mlsag, 4, 2, 2); // MLSAG verification
  TEST_PERFORMANCE3(filter, p, test_sig_mlsag, 8, 2, 2);
  TEST_PERFORMANCE3(filter, p, test_sig_mlsag, 16, 2, 2);
  TEST_PERFORMANCE3(filter, p, test_sig_mlsag, 32, 2, 2);
  TEST_PERFORMANCE3(filter, p, test_sig_mlsag, 64, 2, 2);
  TEST_PERFORMANCE3(filter, p, test_sig_mlsag, 128, 2, 2);
  TEST_PERFORMANCE3(filter, p, test_sig_mlsag, 256, 2, 2);
  TEST_PERFORMANCE3(filter, p, test_sig_clsag, 4, 2, 2); // CLSAG verification
  TEST_PERFORMANCE3(filter, p, test_sig_clsag, 8, 2, 2);
  TEST_PERFORMANCE3(filter, p, test_sig_clsag, 16, 2, 2);
  TEST_PERFORMANCE3(filter, p, test_sig_clsag, 32, 2, 2);
  TEST_PERFORMANCE3(filter, p, test_sig_clsag, 64, 2, 2);
  TEST_PERFORMANCE3(filter, p, test_sig_clsag, 128, 2, 2);
  TEST_PERFORMANCE3(filter, p, test_sig_clsag, 256, 2, 2);

  TEST_PERFORMANCE2(filter, p, test_ringct_mlsag, 11, false);
  TEST_PERFORMANCE2(filter, p, test_ringct_mlsag, 11, true);

  TEST_PERFORMANCE2(filter, p, test_equality, memcmp32, true);
  TEST_PERFORMANCE2(filter, p, test_equality, memcmp32, false);
  TEST_PERFORMANCE2(filter, p, test_equality, verify32, false);
  TEST_PERFORMANCE2(filter, p, test_equality, verify32, false);

  TEST_PERFORMANCE1(filter, p, test_range_proof, true);
  TEST_PERFORMANCE1(filter, p, test_range_proof, false);
  */

  /*
  // 16 amounts
  // 1 proof - 16 amounts
  TEST_PERFORMANCE2(filter, p, test_bulletproof_plus, true, 16);
  // 16 proofs - 1 amount
  TEST_PERFORMANCE6(filter, p, test_aggregated_bulletproof_plus, true, 1, 1, 1, 0, 16);

  // 1 proof - 32 amounts
  TEST_PERFORMANCE2(filter, p, test_bulletproof_plus, true, 32);
  // 2 proofs - 16 amounts
  TEST_PERFORMANCE6(filter, p, test_aggregated_bulletproof_plus, true, 16, 1, 1, 0, 2);

  // batching vs aggregating
  // 5 proofs - 16 amounts
  TEST_PERFORMANCE6(filter, p, test_aggregated_bulletproof_plus, true, 16, 1, 1, 0, 5);
  // 10 proofs - 8 amounts
  TEST_PERFORMANCE6(filter, p, test_aggregated_bulletproof_plus, true, 8, 1, 1, 0, 10);
  // 20 proofs - 4 amounts
  TEST_PERFORMANCE6(filter, p, test_aggregated_bulletproof_plus, true, 4, 1, 1, 0, 20);
  // 40 proofs - 2 amounts
  TEST_PERFORMANCE6(filter, p, test_aggregated_bulletproof_plus, true, 2, 1, 1, 0, 40);
  // 80 proofs - 1 amount
  TEST_PERFORMANCE6(filter, p, test_aggregated_bulletproof_plus, true, 1, 1, 1, 0, 80);

  TEST_PERFORMANCE2(filter, p, test_bulletproof_plus, true, 1); // 1 bulletproof_plus with 1 amount
  TEST_PERFORMANCE2(filter, p, test_bulletproof_plus, false, 1);

  TEST_PERFORMANCE2(filter, p, test_bulletproof_plus, true, 2); // 1 bulletproof_plus with 2 amounts
  TEST_PERFORMANCE2(filter, p, test_bulletproof_plus, false, 2);

  TEST_PERFORMANCE2(filter, p, test_bulletproof_plus, true, 15); // 1 bulletproof_plus with 15 amounts
  TEST_PERFORMANCE2(filter, p, test_bulletproof_plus, false, 15);

  TEST_PERFORMANCE6(filter, p, test_aggregated_bulletproof_plus, false, 2, 1, 1, 0, 4);
  TEST_PERFORMANCE6(filter, p, test_aggregated_bulletproof_plus, true, 2, 1, 1, 0, 4); // 4 proofs, each with 2 amounts
  TEST_PERFORMANCE6(filter, p, test_aggregated_bulletproof_plus, false, 8, 1, 1, 0, 4);
  TEST_PERFORMANCE6(filter, p, test_aggregated_bulletproof_plus, true, 8, 1, 1, 0, 4); // 4 proofs, each with 8 amounts
  TEST_PERFORMANCE6(filter, p, test_aggregated_bulletproof_plus, false, 1, 1, 2, 0, 4);
  TEST_PERFORMANCE6(filter, p, test_aggregated_bulletproof_plus, true, 1, 1, 2, 0, 4); // 4 proofs with 1, 2, 4, 8 amounts
  TEST_PERFORMANCE6(filter, p, test_aggregated_bulletproof_plus, false, 1, 8, 1, 1, 4);
  TEST_PERFORMANCE6(filter, p, test_aggregated_bulletproof_plus, true, 1, 8, 1, 1, 4); // 32 proofs, with 1, 2, 3, 4 amounts, 8 of each
  TEST_PERFORMANCE6(filter, p, test_aggregated_bulletproof_plus, false, 2, 1, 1, 0, 64);
  TEST_PERFORMANCE6(filter, p, test_aggregated_bulletproof_plus, true, 2, 1, 1, 0, 64); // 64 proof, each with 2 amounts

  // 16 inputs
  TEST_PERFORMANCE2(filter, p, test_bulletproof, true, 1); // 1 bulletproof with 1 amount
  TEST_PERFORMANCE2(filter, p, test_bulletproof, false, 1);

  TEST_PERFORMANCE2(filter, p, test_bulletproof, true, 2); // 1 bulletproof with 2 amounts
  TEST_PERFORMANCE2(filter, p, test_bulletproof, false, 2);

  TEST_PERFORMANCE2(filter, p, test_bulletproof, true, 15); // 1 bulletproof with 15 amounts
  TEST_PERFORMANCE2(filter, p, test_bulletproof, false, 15);

  TEST_PERFORMANCE6(filter, p, test_aggregated_bulletproof, false, 2, 1, 1, 0, 4);
  TEST_PERFORMANCE6(filter, p, test_aggregated_bulletproof, true, 2, 1, 1, 0, 4); // 4 proofs, each with 2 amounts
  TEST_PERFORMANCE6(filter, p, test_aggregated_bulletproof, false, 8, 1, 1, 0, 4);
  TEST_PERFORMANCE6(filter, p, test_aggregated_bulletproof, true, 8, 1, 1, 0, 4); // 4 proofs, each with 8 amounts
  TEST_PERFORMANCE6(filter, p, test_aggregated_bulletproof, false, 1, 1, 2, 0, 4);
  TEST_PERFORMANCE6(filter, p, test_aggregated_bulletproof, true, 1, 1, 2, 0, 4); // 4 proofs with 1, 2, 4, 8 amounts
  TEST_PERFORMANCE6(filter, p, test_aggregated_bulletproof, false, 1, 8, 1, 1, 4);
  TEST_PERFORMANCE6(filter, p, test_aggregated_bulletproof, true, 1, 8, 1, 1, 4); // 32 proofs, with 1, 2, 3, 4 amounts, 8 of each
  TEST_PERFORMANCE6(filter, p, test_aggregated_bulletproof, false, 2, 1, 1, 0, 64);
  TEST_PERFORMANCE6(filter, p, test_aggregated_bulletproof, true, 2, 1, 1, 0, 64); // 64 proof, each with 2 amounts



  TEST_PERFORMANCE1(filter, p, test_crypto_ops, op_sc_add);
  TEST_PERFORMANCE1(filter, p, test_crypto_ops, op_sc_sub);
  TEST_PERFORMANCE1(filter, p, test_crypto_ops, op_sc_mul);
  TEST_PERFORMANCE1(filter, p, test_crypto_ops, op_ge_add_raw);
  TEST_PERFORMANCE1(filter, p, test_crypto_ops, op_ge_add_p3_p3);
  TEST_PERFORMANCE1(filter, p, test_crypto_ops, op_addKeys);
  TEST_PERFORMANCE1(filter, p, test_crypto_ops, op_scalarmultBase);
  TEST_PERFORMANCE1(filter, p, test_crypto_ops, op_scalarmultKey);
  TEST_PERFORMANCE1(filter, p, test_crypto_ops, op_scalarmultH);
  TEST_PERFORMANCE1(filter, p, test_crypto_ops, op_scalarmult8);
  TEST_PERFORMANCE1(filter, p, test_crypto_ops, op_scalarmult8_p3);
  TEST_PERFORMANCE1(filter, p, test_crypto_ops, op_ge_dsm_precomp);
  TEST_PERFORMANCE1(filter, p, test_crypto_ops, op_ge_double_scalarmult_base_vartime);
  TEST_PERFORMANCE1(filter, p, test_crypto_ops, op_ge_triple_scalarmult_base_vartime);
  TEST_PERFORMANCE1(filter, p, test_crypto_ops, op_ge_double_scalarmult_precomp_vartime);
  TEST_PERFORMANCE1(filter, p, test_crypto_ops, op_ge_triple_scalarmult_precomp_vartime);
  TEST_PERFORMANCE1(filter, p, test_crypto_ops, op_ge_double_scalarmult_precomp_vartime2);
  TEST_PERFORMANCE1(filter, p, test_crypto_ops, op_addKeys2);
  TEST_PERFORMANCE1(filter, p, test_crypto_ops, op_addKeys3);
  TEST_PERFORMANCE1(filter, p, test_crypto_ops, op_addKeys3_2);
  TEST_PERFORMANCE1(filter, p, test_crypto_ops, op_addKeys_aGbBcC);
  TEST_PERFORMANCE1(filter, p, test_crypto_ops, op_addKeys_aAbBcC);
  TEST_PERFORMANCE1(filter, p, test_crypto_ops, op_isInMainSubgroup);
  TEST_PERFORMANCE1(filter, p, test_crypto_ops, op_zeroCommitUncached);
  TEST_PERFORMANCE1(filter, p, test_crypto_ops, op_zeroCommitCached);

  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_bos_coster, 2);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_bos_coster, 4);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_bos_coster, 8);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_bos_coster, 16);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_bos_coster, 32);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_bos_coster, 64);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_bos_coster, 128);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_bos_coster, 256);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_bos_coster, 512);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_bos_coster, 1024);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_bos_coster, 2048);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_bos_coster, 4096);

  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus, 2);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus, 4);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus, 8);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus, 16);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus, 32);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus, 64);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus, 128);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus, 256);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus, 512);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus, 1024);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus, 2048);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus, 4096);

  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus_cached, 2);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus_cached, 4);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus_cached, 8);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus_cached, 16);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus_cached, 32);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus_cached, 64);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus_cached, 128);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus_cached, 256);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus_cached, 512);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus_cached, 1024);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus_cached, 2048);
  TEST_PERFORMANCE2(filter, p, test_multiexp, multiexp_straus_cached, 4096);
  */

  /*
#if 1
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 2, 1);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 4, 2);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 8, 2);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 16, 3);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 32, 4);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 64, 4);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 128, 5);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 256, 6);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 512, 7);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 1024, 7);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 2048, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 4096, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 2, 1);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 4, 2);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 8, 2);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 16, 3);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 32, 4);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 64, 4);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 128, 5);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 256, 6);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 512, 7);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 1024, 7);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 2048, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 4096, 9);
#else
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 2, 1);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 2, 2);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 2, 3);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 2, 4);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 2, 5);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 2, 6);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 2, 7);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 2, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 2, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 4, 1);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 4, 2);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 4, 3);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 4, 4);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 4, 5);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 4, 6);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 4, 7);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 4, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 4, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 8, 1);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 8, 2);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 8, 3);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 8, 4);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 8, 5);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 8, 6);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 8, 7);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 8, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 8, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 16, 1);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 16, 2);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 16, 3);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 16, 4);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 16, 5);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 16, 6);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 16, 7);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 16, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 16, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 32, 1);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 32, 2);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 32, 3);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 32, 4);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 32, 5);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 32, 6);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 32, 7);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 32, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 32, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 64, 1);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 64, 2);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 64, 3);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 64, 4);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 64, 5);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 64, 6);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 64, 7);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 64, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 64, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 128, 1);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 128, 2);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 128, 3);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 128, 4);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 128, 5);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 128, 6);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 128, 7);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 128, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 128, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 256, 1);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 256, 2);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 256, 3);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 256, 4);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 256, 5);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 256, 6);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 256, 7);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 256, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 256, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 512, 1);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 512, 2);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 512, 3);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 512, 4);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 512, 5);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 512, 6);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 512, 7);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 512, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 512, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 1024, 1);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 1024, 2);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 1024, 3);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 1024, 4);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 1024, 5);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 1024, 6);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 1024, 7);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 1024, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 1024, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 2048, 1);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 2048, 2);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 2048, 3);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 2048, 4);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 2048, 5);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 2048, 6);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 2048, 7);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 2048, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 2048, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 4096, 1);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 4096, 2);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 4096, 3);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 4096, 4);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 4096, 5);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 4096, 6);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 4096, 7);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 4096, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger_cached, 4096, 9);

  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 2, 1);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 2, 2);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 2, 3);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 2, 4);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 2, 5);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 2, 6);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 2, 7);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 2, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 2, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 4, 1);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 4, 2);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 4, 3);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 4, 4);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 4, 5);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 4, 6);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 4, 7);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 4, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 4, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 8, 1);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 8, 2);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 8, 3);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 8, 4);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 8, 5);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 8, 6);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 8, 7);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 8, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 8, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 16, 1);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 16, 2);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 16, 3);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 16, 4);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 16, 5);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 16, 6);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 16, 7);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 16, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 16, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 32, 1);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 32, 2);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 32, 3);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 32, 4);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 32, 5);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 32, 6);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 32, 7);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 32, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 32, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 64, 1);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 64, 2);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 64, 3);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 64, 4);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 64, 5);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 64, 6);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 64, 7);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 64, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 64, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 128, 1);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 128, 2);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 128, 3);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 128, 4);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 128, 5);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 128, 6);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 128, 7);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 128, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 128, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 256, 1);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 256, 2);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 256, 3);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 256, 4);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 256, 5);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 256, 6);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 256, 7);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 256, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 256, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 512, 1);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 512, 2);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 512, 3);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 512, 4);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 512, 5);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 512, 6);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 512, 7);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 512, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 512, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 1024, 1);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 1024, 2);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 1024, 3);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 1024, 4);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 1024, 5);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 1024, 6);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 1024, 7);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 1024, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 1024, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 2048, 1);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 2048, 2);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 2048, 3);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 2048, 4);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 2048, 5);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 2048, 6);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 2048, 7);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 2048, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 2048, 9);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 4096, 1);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 4096, 2);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 4096, 3);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 4096, 4);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 4096, 5);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 4096, 6);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 4096, 7);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 4096, 8);
  TEST_PERFORMANCE3(filter, p, test_multiexp, multiexp_pippenger, 4096, 9);
#endif
  */

  std::cout << "Tests finished. Elapsed time: " << timer.elapsed_ms() / 1000 << " sec" << std::endl;

  return 0;
  CATCH_ENTRY_L0("main", 1);
}

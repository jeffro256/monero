// Copyright (c) 2023, The Monero Project
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

#include <boost/filesystem.hpp>

#include "common/command_line.h"
#include "common/password.h"
#include "common/util.h"
#include "cryptonote_core/cryptonote_core.h"
#include "file_io_utils.h"
#include "serialization/binary_archive.h"
#include "serialization/containers.h"
#include "serialization/crypto.h"
#include "serialization/pair.h"
#include "serialization/string.h"
#include "serialization/variant.h"
#include "stats.h"
#include "version.h"
#include "wallet2_storage.h"

using namespace epee;
using namespace wallet2_basic;

namespace po = boost::program_options;

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "walletutil"

#define DEBUG_CACHE_FIELD_SIZE(name) \
    { \
        const size_t sersize = get_serialized_size(c.name); \
        MINFO("Wallet field " #name " takes up " << sersize << " bytes."); \
    } \

template <typename T>
size_t get_serialized_size(T &x)
{
    std::stringstream ss;
    binary_archive<true> ar(ss);
    CHECK_AND_ASSERT_THROW_MES(::serialization::serialize(ar, x), "Failed to serialize object");
    const size_t sersize = ss.str().size();
    return sersize;
}

int main(int argc, char* argv[])
{
    epee::string_tools::set_module_name_and_folder(argv[0]);

    uint32_t log_level = 0;

    tools::on_startup();

    boost::filesystem::path output_file_path;

    po::options_description desc_cmd_only("Command line options");
    po::options_description desc_cmd_sett("Command line options and settings options");
    const command_line::arg_descriptor<std::string> arg_log_level  = {"log-level",  "0-4 or categories", ""};
    const command_line::arg_descriptor<std::string, true> arg_wallet_file  = {"wallet-file", "path to wallet file"};

    command_line::add_arg(desc_cmd_sett, arg_log_level);
    command_line::add_arg(desc_cmd_sett, arg_wallet_file);
    command_line::add_arg(desc_cmd_only, command_line::arg_help);

    po::options_description desc_options("Allowed options");
    desc_options.add(desc_cmd_only).add(desc_cmd_sett);

    po::positional_options_description positional_options;
    positional_options.add(arg_wallet_file.name, 1);

    po::variables_map vm;
    bool r = command_line::handle_error_helper(desc_options, [&]()
    {
        auto parser = po::command_line_parser(argc, argv).options(desc_options).positional(positional_options);
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

    mlog_configure(mlog_get_default_log_path("monero-wallet2-size-debug.log"), true);
    if (!command_line::is_arg_defaulted(vm, arg_log_level))
        mlog_set_log(command_line::get_arg(vm, arg_log_level).c_str());
    else
        mlog_set_log(std::string(std::to_string(log_level) + ",walletutil:INFO").c_str());

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    std::string cache_blob;
    CHECK_AND_ASSERT_THROW_MES(file_io_utils::load_file_to_string(command_line::get_arg(vm, arg_wallet_file), cache_blob),
        "Could not read from file " << command_line::get_arg(vm, arg_wallet_file));

    const auto pwd_container = tools::password_container::prompt(false, "Enter wallet password");

    cache c = cache::load_from_memory(cache_blob, pwd_container->password(), {});

    DEBUG_CACHE_FIELD_SIZE(m_blockchain)
    DEBUG_CACHE_FIELD_SIZE(m_transfers)
    DEBUG_CACHE_FIELD_SIZE(m_account_public_address)
    DEBUG_CACHE_FIELD_SIZE(m_key_images)
    DEBUG_CACHE_FIELD_SIZE(m_unconfirmed_txs)
    DEBUG_CACHE_FIELD_SIZE(m_payments)
    DEBUG_CACHE_FIELD_SIZE(m_tx_keys)
    DEBUG_CACHE_FIELD_SIZE(m_confirmed_txs)
    DEBUG_CACHE_FIELD_SIZE(m_tx_notes)
    DEBUG_CACHE_FIELD_SIZE(m_unconfirmed_payments)
    DEBUG_CACHE_FIELD_SIZE(m_pub_keys)
    DEBUG_CACHE_FIELD_SIZE(m_address_book)
    DEBUG_CACHE_FIELD_SIZE(m_scanned_pool_txs[0])
    DEBUG_CACHE_FIELD_SIZE(m_scanned_pool_txs[1])
    DEBUG_CACHE_FIELD_SIZE(m_subaddresses)
    DEBUG_CACHE_FIELD_SIZE(m_subaddress_labels)
    DEBUG_CACHE_FIELD_SIZE(m_additional_tx_keys)
    DEBUG_CACHE_FIELD_SIZE(m_attributes)
    DEBUG_CACHE_FIELD_SIZE(m_account_tags)
    DEBUG_CACHE_FIELD_SIZE(m_ring_history_saved)
    DEBUG_CACHE_FIELD_SIZE(m_last_block_reward)
    DEBUG_CACHE_FIELD_SIZE(m_tx_device)
    DEBUG_CACHE_FIELD_SIZE(m_device_last_key_image_sync)
    DEBUG_CACHE_FIELD_SIZE(m_cold_key_images)
    DEBUG_CACHE_FIELD_SIZE(m_has_ever_refreshed_from_node)

    {
        std::stringstream ss;
        binary_archive<true> ar(ss);
        CHECK_AND_ASSERT_THROW_MES(::serialization::serialize(ar, c), "Failed to serialize cache");
        const size_t sersize = ss.str().size();
        MINFO("Grand Total: " << sersize);
    }

    MINFO("------------------------------------------------------------------");
    MINFO("------------------------------------------------------------------");
    
    std::vector<size_t> transfer_details_sizes;
    transfer_details_sizes.reserve(c.m_transfers.size());
    for (auto &t : c.m_transfers)
        transfer_details_sizes.push_back(get_serialized_size(t));
    
    Stats<size_t> transfer_stats(transfer_details_sizes);

    MINFO("Stats about m_transfers list:");
    MINFO("min: " << transfer_stats.get_min());
    MINFO("max: " << transfer_stats.get_max());
    MINFO("mean: " << transfer_stats.get_mean());
    MINFO("median: " << transfer_stats.get_median());
    MINFO("stdev: " << transfer_stats.get_standard_deviation());
    MINFO("variance: " << transfer_stats.get_variance());

    MINFO("------------------------------------------------------------------");
    MINFO("------------------------------------------------------------------");
    
    std::vector<size_t> m_multisig_k_sizes;
    m_multisig_k_sizes.reserve(c.m_transfers.size());
    for (auto &t : c.m_transfers)
        m_multisig_k_sizes.push_back(get_serialized_size(t.m_multisig_k));
    
    Stats<size_t> m_multisig_k_stats(m_multisig_k_sizes);
    const size_t m_multisig_k_stats_sum = std::accumulate(m_multisig_k_sizes.begin(), m_multisig_k_sizes.end(), 0);

    int mk_num_empty = 0;
    for (const auto &td : c.m_transfers)
        for (const auto &mk : td.m_multisig_k)
            mk_num_empty += mk == rct::zero();

    MINFO("Stats about m_transfers subfield m_multisig_k:");
    MINFO("min: " << m_multisig_k_stats.get_min());
    MINFO("max: " << m_multisig_k_stats.get_max());
    MINFO("mean: " << m_multisig_k_stats.get_mean());
    MINFO("median: " << m_multisig_k_stats.get_median());
    MINFO("stdev: " << m_multisig_k_stats.get_standard_deviation());
    MINFO("variance: " << m_multisig_k_stats.get_variance());
    MINFO("sum: " << m_multisig_k_stats_sum);
    MINFO("number empty keys: " << mk_num_empty);

    MINFO("------------------------------------------------------------------");
    MINFO("------------------------------------------------------------------");
    
    std::vector<size_t> m_multisig_info_sizes;
    m_multisig_info_sizes.reserve(c.m_transfers.size());
    for (auto &t : c.m_transfers)
        m_multisig_info_sizes.push_back(get_serialized_size(t.m_multisig_info));
    
    Stats<size_t> m_multisig_info_stats(m_multisig_info_sizes);
    const size_t m_multisig_info_stats_sum = std::accumulate(m_multisig_info_sizes.begin(), m_multisig_info_sizes.end(), 0);

    MINFO("Stats about m_transfers subfield m_multisig_info:");
    MINFO("min: " << m_multisig_info_stats.get_min());
    MINFO("max: " << m_multisig_info_stats.get_max());
    MINFO("mean: " << m_multisig_info_stats.get_mean());
    MINFO("median: " << m_multisig_info_stats.get_median());
    MINFO("stdev: " << m_multisig_info_stats.get_standard_deviation());
    MINFO("variance: " << m_multisig_info_stats.get_variance());
    MINFO("sum: " << m_multisig_info_stats_sum);

    return 0;
}

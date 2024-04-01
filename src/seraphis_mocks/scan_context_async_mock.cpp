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

//paired header
#include "scan_context_async_mock.h"

//local headers
#include "async/misc_utils.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "misc_language.h"
#include "misc_log_ex.h"
#include "net/http.h"
#include "seraphis_core/legacy_enote_utils.h"
#include "seraphis_impl/scan_ledger_chunk_simple.h"
#include "seraphis_main/contextual_enote_record_types.h"
#include "seraphis_main/enote_finding_context.h"
#include "seraphis_main/enote_record_utils_legacy.h"
#include "seraphis_main/scan_core_types.h"
#include "seraphis_main/scan_misc_utils.h"
#include "seraphis_main/scan_balance_recovery_utils.h"
#include "storages/http_abstract_invoke.h"
#include "wallet/wallet_errors.h"

//standard headers
#include <exception>
#include <future>
#include <string>
#include <utility>

//third party headers
#include <boost/thread/thread.hpp>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis_impl"

namespace sp
{
namespace scanning
{
namespace mocks
{
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void validate_get_blocks_res(const ChunkRequest &req,
    const cryptonote::COMMAND_RPC_GET_BLOCKS_FAST::response &res)
{
    THROW_WALLET_EXCEPTION_IF(res.blocks.size() != res.output_indices.size(), tools::error::get_blocks_error,
        "mismatched blocks (" + boost::lexical_cast<std::string>(res.blocks.size()) + ") and output_indices (" +
        boost::lexical_cast<std::string>(res.output_indices.size()) + ") sizes from daemon");

    for (std::size_t i = 0; i < res.blocks.size(); ++i)
    {
        const std::size_t num_txs            = res.blocks[i].txs.size() + 1; // Add 1 for miner tx
        const std::size_t num_output_indices = res.output_indices[i].indices.size();

        THROW_WALLET_EXCEPTION_IF(num_txs != num_output_indices, tools::error::get_blocks_error,
            "mismatched block txs (" + boost::lexical_cast<std::string>(num_txs) + ") and output_indices" +
            " (" + boost::lexical_cast<std::string>(num_output_indices) + ") sizes from daemon");
    }

    if (!res.blocks.empty())
    {
        // current height == (top block index + 1)
        THROW_WALLET_EXCEPTION_IF(req.start_index >= res.current_height, tools::error::get_blocks_error,
            "returned non-empty blocks in getblocks.bin but requested start index is >= chain height");
    }
    else
    {
        // We expect to have scanned to the tip
        THROW_WALLET_EXCEPTION_IF(req.start_index < res.current_height, tools::error::get_blocks_error,
            "no blocks returned in getblocks.bin but requested start index is < chain height");

        // Scanner is not designed to support retrieving empty chunks when no top block hash is returned (i.e. when
        // pointing to an older daemon version)
        THROW_WALLET_EXCEPTION_IF(res.top_block_hash == crypto::null_hash, tools::error::wallet_internal_error,
            "did not expect empty chunk when top block hash is null");
    }
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void prepare_unscanned_legacy_transaction(const crypto::hash &tx_hash,
    const cryptonote::transaction &tx,
    const std::vector<std::uint64_t> legacy_output_index_number_per_enote,
    sp::LegacyUnscannedTransaction &unscanned_tx_out)
{
    unscanned_tx_out = LegacyUnscannedTransaction{};

    unscanned_tx_out.transaction_id         = rct::hash2rct(tx_hash);
    unscanned_tx_out.unlock_time            = tx.unlock_time;

    unscanned_tx_out.tx_memo = sp::TxExtra(
            (const unsigned char *) tx.extra.data(),
            (const unsigned char *) tx.extra.data() + tx.extra.size()
        );

    sp::legacy_outputs_to_enotes(tx, unscanned_tx_out.enotes);

    CHECK_AND_ASSERT_THROW_MES(legacy_output_index_number_per_enote.empty() ||
            legacy_output_index_number_per_enote.size() == unscanned_tx_out.enotes.size(),
        "bad number of output indices compared to number of legacy tx enotes");

    unscanned_tx_out.legacy_key_images.reserve(tx.vin.size());
    for (const auto &in: tx.vin)
    {
        if (in.type() != typeid(cryptonote::txin_to_key))
            continue;
        const auto &txin = boost::get<cryptonote::txin_to_key>(in);
        unscanned_tx_out.legacy_key_images.emplace_back(txin.k_image);
    }

    const bool is_rct{tx.version == 2};

    unscanned_tx_out.legacy_output_index_per_enote.clear();
    unscanned_tx_out.legacy_output_index_per_enote.reserve(unscanned_tx_out.enotes.size());
    for (size_t i = 0; i < unscanned_tx_out.enotes.size(); ++i)
    {
        const rct::xmr_amount ledger_indexing_amount{
                get_legacy_ledger_indexing_amount(unscanned_tx_out.enotes[i], is_rct)
            };
        const std::uint64_t global_index{
                legacy_output_index_number_per_enote.empty() ? 0 : legacy_output_index_number_per_enote[i]
            };
        unscanned_tx_out.legacy_output_index_per_enote.push_back({ledger_indexing_amount, global_index});
    }
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static bool is_terminal_chunk(const sp::scanning::ChunkContext &context, const std::uint64_t end_scan_index)
{
    if (sp::scanning::chunk_context_is_empty(context))
    {
        MDEBUG("Chunk context is empty starting at " << context.start_index);
        return true;
    }

    // is the chunk the terminal chunk in the chain
    const std::uint64_t current_chunk_end_index{context.start_index + sp::scanning::chunk_size(context)};
    if (current_chunk_end_index >= end_scan_index)
    {
        MDEBUG("Chunk context end index: " << current_chunk_end_index
            << " (end_scan_index=" << end_scan_index << ")");
        return true;
    }

    return false;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void rpc_get_blocks_internal(const ChunkRequest &chunk_request,
    const std::function<bool(
        const cryptonote::COMMAND_RPC_GET_BLOCKS_FAST::request&,
        cryptonote::COMMAND_RPC_GET_BLOCKS_FAST::response&
    )> &rpc_get_blocks,
    const std::uint64_t max_get_blocks_attempts,
    const bool trusted_daemon,
    const bool high_height_ok,
    cryptonote::COMMAND_RPC_GET_BLOCKS_FAST::response &res_out)
{
    cryptonote::COMMAND_RPC_GET_BLOCKS_FAST::request req = AUTO_VAL_INIT(req);

    req.start_height    = chunk_request.start_index;
    req.max_block_count = chunk_request.requested_chunk_size;
    req.high_height_ok  = high_height_ok;
    req.prune           = true;
    req.no_miner_tx     = false;

    bool r = false;
    std::size_t try_count = 0;
    do
    {
        ++try_count;
        try
        {
            MDEBUG("Pulling blocks at req start height: " << req.start_height << " (try_count=" << try_count << ")");
            r = rpc_get_blocks(req, res_out);
            const std::string status = cryptonote::get_rpc_status(trusted_daemon, res_out.status);
            THROW_ON_RPC_RESPONSE_ERROR(r, {}, res_out, "getblocks.bin", tools::error::get_blocks_error, status);
            validate_get_blocks_res(chunk_request, res_out);
        }
        catch (tools::error::deprecated_rpc_access&)
        {
            // No need to retry
            std::rethrow_exception(std::current_exception());
        }
        catch (...)
        {
            r = false;
            if (try_count >= max_get_blocks_attempts)
                std::rethrow_exception(std::current_exception());
        }
    } while (!r && try_count < max_get_blocks_attempts);

    THROW_WALLET_EXCEPTION_IF(!r, tools::error::wallet_internal_error, "failed to get blocks");

    MDEBUG("Pulled blocks: requested start height " << req.start_height << ", count " << res_out.blocks.size()
        << ", node height " << res_out.current_height << ", top hash " << res_out.top_block_hash
        << ", pool info " << static_cast<unsigned int>(res_out.pool_info_extent));
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void prepare_unscanned_block(const cryptonote::block_complete_entry &res_block_entry,
    const std::size_t block_idx,
    const std::vector<cryptonote::COMMAND_RPC_GET_BLOCKS_FAST::tx_output_indices> &output_indices,
    sp::LegacyUnscannedBlock &unscanned_block_out)
{
    unscanned_block_out.unscanned_txs.resize(1 + res_block_entry.txs.size()); // Add 1 for miner tx

    // Parse block
    cryptonote::block block;
    bool r = cryptonote::parse_and_validate_block_from_blob(res_block_entry.block, block);
    THROW_WALLET_EXCEPTION_IF(!r, tools::error::wallet_internal_error,
        "failed to parse block blob" + std::to_string(block_idx));

    THROW_WALLET_EXCEPTION_IF(res_block_entry.txs.size() != block.tx_hashes.size(),
        tools::error::wallet_internal_error, "mismatched num txs to hashes at block" + std::to_string(block_idx));

    unscanned_block_out.block_index     = cryptonote::get_block_height(block);
    unscanned_block_out.block_timestamp = block.timestamp;
    unscanned_block_out.block_hash      = rct::hash2rct(cryptonote::get_block_hash(block));
    unscanned_block_out.prev_block_hash = rct::hash2rct(block.prev_id);

    THROW_WALLET_EXCEPTION_IF(output_indices.size() != unscanned_block_out.unscanned_txs.size(),
        tools::error::wallet_internal_error, "mismatched size of output indices to unscanned txs");

    // Prepare miner tx
    crypto::hash miner_tx_hash = cryptonote::get_transaction_hash(block.miner_tx);
    prepare_unscanned_legacy_transaction(miner_tx_hash,
        block.miner_tx,
        output_indices[0].indices,
        unscanned_block_out.unscanned_txs[0]);

    // Prepare non-miner txs
    for (std::size_t tx_idx = 0; tx_idx < res_block_entry.txs.size(); ++tx_idx)
    {
        const std::size_t unscanned_tx_idx = 1 + tx_idx;
        auto &unscanned_tx = unscanned_block_out.unscanned_txs[unscanned_tx_idx];

        cryptonote::transaction tx;
        r = cryptonote::parse_and_validate_tx_base_from_blob(res_block_entry.txs[tx_idx].blob, tx);
        THROW_WALLET_EXCEPTION_IF(!r, tools::error::wallet_internal_error,
            "failed to parse tx blob at index " + std::to_string(tx_idx));

        prepare_unscanned_legacy_transaction(block.tx_hashes[tx_idx],
            std::move(tx),
            output_indices[unscanned_tx_idx].indices,
            unscanned_tx);
    }
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void parse_rpc_get_blocks(const ChunkRequest &chunk_request,
    const cryptonote::COMMAND_RPC_GET_BLOCKS_FAST::response &res,
    sp::scanning::ChunkContext &chunk_context_out,
    sp::LegacyUnscannedChunk &unscanned_chunk_out)
{
    validate_get_blocks_res(chunk_request, res);

    chunk_context_out.block_ids.clear();
    unscanned_chunk_out.clear();

    // Older daemons can return more blocks than requested because they did not support a max_block_count req param.
    // The scanner expects requested_chunk_size blocks however, so we only care about the blocks up until that point.
    // Note the scanner can also return *fewer* blocks than requested if at chain tip or the chunk exceeded max size.
    const std::uint64_t num_blocks = std::min((std::uint64_t)res.blocks.size(), chunk_request.requested_chunk_size);
    unscanned_chunk_out.resize(num_blocks);
    chunk_context_out.block_ids.reserve(num_blocks);

    if (num_blocks == 0)
    {
        // must have requested the tip of the chain
        chunk_context_out.prefix_block_id = rct::hash2rct(res.top_block_hash);
        chunk_context_out.start_index = res.current_height; // current height == (top block index + 1)
        return;
    }

    // Parse blocks and txs
    for (std::size_t block_idx = 0; block_idx < num_blocks; ++block_idx)
    {
        const auto &res_block_entry = res.blocks[block_idx];
        const auto &output_indices  = res.output_indices[block_idx].indices;
        auto &unscanned_block_out   = unscanned_chunk_out[block_idx];

        prepare_unscanned_block(res_block_entry,
            block_idx,
            output_indices,
            unscanned_block_out);

        // Set chunk context data
        chunk_context_out.block_ids.emplace_back(unscanned_block_out.block_hash);
        if (block_idx == 0)
        {
            chunk_context_out.prefix_block_id = unscanned_block_out.prev_block_hash;
            chunk_context_out.start_index     = unscanned_block_out.block_index;
        }
    }
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
bool AsyncScanContextLegacy::check_launch_next_task() const
{
    THROW_WALLET_EXCEPTION_IF(!m_pending_queue_mutex.thread_owns_lock(), tools::error::wallet_internal_error,
        "this thread does not own the pending queue mutex");

    if (!m_scanner_ready.load(std::memory_order_relaxed))
    {
        MDEBUG("Pending queue is not available for use, no tasks can be launched");
        return false;
    }

    const std::uint64_t num_blocks_in_chain = m_num_blocks_in_chain.load(std::memory_order_relaxed);
    if (num_blocks_in_chain != 0 && m_scan_index.load(std::memory_order_relaxed) >= num_blocks_in_chain)
    {
        MDEBUG("Scan tasks are scheduled to scan to chain tip, not launching another task");
        return false;
    }

    if (m_num_pending_chunks.load(std::memory_order_relaxed) >= m_config.pending_chunk_queue_size)
    {
        MDEBUG("Pending queue is already at max capacity");
        return false;
    }

    // We use a separate counter for scanning chunks so we don't overload memory.
    // Continuously fetching chunks while the scanner is backstopped can overload memory.
    if (m_num_scanning_chunks.load(std::memory_order_relaxed) >= m_config.pending_chunk_queue_size)
    {
        MDEBUG("Scanning queue is already at max capacity");
        return false;
    }

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
void AsyncScanContextLegacy::try_fill_gap(bool chunk_is_terminal_chunk,
    const std::uint64_t &requested_chunk_size,
    const sp::scanning::ChunkContext &chunk_context)
{
    if (chunk_is_terminal_chunk)
        return;

    // If chunk was smaller than requested, will need to fill the gap
    const std::size_t chunk_size = sp::scanning::chunk_size(chunk_context);

    THROW_WALLET_EXCEPTION_IF(chunk_size > requested_chunk_size, tools::error::wallet_internal_error,
        "chunk context is larger than requested");

    const std::uint64_t gap = requested_chunk_size - chunk_size;

    // No gap, nothing to fill
    if (gap == 0)
        return;

    MDEBUG("There was a " << gap << " block gap at chunk request starting at " << chunk_context.start_index);

    const std::uint64_t gap_start_index = chunk_context.start_index + chunk_size;

    if (m_config.pending_chunk_queue_size > 1)
    {
        // Launch a new task to fill the gap
        const ChunkRequest next_chunk_request{
                .start_index          = gap_start_index,
                .requested_chunk_size = gap
            };

        SCOPE_LOCK_MUTEX(m_pending_queue_mutex);
        this->push_next_chunk_task(next_chunk_request);
    }
    else
    {
        // Pull scan index back to the start of the gap for next task.
        // - For serial scan contexts (when `m_config.pending_chunk_queue_size == 1`),
        //   we can't launch a gap-filler task. Instead, we say the next serial task will start
        //   at the gap start index.
        m_scan_index.store(gap_start_index, std::memory_order_relaxed);
    }
}
//-------------------------------------------------------------------------------------------------------------------
void AsyncScanContextLegacy::update_chain_state(const sp::scanning::ChunkContext &chunk_context,
    const std::uint64_t num_blocks_in_chain,
    const rct::key &top_block_hash,
    bool &chunk_is_terminal_chunk_out)
{
    std::lock_guard<std::mutex> lock{m_chain_state_mutex};

    MDEBUG("Updating chain state");

    // Update the chain tip.
    // - It's possible the chain tip will get set to a stale value here if a stale RPC request returns after a fresh
    //   one. That's ok. It will get corrected either by another request coming in later, or on the next scan pass.
    // - Unless the scanner is checking difficulty, technically there's no way for it to know which chain is actually
    //   the highest difficulty chain anyway, so it has to trust whatever value comes in here.
    // TODO: only update if difficulty > last known difficulty; needs a change to the daemon RPC
    if (num_blocks_in_chain != m_num_blocks_in_chain.load(std::memory_order_relaxed)
        || top_block_hash != m_top_block_hash)
    {
        m_num_blocks_in_chain.store(num_blocks_in_chain, std::memory_order_relaxed);

        // Note: the top block hash can be null if pointing to an older daemon
        m_top_block_hash = top_block_hash;

        MDEBUG("Updated m_num_blocks_in_chain to " << num_blocks_in_chain
            << " (m_top_block_hash=" << top_block_hash << ")");
    }

    // Check if it's the scanner's terminal chunk (empty chunk context or reached tip of the chain)
    const std::uint64_t n_blocks_in_chain = m_num_blocks_in_chain.load(std::memory_order_relaxed);
    chunk_is_terminal_chunk_out = is_terminal_chunk(chunk_context, n_blocks_in_chain);

    // Use the terminal chunk to update the top block hash if the chunk isn't empty.
    // - This is required if the daemon RPC did NOT provide the top block hash (e.g. when pointing to an older
    //   daemon), in which case we have to use the last block ID in the terminal chunk to set the top block hash.
    if (chunk_is_terminal_chunk_out && !chunk_context.block_ids.empty())
    {
        m_top_block_hash = chunk_context.block_ids[chunk_context.block_ids.size() - 1];
        MDEBUG("Used terminal chunk to update top_block_hash " << m_top_block_hash
            << " (num_blocks_in_chain=" << n_blocks_in_chain << ")");
    }

    // Sanity check expected values at terminal chunk
    if (chunk_is_terminal_chunk_out)
    {
        // The m_scan_index must be at the tip or later (if the async scanner scheduled chunk tasks way beyond tip)
        THROW_WALLET_EXCEPTION_IF(m_scan_index.load(std::memory_order_relaxed) < n_blocks_in_chain,
            tools::error::wallet_internal_error,
            "scan index is < m_num_blocks_in_chain even though we encountered the terminal chunk");

        THROW_WALLET_EXCEPTION_IF(n_blocks_in_chain == 0, tools::error::wallet_internal_error,
            "expected >0 num blocks in the chain at terminal chunk");

        THROW_WALLET_EXCEPTION_IF(m_top_block_hash == rct::hash2rct(crypto::null_hash),
            tools::error::wallet_internal_error, "expected top block hash to be set at terminal chunk");
    }
}
//-------------------------------------------------------------------------------------------------------------------
void AsyncScanContextLegacy::handle_chunk_request(const ChunkRequest &chunk_request,
    sp::scanning::ChunkContext &chunk_context_out,
    LegacyUnscannedChunk &unscanned_chunk_out,
    bool &chunk_is_terminal_chunk_out)
{
    // Query daemon for chunk of blocks
    cryptonote::COMMAND_RPC_GET_BLOCKS_FAST::response res = AUTO_VAL_INIT(res);
    {
        async::fanout_token_t fanout_token{m_threadpool.launch_temporary_worker()};
        rpc_get_blocks_internal(chunk_request,
            rpc_get_blocks,
            m_config.max_get_blocks_attempts,
            m_config.trusted_daemon,
            m_config.high_height_ok,
            res);
    }

    // Parse the result
    parse_rpc_get_blocks(chunk_request,
        res,
        chunk_context_out,
        unscanned_chunk_out);

    // Update scanner's known top block height and hash
    this->update_chain_state(chunk_context_out,
        res.current_height, // current height == (top block index + 1)
        rct::hash2rct(res.top_block_hash),
        chunk_is_terminal_chunk_out);

    // Check if the chunk was smaller than requested and fill gap if needed
    this->try_fill_gap(chunk_is_terminal_chunk_out,
        chunk_request.requested_chunk_size,
        chunk_context_out);
}
//-------------------------------------------------------------------------------------------------------------------
async::TaskVariant AsyncScanContextLegacy::chunk_task(const ChunkRequest &chunk_request,
    std::shared_future<void> &context_stop_flag,
    std::shared_future<void> &data_stop_flag,
    std::shared_ptr<std::promise<sp::scanning::ChunkContext>> &chunk_context_ptr_out,
    std::shared_ptr<std::promise<sp::scanning::ChunkData>> &chunk_data_ptr_out,
    async::join_token_t &context_join_token_out)
{
    // Check if canceled
    if (async::future_is_ready(context_stop_flag))
    {
        m_num_pending_chunks.fetch_sub(1, std::memory_order_relaxed);
        return boost::none;
    }

    // Get the chunk from the daemon and prepare to scan
    sp::scanning::ChunkContext chunk_context{};
    LegacyUnscannedChunk unscanned_chunk{};
    bool chunk_is_terminal_chunk = false;
    try
    {
        this->handle_chunk_request(chunk_request,
            chunk_context,
            unscanned_chunk,
            chunk_is_terminal_chunk);
    }
    catch (...)
    {
        LOG_ERROR("Failed to get chunk context at start index " << chunk_request.start_index);
        chunk_context_ptr_out->set_exception(std::move(std::current_exception()));
        m_num_pending_chunks.fetch_sub(1, std::memory_order_relaxed);
        return boost::none;
    }

    // Finished retrieving the chunk
    chunk_context_ptr_out->set_value(std::move(chunk_context));
    context_join_token_out = nullptr;
    m_num_pending_chunks.fetch_sub(1, std::memory_order_relaxed);

    // Check if canceled
    if (async::future_is_ready(data_stop_flag))
        return boost::none;

    // launch the next task if we expect more and the queue has room
    this->try_launch_next_chunk_task(chunk_is_terminal_chunk);

    // Retrieved the chunk, now need to scan it
    m_num_scanning_chunks.fetch_add(1, std::memory_order_relaxed);

    // find-received-scan raw data
    // - note: process chunk data can 'do nothing' if the chunk is empty (i.e. don't launch any tasks)
    sp::scanning::ChunkData chunk_data;
    try { m_enote_finding_context.view_scan_chunk(unscanned_chunk, chunk_data); }
    catch (...)
    {
        LOG_ERROR("Failed to view scan chunk at start index " << chunk_request.start_index);
        chunk_data_ptr_out->set_exception(std::move(std::current_exception()));
        m_num_scanning_chunks.fetch_sub(1, std::memory_order_relaxed);
        return boost::none;
    }

    // Finished scanning the chunk
    chunk_data_ptr_out->set_value(std::move(chunk_data));
    m_num_scanning_chunks.fetch_sub(1, std::memory_order_relaxed);

    MDEBUG("Finished scanning chunk starting at " << chunk_request.start_index);

    this->try_launch_next_chunk_task(chunk_is_terminal_chunk);

    return boost::none;
}
//-------------------------------------------------------------------------------------------------------------------
PendingChunk AsyncScanContextLegacy::launch_chunk_task(const ChunkRequest &chunk_request)
{
    THROW_WALLET_EXCEPTION_IF(!m_pending_queue_mutex.thread_owns_lock(), tools::error::wallet_internal_error,
        "this thread does not own the pending queue mutex");

    MDEBUG("Launching chunk task at " << chunk_request.start_index
        << " (requested_chunk_size=" << chunk_request.requested_chunk_size << ")");

    // prepare chunk task
    std::promise<void> context_stop_signal{};
    std::promise<void> data_stop_signal{};
    std::promise<sp::scanning::ChunkContext> chunk_context_handle{};
    std::promise<sp::scanning::ChunkData> chunk_data_handle{};
    std::shared_future<sp::scanning::ChunkContext> chunk_context_future = chunk_context_handle.get_future().share();
    std::shared_future<sp::scanning::ChunkData> chunk_data_future       = chunk_data_handle.get_future().share();
    async::join_signal_t context_join_signal = m_threadpool.make_join_signal();
    async::join_signal_t data_join_signal    = m_threadpool.make_join_signal();
    async::join_token_t context_join_token   = m_threadpool.get_join_token(context_join_signal);
    async::join_token_t data_join_token      = m_threadpool.get_join_token(data_join_signal);

    auto task =
        [
            this,
            l_chunk_request      = chunk_request,
            l_context_stop_flag  = context_stop_signal.get_future().share(),
            l_data_stop_flag     = data_stop_signal.get_future().share(),
            l_chunk_context      = std::make_shared<std::promise<sp::scanning::ChunkContext>>(std::move(chunk_context_handle)),
            l_chunk_data         = std::make_shared<std::promise<sp::scanning::ChunkData>>(std::move(chunk_data_handle)),
            l_context_join_token = context_join_token,
            l_data_join_token    = data_join_token
        ]() mutable -> async::TaskVariant
        {
            return this->chunk_task(l_chunk_request,
                l_context_stop_flag,
                l_data_stop_flag,
                l_chunk_context,
                l_chunk_data,
                l_context_join_token);
        };

    // launch the task
    m_num_pending_chunks.fetch_add(1, std::memory_order_relaxed);
    m_threadpool.submit(async::make_simple_task(async::DefaultPriorityLevels::MEDIUM, std::move(task)));

    // return pending chunk for caller to deal with as needed
    async::join_condition_t chunk_context_join_condition{
            m_threadpool.get_join_condition(std::move(context_join_signal), std::move(context_join_token))
        };

    async::join_condition_t chunk_data_join_condition{
            m_threadpool.get_join_condition(std::move(data_join_signal), std::move(data_join_token))
        };

    return PendingChunk{
            .chunk_request = chunk_request,
            .pending_context = sp::scanning::PendingChunkContext{
                    .stop_signal            = std::move(context_stop_signal),
                    .chunk_context          = std::move(chunk_context_future),
                    .context_join_condition = std::move(chunk_context_join_condition)
                },
            .pending_data    = sp::scanning::PendingChunkData{
                    .stop_signal            = std::move(data_stop_signal),
                    .chunk_data             = std::move(chunk_data_future),
                    .data_join_condition    = std::move(chunk_data_join_condition)
                }
        };
}
//-------------------------------------------------------------------------------------------------------------------
bool AsyncScanContextLegacy::try_launch_next_chunk_task()
{
    THROW_WALLET_EXCEPTION_IF(!m_pending_queue_mutex.thread_owns_lock(), tools::error::wallet_internal_error,
        "this thread does not own the pending queue mutex");

    if (!this->check_launch_next_task())
        return false;

    // Advance the scanner's scanning index
    const std::uint64_t start_index = m_scan_index.fetch_add(m_max_chunk_size_hint);

    const ChunkRequest next_chunk_request{
            .start_index          = start_index,
            .requested_chunk_size = m_max_chunk_size_hint
        };

    return this->push_next_chunk_task(next_chunk_request);
}
//-------------------------------------------------------------------------------------------------------------------
void AsyncScanContextLegacy::try_launch_next_chunk_task(const bool chunk_is_terminal_chunk)
{
    // Don't need to launch the next task if found the terminal chunk, we're done!
    if (chunk_is_terminal_chunk)
        return;
    SCOPE_LOCK_MUTEX(m_pending_queue_mutex);
    this->try_launch_next_chunk_task();
}
//-------------------------------------------------------------------------------------------------------------------
bool AsyncScanContextLegacy::push_next_chunk_task(const ChunkRequest &next_chunk_request)
{
    THROW_WALLET_EXCEPTION_IF(!m_pending_queue_mutex.thread_owns_lock(), tools::error::wallet_internal_error,
        "this thread does not own the pending queue mutex");

    if (!m_scanner_ready.load(std::memory_order_relaxed))
    {
        MDEBUG("Pending queue is not available for use, not pushing next chunk task");
        return false;
    }

    auto task = this->launch_chunk_task(next_chunk_request);
    m_pending_chunk_queue.force_push(std::move(task));

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
void AsyncScanContextLegacy::handle_terminal_chunk()
{
    THROW_WALLET_EXCEPTION_IF(!m_async_scan_context_mutex.thread_owns_lock(), tools::error::wallet_internal_error,
        "this thread does not own the async scan context mutex");

    // Clear up everything left in the queue
    this->close_and_clear_pending_queue();

    // Make sure we scanned to current tip
    if (m_last_scanned_index == m_num_blocks_in_chain.load(std::memory_order_relaxed))
    {
        // We're good to go
        MDEBUG("We're prepared for the end condition, we scanned to " << m_last_scanned_index);
        m_scanner_finished = true;
    }
    else
    {
        // The chain must have advanced since we started scanning, restart scanning from the highest scan
        MDEBUG("The chain advanced since we started scanning, restart from last scan");
        SCOPE_LOCK_MUTEX(m_pending_queue_mutex);
        this->start_scanner(m_last_scanned_index, m_max_chunk_size_hint);
    }
}
//-------------------------------------------------------------------------------------------------------------------
std::unique_ptr<sp::scanning::LedgerChunk> AsyncScanContextLegacy::handle_end_condition()
{
    THROW_WALLET_EXCEPTION_IF(!m_async_scan_context_mutex.thread_owns_lock(), tools::error::wallet_internal_error,
        "this thread does not own the async scan context mutex");
    THROW_WALLET_EXCEPTION_IF(!m_pending_queue_mutex.thread_owns_lock(), tools::error::wallet_internal_error,
        "this thread does not own the pending queue mutex");

    const std::uint64_t num_blocks_in_chain = m_num_blocks_in_chain.load(std::memory_order_relaxed);

    MDEBUG("No pending chunks remaining, num blocks in chain " << num_blocks_in_chain
        << ", top hash " << m_top_block_hash << " , last scanned index " << m_last_scanned_index);

    THROW_WALLET_EXCEPTION_IF(!m_scanner_finished, tools::error::wallet_internal_error,
        "finished scanning but m_scanner_finished is not set");

    THROW_WALLET_EXCEPTION_IF(num_blocks_in_chain == 0, tools::error::wallet_internal_error,
        "finished scanning but num blocks in chain not set");

    THROW_WALLET_EXCEPTION_IF(m_top_block_hash == rct::hash2rct(crypto::null_hash),
        tools::error::wallet_internal_error, "finished scanning but top block hash not set");

    THROW_WALLET_EXCEPTION_IF(m_last_scanned_index != num_blocks_in_chain,
        tools::error::wallet_internal_error, "finished scanning but did not scan to the tip of the chain");

    // Use an empty chunk to indicate to the caller the scanner is finished
    sp::scanning::ChunkContext empty_terminal_chunk{
            .prefix_block_id = m_top_block_hash,
            .start_index     = num_blocks_in_chain,
            .block_ids       = {}
        };

    return std::make_unique<sp::scanning::LedgerChunkEmpty>(std::move(empty_terminal_chunk));
}
//-------------------------------------------------------------------------------------------------------------------
void AsyncScanContextLegacy::close_and_clear_pending_queue()
{
    THROW_WALLET_EXCEPTION_IF(!m_async_scan_context_mutex.thread_owns_lock(), tools::error::wallet_internal_error,
        "this thread does not own the async scan context mutex");

    // TODO: implement a faster cancel (adding ability to cancel http requests would be significant)
    MDEBUG("Waiting until pending queue clears");

    // Don't allow scheduling any more chunk tasks until the scanner is restarted
    m_scanner_ready.store(false, std::memory_order_relaxed);

    m_pending_chunk_queue.shut_down();

    // Send stop signals to all pending tasks and drain the queue
    std::vector<PendingChunk> drained_chunks;
    PendingChunk pending_chunk;
    auto pending_chunk_res = m_pending_chunk_queue.force_pop(pending_chunk);
    while (pending_chunk_res != async::TokenQueueResult::SHUTTING_DOWN)
    {
        THROW_WALLET_EXCEPTION_IF(pending_chunk_res != async::TokenQueueResult::SUCCESS,
            tools::error::wallet_internal_error, "Failed to clear pending chunks");

        // Send stop signals
        pending_chunk.pending_context.stop_signal.set_value();
        pending_chunk.pending_data.stop_signal.set_value();

        // Push the pending chunk into our drain catcher
        drained_chunks.push_back(std::move(pending_chunk));

        // Get the next pending chunk if there is one
        pending_chunk_res = m_pending_chunk_queue.force_pop(pending_chunk);
    }

    // Wait until all work from the queue is done
    while (!drained_chunks.empty())
    {
        auto &clear_chunk = drained_chunks.back();
        MDEBUG("Waiting to clear onchain chunk starting at " << clear_chunk.chunk_request.start_index);

        // Wait until **data** join condition is set, we're not waiting on just the contexts
        m_threadpool.work_while_waiting(clear_chunk.pending_data.data_join_condition,
            async::DefaultPriorityLevels::MAX);

        drained_chunks.pop_back();
    }

    MDEBUG("Pending queue cleared");
}
//-------------------------------------------------------------------------------------------------------------------
void AsyncScanContextLegacy::start_scanner(const std::uint64_t start_index,
    const std::uint64_t max_chunk_size_hint)
{
    THROW_WALLET_EXCEPTION_IF(!m_async_scan_context_mutex.thread_owns_lock(), tools::error::wallet_internal_error,
        "this thread does not own the async scan context mutex");
    THROW_WALLET_EXCEPTION_IF(!m_pending_queue_mutex.thread_owns_lock(), tools::error::wallet_internal_error,
        "this thread does not own the pending queue mutex");

    MDEBUG("Starting scanner from index " << start_index);

    THROW_WALLET_EXCEPTION_IF(m_pending_chunk_queue.reset() != async::TokenQueueResult::SUCCESS,
        tools::error::wallet_internal_error, "Pending queue failed to reset");

    m_max_chunk_size_hint = max_chunk_size_hint;
    m_scanner_ready.store(true, std::memory_order_relaxed);
    m_scanner_finished = false;

    m_num_pending_chunks.store(0, std::memory_order_relaxed);
    m_num_scanning_chunks.store(0, std::memory_order_relaxed);
    m_scan_index.store(start_index, std::memory_order_relaxed);
    m_last_scanned_index = start_index;

    m_num_blocks_in_chain.store(0, std::memory_order_relaxed);
    m_top_block_hash = rct::hash2rct(crypto::null_hash);

    // launch tasks until the queue fills up
    while (this->try_launch_next_chunk_task()) {};
}
//-------------------------------------------------------------------------------------------------------------------
void AsyncScanContextLegacy::begin_scanning_from_index(const std::uint64_t start_index,
    const std::uint64_t max_chunk_size_hint)
{
    SCOPE_LOCK_MUTEX(m_async_scan_context_mutex);

    // Wait for any pending chunks to finish if there are any (it's possible the caller detected a reorg and wants
    // to restart scanning from the reorged block)
    this->close_and_clear_pending_queue();

    SCOPE_LOCK_MUTEX(m_pending_queue_mutex);
    this->start_scanner(start_index, max_chunk_size_hint);
}
//-------------------------------------------------------------------------------------------------------------------
std::unique_ptr<sp::scanning::LedgerChunk> AsyncScanContextLegacy::get_onchain_chunk()
{
    SCOPE_LOCK_MUTEX(m_async_scan_context_mutex);
    THROW_WALLET_EXCEPTION_IF(!m_scanner_ready.load(std::memory_order_relaxed) && !m_scanner_finished,
        tools::error::wallet_internal_error, "scanner is not ready for use and not finished scanning yet");

    // Get the chunk with the lowest requested start index
    PendingChunk oldest_chunk;
    {
        SCOPE_LOCK_MUTEX(m_pending_queue_mutex);

        // Explicitly remove the min element (instead of the first element) because chunks might not be in the queue
        // in chain order. If we needed to fill a gap (try_fill_gap), the pending chunk gets pushed to the end
        // of the queue even though the requested start index may be lower than pending chunks already in the queue.
        async::TokenQueueResult oldest_chunk_result = m_pending_chunk_queue.try_remove_min(oldest_chunk);
        if (oldest_chunk_result == async::TokenQueueResult::QUEUE_EMPTY)
        {
            // We should be done scanning now
            return this->handle_end_condition();
        }
        THROW_WALLET_EXCEPTION_IF(oldest_chunk_result != async::TokenQueueResult::SUCCESS,
            tools::error::wallet_internal_error, "Failed to remove earliest onchain chunk");

        THROW_WALLET_EXCEPTION_IF(m_scanner_finished, tools::error::wallet_internal_error,
            "expected empty queue upon handling terminal chunk");
    }

    THROW_WALLET_EXCEPTION_IF(!m_scanner_ready.load(std::memory_order_relaxed),
        tools::error::wallet_internal_error, "scanner is not ready for use");

    sp::scanning::mocks::ChunkRequest &oldest_request = oldest_chunk.chunk_request;
    sp::scanning::PendingChunkContext &oldest_pending_context = oldest_chunk.pending_context;
    MDEBUG("Waiting for onchain chunk starting at " << oldest_request.start_index);

    THROW_WALLET_EXCEPTION_IF(oldest_request.start_index != m_last_scanned_index,
        tools::error::wallet_internal_error, "Chunk has index that is higher than expected");

    // Wait until the earliest chunk context is ready
    m_threadpool.work_while_waiting(oldest_pending_context.context_join_condition,
        async::DefaultPriorityLevels::MAX);

    MDEBUG("Done waiting for onchain chunk starting at " << oldest_request.start_index);

    // Expect the earliest chunk context to be ready
    THROW_WALLET_EXCEPTION_IF(!async::future_is_ready(oldest_pending_context.chunk_context),
        tools::error::wallet_internal_error, "Earliest onchain chunk context is not ready");

    // If there was an exception fetching the chunk context, .get() will throw it here
    sp::scanning::ChunkContext oldest_context = std::move(oldest_pending_context.chunk_context.get());
    m_last_scanned_index = oldest_context.start_index + sp::scanning::chunk_size(oldest_context);

    // Handle the terminal chunk
    const std::uint64_t num_blocks_in_chain = m_num_blocks_in_chain.load(std::memory_order_relaxed);
    if (is_terminal_chunk(oldest_context, num_blocks_in_chain))
    {
        MDEBUG("Encountered potential terminal chunk starting at " << oldest_context.start_index
            << " (expected to start at " << oldest_request.start_index << ")");
        this->handle_terminal_chunk();
    }

    // We're ready to return the pending chunk now
    std::vector<sp::scanning::PendingChunkData> pending_chunk_data;
    pending_chunk_data.emplace_back(std::move(oldest_chunk.pending_data));

    if (num_blocks_in_chain > 0)
        LOG_PRINT_L0("Block " << m_last_scanned_index << " / " << num_blocks_in_chain);

    return std::make_unique<sp::scanning::AsyncLedgerChunk>(m_threadpool,
        std::move(oldest_chunk.pending_context),
        std::move(pending_chunk_data),
        std::vector<rct::key>{rct::zero()});
}
//-------------------------------------------------------------------------------------------------------------------
AsyncScanContextLegacy::~AsyncScanContextLegacy()
{
    SCOPE_LOCK_MUTEX(m_async_scan_context_mutex);

    // All tasks with copies of `this` are tracked in the pending queue. When the pending queue returns empty (after
    // draining and working on all removed tasks), we know that there are no lingering tasks with copies of `this`.
    this->close_and_clear_pending_queue();
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace scanning
} //namespace scanning
} //namespace sp

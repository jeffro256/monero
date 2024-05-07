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

// NOT FOR PRODUCTION
// TODO for production-ready:
// 1. Pool handling.
// 2. Pre-RCT output handling.
// 3. Ability to stop the scanner (terminate_scanning)

// Simple implementations of enote scanning contexts.

#pragma once

//local headers
#include "async/mutex.h"
#include "async/threadpool.h"
#include "common/variant.h"
#include "crypto/hash.h"
#include "cryptonote_basic/cryptonote_basic.h"
#include "cryptonote_config.h"
#include "ringct/rctTypes.h"
#include "rpc/core_rpc_server_commands_defs.h"
#include "seraphis_main/enote_finding_context.h"
#include "seraphis_main/scan_context.h"
#include "seraphis_main/scan_core_types.h"
#include "seraphis_main/scan_ledger_chunk.h"
#include "seraphis_main/scan_machine_types.h"
#include "seraphis_impl/scan_ledger_chunk_async.h"

//third party headers

//standard headers
#include <atomic>
#include <cstdint>
#include <memory>
#include <mutex>
#include <thread>
#include <vector>

//forward declarations


namespace sp
{
namespace scanning
{
namespace mocks
{
//-------------------------------------------------------------------------------------------------------------------
struct ChunkRequest final
{
    std::uint64_t start_index;
    std::uint64_t requested_chunk_size;
};
//-------------------------------------------------------------------------------------------------------------------
struct PendingChunk final
{
    ChunkRequest chunk_request;
    sp::scanning::PendingChunkContext pending_context;
    sp::scanning::PendingChunkData pending_data;
};

static inline bool operator<(const PendingChunk &pending_chunk1, const PendingChunk &pending_chunk2)
{
    return pending_chunk1.chunk_request.start_index < pending_chunk2.chunk_request.start_index;
}
//-------------------------------------------------------------------------------------------------------------------
struct AsyncScanContextLegacyConfig final
{
    /// max number of chunks that will be requested at once in a queue
    const std::uint64_t pending_chunk_queue_size{10};
    /// maximum number of times to retry fetching blocks from daemon on failure
    std::uint64_t max_get_blocks_attempts{3};
    /// whether or not user trusts the daemon's results
    bool trusted_daemon{false};
    /// whether or not the daemon returns a successful response to getblocks.bin when the request includes a height
    /// that is higher than chain tip
    bool high_height_ok{true};
};
//-------------------------------------------------------------------------------------------------------------------
////
// WARNING: if the chunk size increment exceeds the max chunk size obtainable from the raw chunk data source, then
//          this will be less efficient because it will need to 'gap fill' continuously. To maximize efficiency,
//          either make sure the scanner is pointing to a daemon that supports the max_block_count req param,
//          or use a pending_chunk_queue_size of 1 and a multithreaded enote finding context.
///
class AsyncScanContextLegacy final : public ScanContextLedger
{
public:
    AsyncScanContextLegacy(const AsyncScanContextLegacyConfig &config,
            sp::EnoteFindingContextLegacy &enote_finding_context,
            async::Threadpool &threadpool,
            const std::function<bool(
                const cryptonote::COMMAND_RPC_GET_BLOCKS_FAST::request&,
                cryptonote::COMMAND_RPC_GET_BLOCKS_FAST::response&
            )> &rpc_get_blocks) :
        m_config{config},
        m_enote_finding_context{enote_finding_context},
        m_scanner_ready{false},
        m_threadpool{threadpool},
        rpc_get_blocks{rpc_get_blocks}
    {
        assert(config.pending_chunk_queue_size > 0);
        assert(config.max_get_blocks_attempts > 0);
    }

    ~AsyncScanContextLegacy();

    /// disable copy/move (this is a scoped manager [reference wrapper])
    AsyncScanContextLegacy& operator=(AsyncScanContextLegacy&&) = delete;

    /// Kick off the scanner starting from the provided index
    void begin_scanning_from_index(const std::uint64_t start_index,
        const std::uint64_t max_chunk_size_hint) override;

    /// Get the next chunk from the scanner. Must call begin_scanning_from_index once before get_onchain_chunk
    std::unique_ptr<sp::scanning::LedgerChunk> get_onchain_chunk() override;

    // TODO: implement below functions
    /// stop the current scanning process (should be no-throw no-fail)
    void terminate_scanning() override { /* no-op */ }
    /// test if scanning has been aborted
    bool is_aborted() const override { return false; }

private:
    /// abstracted function that gets blocks via RPC request
    const std::function<bool(
        const cryptonote::COMMAND_RPC_GET_BLOCKS_FAST::request&,
        cryptonote::COMMAND_RPC_GET_BLOCKS_FAST::response&
    )> &rpc_get_blocks;

    /// reset scanner state and kick off scanner
    void start_scanner(const std::uint64_t start_index,
        const std::uint64_t max_chunk_size_hint);

    /// launch task to get a chunk of blocks, returns a pending chunk composed of futures
    PendingChunk launch_chunk_task(const ChunkRequest &chunk_request);

    // do the actual task handling chunks and resolve chunk promises as soon as ready
    async::TaskVariant chunk_task(const ChunkRequest &chunk_request,
        std::shared_future<void> &context_stop_flag_out,
        std::shared_future<void> &data_stop_flag_out,
        std::shared_ptr<std::promise<sp::scanning::ChunkContext>> &chunk_context_ptr_out,
        std::shared_ptr<std::promise<sp::scanning::ChunkData>> &chunk_data_ptr_out,
        async::join_token_t &context_join_token_out);

    /// close queue to further tasks and wait until all tasks in the queue have completed
    void close_and_clear_pending_queue();

    /// check if we should launch the next task to get the next chunk of blocks
    bool check_launch_next_task() const;

    /// launch task to get the next chunk of blocks advancing the scanner's scan_index
    bool try_launch_next_chunk_task();

    /// launch the next chunk task if we should
    void try_launch_next_chunk_task(bool chunk_is_terminal_chunk);

    /// push the next chunk task into the pending queue
    bool push_next_chunk_task(const ChunkRequest &next_chunk_request);

    /// if a chunk is smaller than requested, need to fill gap to next chunk
    void try_fill_gap(bool chunk_is_terminal_chunk,
        const std::uint64_t &requested_chunk_size,
        const sp::scanning::ChunkContext &chunk_context);

    /// fetch chunk from daemon, parse it into chunk context and unscanned chunk
    void handle_chunk_request(const ChunkRequest &chunk_request,
        sp::scanning::ChunkContext &chunk_context_out,
        LegacyUnscannedChunk &unscanned_chunk_out,
        bool &chunk_is_terminal_chunk_out);

    /// update the async scan context's known chain height and top block hash
    void update_chain_state(const sp::scanning::ChunkContext &chunk_context,
        const std::uint64_t num_blocks_in_chain,
        const rct::key &top_block_hash,
        bool &chunk_is_terminal_chunk_out);

    /// once the scanner reaches the terminal chunk, prepare it for the end condition
    void handle_terminal_chunk();

    /// return an empty chunk with prev block hash set
    std::unique_ptr<sp::scanning::LedgerChunk> handle_end_condition();
private:
    /// config options
    const AsyncScanContextLegacyConfig &m_config;
    std::uint64_t m_max_chunk_size_hint{(uint64_t)COMMAND_RPC_GET_BLOCKS_FAST_MAX_BLOCK_COUNT};

    /// finding context used to view scan enotes
    const sp::EnoteFindingContextLegacy &m_enote_finding_context;

    /// pending chunks
    async::TokenQueue<PendingChunk> m_pending_chunk_queue{};
    std::atomic<bool> m_scanner_ready{false};
    bool m_scanner_finished{false};

    /// scanner state
    std::atomic<std::uint64_t> m_num_pending_chunks{0};
    std::atomic<std::uint64_t> m_num_scanning_chunks{0};
    std::atomic<std::uint64_t> m_scan_index{0};
    std::uint64_t m_last_scanned_index{0};
    std::uint64_t m_end_scan_index{0};

    /// chain state known to async scanner
    std::atomic<std::uint64_t> m_num_blocks_in_chain{0};
    rct::key m_top_block_hash{rct::hash2rct(crypto::null_hash)};

    /// threading helpers
    async::Threadpool &m_threadpool;
    async::Mutex m_async_scan_context_mutex;
    async::Mutex m_pending_queue_mutex;
    std::mutex m_chain_state_mutex;
};
//-------------------------------------------------------------------------------------------------------------------
} //namespace mocks
} //namespace scanning
} //namespace sp

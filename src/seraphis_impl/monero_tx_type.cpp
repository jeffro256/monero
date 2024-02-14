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

//local headers
#include "monero_tx_type.h"

//third party headers

//standard headers

//forward declarations

namespace sp
{
std::uint8_t tx_version_ref(const MoneroTxVariant &tx)
{
    struct tx_version_visitor: tools::variant_static_visitor<std::uint8_t>
    {
        std::uint8_t operator()(const CryptonoteTxCoinbaseV1 &cnv1cb) const { return 1; }
        std::uint8_t operator()(const CryptonoteTxV1 &cnv1) const { return 1; }
        std::uint8_t operator()(const RingCTTxCoinbaseV2 &rctv2cb) const { return 2; }
        std::uint8_t operator()(const RingCTTxV2 &rctv2) const { return 2; }
        std::uint8_t operator()(const SpTxCoinbaseV1&) const { return 3; }
        std::uint8_t operator()(const SpTxSquashedV1&) const { return 4; }
    };

    return tx.visit(tx_version_visitor());
}

std::uint64_t unlock_time_ref(const MoneroTxVariant &tx)
{
    struct unlock_time_visitor: tools::variant_static_visitor<std::uint64_t>
    {
        std::uint64_t operator()(const CryptonoteTxCoinbaseV1 &cnv1cb) const
        { return cnv1cb.height + CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW; }
        std::uint64_t operator()(const CryptonoteTxV1 &cnv1) const { return cnv1.unlock_time; }
        std::uint64_t operator()(const RingCTTxCoinbaseV2 &rctv2cb) const
        { return rctv2cb.height + CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW; }
        std::uint64_t operator()(const RingCTTxV2 &rctv2) const { return rctv2.unlock_time; }
        std::uint64_t operator()(const SpTxCoinbaseV1&) const { return 0; }
        std::uint64_t operator()(const SpTxSquashedV1&) const { return 0; }
    };

    return tx.visit(unlock_time_visitor());
}

std::uint64_t block_height_ref(const MoneroTxVariant &tx)
{
    struct block_height_visitor: tools::variant_static_visitor<std::uint64_t>
    {
        [[noreturn]] static void throw_not_coinbase()
        { throw std::runtime_error("cannot get static block height of non-coinbase tx"); }
        std::uint64_t operator()(const CryptonoteTxCoinbaseV1 &cnv1cb) const { return cnv1cb.height; }
        std::uint64_t operator()(const CryptonoteTxV1 &cnv1) const { throw_not_coinbase(); }
        std::uint64_t operator()(const RingCTTxCoinbaseV2 &rctv2cb) const { return rctv2cb.height; }
        std::uint64_t operator()(const RingCTTxV2 &rctv2) const { throw_not_coinbase(); }
        std::uint64_t operator()(const SpTxCoinbaseV1 &spv1cb) const { return spv1cb.block_height; }
        std::uint64_t operator()(const SpTxSquashedV1&) const { throw_not_coinbase(); }
    };

    return tx.visit(block_height_visitor());
}

const std::vector<std::uint8_t>& extra_ref(const MoneroTxVariant &tx)
{
    struct extra_visitor: tools::variant_static_visitor<const std::vector<std::uint8_t>&>
    {
        result_type operator()(const CryptonoteTxCoinbaseV1 &cnv1cb) const { return cnv1cb.extra; }
        result_type operator()(const CryptonoteTxV1 &cnv1) const { return cnv1.extra; }
        result_type operator()(const RingCTTxCoinbaseV2 &rctv2cb) const { return rctv2cb.extra; }
        result_type operator()(const RingCTTxV2 &rctv2) const { return rctv2.extra; }
        result_type operator()(const SpTxCoinbaseV1 &spv1cb) const { return spv1cb.tx_supplement.tx_extra; }
        result_type operator()(const SpTxSquashedV1 &spv1) const { return spv1.tx_supplement.tx_extra; }
    };

    return tx.visit(extra_visitor());
}

bool is_coinbase(const MoneroTxVariant &tx)
{
    struct is_coinbase_visitor: tools::variant_static_visitor<bool>
    {
        bool operator()(const CryptonoteTxCoinbaseV1 &cnv1cb) const { return true; }
        bool operator()(const CryptonoteTxV1 &cnv1)           const { return false; }
        bool operator()(const RingCTTxCoinbaseV2 &rctv2cb)    const { return true; }
        bool operator()(const RingCTTxV2 &rctv2)              const { return false; }
        bool operator()(const SpTxCoinbaseV1 &spv1cb)         const { return true; }
        bool operator()(const SpTxSquashedV1&)                const { return false; }
    };

    return tx.visit(is_coinbase_visitor());
}

bool is_pruned(const MoneroTxVariant &tx)
{
    struct rct_body_is_pruned_visitor: tools::variant_static_visitor<bool>
    {
        bool operator()(const RingCTBodyFull &body) const { return body.range_sigs.empty(); }
        bool operator()(const RingCTBodySimple &body) const { return body.range_sigs.empty(); }
        bool operator()(const RingCTBodyBulletproof &body) const { return body.pseudo_commitments.empty(); }
        bool operator()(const RingCTBodyBulletproofCompact &body) const { return body.pseudo_commitments.empty(); }
        bool operator()(const RingCTBodyClsag &body) const { return body.pseudo_commitments.empty(); }
        bool operator()(const RingCTBodyBulletproofPlus &body) const { return body.pseudo_commitments.empty(); }
    };

    struct is_pruned_visitor: tools::variant_static_visitor<bool>
    {
        bool operator()(const CryptonoteTxCoinbaseV1&) const { return false; }
        bool operator()(const CryptonoteTxV1 &cnv1) const { return cnv1.signatures.empty(); }
        bool operator()(const RingCTTxCoinbaseV2 &rctv2cb) const { return false; }
        bool operator()(const RingCTTxV2 &rctv2) const { return rctv2.body.visit(rct_body_is_pruned_visitor()); }
        bool operator()(const SpTxCoinbaseV1 &spv1cb) const { return false; }
        bool operator()(const SpTxSquashedV1 &spv1) const { return spv1.sp_image_proofs.empty(); }
    };

    return tx.visit(is_pruned_visitor());
}
} //namespace sp

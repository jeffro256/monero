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

#include "cryptonote_basic/cryptonote_format_utils.h"
#include "file_io_utils.h"
#include "ringct/rctTypes.h"
#include "seraphis_core/binned_reference_set.h"
#include "seraphis_impl/cryptonote_tx_serialization.h"
#include "seraphis_impl/monero_tx_type.h"
#include "seraphis_impl/seraphis_serialization.h"
#include "seraphis_main/txtype_base.h"
#include "seraphis_main/txtype_coinbase_v1.h"
#include "seraphis_main/txtype_squashed_v1.h"
#include "seraphis_mocks/seraphis_mocks.h"
#include "serialization/binary_utils.h"
#include "span.h"
#include "unit_tests_utils.h"

#include "gtest/gtest.h"

#include <optional>

using namespace sp;
using namespace jamtis;
using namespace sp::mocks;

namespace
{
template <class TxType>
bool compare_to_cn_tx(const cryptonote::transaction &cntx, const TxType&) { return false; }

bool compare_to_cn_tx(const cryptonote::transaction &cntx, const CryptonoteTxCoinbaseV1 &cb1tx)
{
    CHECK_AND_ASSERT_MES(cntx.version == 1, false, "bad version");
    CHECK_AND_ASSERT_MES(cntx.vin.size() == 1, false, "too many inputs");
    CHECK_AND_ASSERT_MES(cntx.vin[0].type() == typeid(cryptonote::txin_gen), false, "not coinbase input");
    CHECK_AND_ASSERT_MES(boost::get<cryptonote::txin_gen>(cntx.vin[0]).height == cb1tx.height, false, "mismatched coinbase height");
    CHECK_AND_ASSERT_MES(cntx.extra == cb1tx.extra, false, "mismatched tx_extra");
    CHECK_AND_ASSERT_MES(cntx.vout.size() == cb1tx.vout.size(), false, "mismatched vout size");
    for (size_t i = 0; i < cb1tx.vout.size(); ++i)
    {
        CHECK_AND_ASSERT_MES(cntx.vout[i].amount == cb1tx.vout[i].amount, false, "mismatched output amount");
        CHECK_AND_ASSERT_MES(cntx.vout[i].target.type() == typeid(cryptonote::txout_to_key), false, "wrong txout type");
        CHECK_AND_ASSERT_MES(boost::get<cryptonote::txout_to_key>(cntx.vout[i].target).key == rct::rct2pk(cb1tx.vout[i].onetime_address), false, "wrong txout key");
    }
    return true;
}

struct vout_clearamount_equality_visitor
{
    using result_type = bool;
    bool operator()(boost::blank) const { return false; }
    bool operator()(const std::vector<LegacyEnoteV1> &enotes) const
    {
        if (enotes.size() != vout.size()) return false;
        for (size_t i = 0; i < vout.size(); ++i)
        {
            CHECK_AND_ASSERT_MES(vout[i].amount == enotes[i].amount, false, "mismatched output amount");
            CHECK_AND_ASSERT_MES(vout[i].target.type() == typeid(cryptonote::txout_to_key), false, "wrong txout type");
            CHECK_AND_ASSERT_MES(boost::get<cryptonote::txout_to_key>(vout[i].target).key == rct::rct2pk(enotes[i].onetime_address), false, "wrong txout key");
        }
        return true;
    }
    bool operator()(const std::vector<LegacyEnoteV4> &enotes) const
    {
        if (enotes.size() != vout.size()) return false;
        for (size_t i = 0; i < vout.size(); ++i)
        {
            CHECK_AND_ASSERT_MES(vout[i].amount == enotes[i].amount, false, "mismatched output amount");
            CHECK_AND_ASSERT_MES(vout[i].target.type() == typeid(cryptonote::txout_to_tagged_key), false, "wrong txout type");
            CHECK_AND_ASSERT_MES(boost::get<cryptonote::txout_to_tagged_key>(vout[i].target).key == rct::rct2pk(enotes[i].onetime_address), false, "wrong txout key");
            CHECK_AND_ASSERT_MES(boost::get<cryptonote::txout_to_tagged_key>(vout[i].target).view_tag == enotes[i].view_tag, false, "wrong view tag");
        }
        return true;
    }
    const std::vector<cryptonote::tx_out> &vout;
};

bool compare_to_cn_tx(const cryptonote::transaction &cntx, const RingCTTxCoinbaseV2 &cb2tx)
{
    CHECK_AND_ASSERT_MES(cntx.version == 2, false, "bad version");
    CHECK_AND_ASSERT_MES(cntx.vin.size() == 1, false, "too many inputs");
    CHECK_AND_ASSERT_MES(cntx.vin[0].type() == typeid(cryptonote::txin_gen), false, "not coinbase input");
    CHECK_AND_ASSERT_MES(boost::get<cryptonote::txin_gen>(cntx.vin[0]).height == cb2tx.height, false, "mismatched coinbase height");
    CHECK_AND_ASSERT_MES(cntx.extra == cb2tx.extra, false, "mismatched tx_extra");

    if (!cb2tx.vout.visit(vout_clearamount_equality_visitor{cntx.vout}))
        return false;
    
    return true;
}

bool compare_to_cn_tx(const cryptonote::transaction &cntx, const CryptonoteTxV1 &v1tx)
{
    CHECK_AND_ASSERT_MES(cntx.version == 1, false, "bad version");
    CHECK_AND_ASSERT_MES(cntx.unlock_time == v1tx.unlock_time, false, "wrong unlock time");
    CHECK_AND_ASSERT_MES(cntx.vin.size() == v1tx.vin.size(), false, "wrong number of inputs");
    for (size_t i = 0; i < v1tx.vin.size(); ++i)
    {
        CHECK_AND_ASSERT_MES(cntx.vin[i].type() == typeid(cryptonote::txin_to_key), false, "not normal input");
        const auto &txinp = boost::get<cryptonote::txin_to_key>(cntx.vin[i]);
        CHECK_AND_ASSERT_MES(txinp.amount == v1tx.vin[i].amount, false, "wrong input amount");
        CHECK_AND_ASSERT_MES(txinp.k_image == v1tx.vin[i].k_image, false, "wrong input key image");
        CHECK_AND_ASSERT_MES(txinp.key_offsets == v1tx.vin[i].key_offsets, false, "wrong input ring members");
    }
    CHECK_AND_ASSERT_MES(cntx.extra == v1tx.extra, false, "mismatched tx_extra");
    CHECK_AND_ASSERT_MES(cntx.signatures == v1tx.signatures, false, "mismatched signatures");

    if (!v1tx.vout.visit(vout_clearamount_equality_visitor{cntx.vout}))
        return false;
    
    return true;
}

bool operator==(const rct::mgSig &x, const RingCTMlsag &y)
{
    if (!(x.cc == y.cc)) return false;
    if (x.ss.empty()) return false;
    const size_t rows = x.ss[0].size();
    for (const auto &col : x.ss) if (col.size() != rows) return false;
    const size_t num_ss_elems = x.ss.size() * rows;
    if (y.ss.size() != num_ss_elems) return false;
    for (size_t n = 0; n < num_ss_elems; ++n) if (!(x.ss[n / rows][n % rows] == y.ss[n])) return false;
    return true;
}

bool operator==(const rct::clsag &x, const RingCTClsag &y)
{
    return y.c1 == x.c1 && y.D == x.D && y.s == x.s;
}

bool operator==(const rct::rangeSig &x, const rct::rangeSig &y)
{
    constexpr size_t k64s = 64 * sizeof(rct::key);
    return !memcmp(x.Ci, y.Ci, k64s) && !memcmp(x.asig.s0, y.asig.s0, k64s) && !memcmp(x.asig.s1, y.asig.s1, k64s) &&
        x.asig.ee == y.asig.ee;
}

bool operator==(const rct::Bulletproof &x, const RingCTBulletproof &y)
{
    return x.A == y.A && x.S == y.S && x.T1 == y.T1 && x.T2 == y.T2 && x.taux == y.taux && x.mu == y.mu && x.L == y.L
        && x.R == y.R && x.a == y.a && x.b == y.b && x.t == y.t;
}

bool operator==(const rct::BulletproofPlus &x, const RingCTBulletproofPlus &y)
{
    return x.A == y.A && x.A1 == y.A1 && x.B == y.B && x.r1 == y.r1 && x.s1 == y.s1 && x.d1 == y.d1 && x.L == y.L && x.R == y.R;
}

bool operator==(const std::vector<rct::mgSig> &x, const std::vector<RingCTMlsag> &y)
{ if (x.size() != y.size()) return false; for (size_t i = 0; i < x.size(); ++i) if (!(x[i] == y[i])) return false; return true; }

bool operator==(const std::vector<rct::clsag> &x, const std::vector<RingCTClsag> &y)
{ if (x.size() != y.size()) return false; for (size_t i = 0; i < x.size(); ++i) if (!(x[i] == y[i])) return false; return true; }

bool operator==(const std::vector<rct::rangeSig> &x, const std::vector<rct::rangeSig> &y)
{ if (x.size() != y.size()) return false; for (size_t i = 0; i < x.size(); ++i) if (!(x[i] == y[i])) return false; return true; }

bool operator==(const std::vector<rct::Bulletproof> &x, const std::vector<RingCTBulletproof> &y)
{ if (x.size() != y.size()) return false; for (size_t i = 0; i < x.size(); ++i) if (!(x[i] == y[i])) return false; return true; }

bool operator==(const std::vector<rct::BulletproofPlus> &x, const std::vector<RingCTBulletproofPlus> &y)
{ if (x.size() != y.size()) return false; for (size_t i = 0; i < x.size(); ++i) if (!(x[i] == y[i])) return false; return true; }

bool compare_to_cn_tx(const cryptonote::transaction &cntx, const RingCTTxV2 &v2tx)
{
    CHECK_AND_ASSERT_MES(cntx.version == 2, false, "bad version");
    CHECK_AND_ASSERT_MES(cntx.unlock_time == v2tx.unlock_time, false, "wrong unlock time");
    CHECK_AND_ASSERT_MES(cntx.vin.size() == v2tx.vin.size(), false, "wrong number of inputs");
    for (size_t i = 0; i < v2tx.vin.size(); ++i)
    {
        CHECK_AND_ASSERT_MES(cntx.vin[i].type() == typeid(cryptonote::txin_to_key), false, "not normal input");
        const auto &txinp = boost::get<cryptonote::txin_to_key>(cntx.vin[i]);
        CHECK_AND_ASSERT_MES(txinp.amount == v2tx.vin[i].amount, false, "wrong input amount");
        CHECK_AND_ASSERT_MES(txinp.k_image == v2tx.vin[i].k_image, false, "wrong input key image");
        CHECK_AND_ASSERT_MES(txinp.key_offsets == v2tx.vin[i].key_offsets, false, "wrong input ring members");
    }
    CHECK_AND_ASSERT_MES(cntx.extra == v2tx.extra, false, "mismatched tx_extra");
    CHECK_AND_ASSERT_MES(cntx.rct_signatures.type == ringct_type(v2tx.body), false, "Wrong RingCT version");
    CHECK_AND_ASSERT_MES(cntx.rct_signatures.txnFee == v2tx.fee, false, "mismatched fee");

    struct rct_sigs_equality_visitor
    {
        using result_type = bool;
        bool operator()(boost::blank) const { return false; }
        bool operator()(const RingCTBodyFull &rbody) const
        {
            if (rbody.vout.size() != simplified_vout.size())
                return false;
            for (size_t i = 0; i < rbody.vout.size(); ++i)
            {
                if (simplified_vout[i].first != rct::rct2pk(rbody.vout[i].onetime_address)) return false;
                if (simplified_vout[i].second) return false;
            }
            if (rv.p.MGs.size() != 0)
            {
                if (rv.p.MGs.size() != 1) return false;
                if (!(rv.p.MGs[0] == rbody.mlsag_full)) return false;
                if (!(rv.p.rangeSigs == rbody.range_sigs)) return false;
            }
            else // pruned RingCT v1
            {
                if (!rbody.mlsag_full.ss.empty()) return false;
                if (!rbody.range_sigs.empty()) return false;
            }
            return true;
        }
        bool operator()(const RingCTBodySimple &rbody) const
        {
            if (rbody.vout.size() != simplified_vout.size())
                return false;
            for (size_t i = 0; i < rbody.vout.size(); ++i)
            {
                if (simplified_vout[i].first != rct::rct2pk(rbody.vout[i].onetime_address)) return false;
                if (simplified_vout[i].second) return false;
            }
            if (rv.pseudoOuts != rbody.pseudo_commitments) return false;
            if (!(rv.p.MGs == rbody.mlsags_simple)) return false;
            if (!(rv.p.rangeSigs == rbody.range_sigs)) return false;
            return true;
        }
        bool operator()(const RingCTBodyBulletproof &rbody) const
        {
            if (rbody.vout.size() != simplified_vout.size())
                return false;
            for (size_t i = 0; i < rbody.vout.size(); ++i)
            {
                if (simplified_vout[i].first != rct::rct2pk(rbody.vout[i].onetime_address)) return false;
                if (simplified_vout[i].second) return false;
            }
            if (rv.p.pseudoOuts != rbody.pseudo_commitments) return false;
            if (!(rv.p.MGs == rbody.mlsags_simple)) return false;
            if (!(rv.p.bulletproofs == rbody.bulletproofs)) return false;
            return true;
        }
        bool operator()(const RingCTBodyBulletproofCompact &rbody) const
        {
            if (rbody.vout.size() != simplified_vout.size())
                return false;
            for (size_t i = 0; i < rbody.vout.size(); ++i)
            {
                if (simplified_vout[i].first != rct::rct2pk(rbody.vout[i].onetime_address)) return false;
                if (simplified_vout[i].second) return false;
            }
            if (rv.p.pseudoOuts != rbody.pseudo_commitments) return false;
            if (!(rv.p.MGs == rbody.mlsags_simple)) return false;
            if (!(rv.p.bulletproofs == rbody.bulletproofs)) return false;
            return true;
        }
        bool operator()(const RingCTBodyClsag &rbody) const
        {
            if (rbody.vout.size() != simplified_vout.size())
                return false;
            for (size_t i = 0; i < rbody.vout.size(); ++i)
            {
                if (simplified_vout[i].first != rct::rct2pk(rbody.vout[i].onetime_address)) return false;
                if (simplified_vout[i].second) return false;
            }
            if (rv.p.pseudoOuts != rbody.pseudo_commitments) return false;
            if (!(rv.p.CLSAGs == rbody.clsags)) return false;
            if (!(rv.p.bulletproofs == rbody.bulletproofs)) return false;
            return true;
        }
        bool operator()(const RingCTBodyBulletproofPlus &rbody) const
        {
            if (rbody.vout.size() != simplified_vout.size())
                return false;
            for (size_t i = 0; i < rbody.vout.size(); ++i)
            {
                if (simplified_vout[i].first != rct::rct2pk(rbody.vout[i].onetime_address)) return false;
                if (!simplified_vout[i].second) return false;
                if (*simplified_vout[i].second != rbody.vout[i].view_tag) return false;
            }
            if (rv.p.pseudoOuts != rbody.pseudo_commitments) return false;
            if (!(rv.p.CLSAGs == rbody.clsags)) return false;
            if (!(rv.p.bulletproofs_plus == rbody.bulletproofs_plus)) return false;
            return true;
        }
        const std::vector<std::pair<crypto::public_key, std::optional<crypto::view_tag>>> &simplified_vout;
        const rct::rctSig &rv;
    };
    // make simplified vout
    std::vector<std::pair<crypto::public_key, std::optional<crypto::view_tag>>> simplified_vout;
    for (const auto &o : cntx.vout)
    {
        if (o.amount != 0) return false;
        if (o.target.type() == typeid(cryptonote::txout_to_key))
            simplified_vout.emplace_back(boost::get<cryptonote::txout_to_key>(o.target).key, std::nullopt);
        else if (o.target.type() == typeid(cryptonote::txout_to_tagged_key))
            simplified_vout.emplace_back(boost::get<cryptonote::txout_to_tagged_key>(o.target).key,
                boost::get<cryptonote::txout_to_tagged_key>(o.target).view_tag);
        else
            return false;
    }
    if (!v2tx.body.visit(rct_sigs_equality_visitor{simplified_vout, cntx.rct_signatures}))
        return false;
    return true;
}

bool compare_to_cn_tx(const cryptonote::transaction &cntx, const MoneroTxVariant &txvar)
{
    if (is_coinbase(txvar) != cryptonote::is_coinbase(cntx)) return false;
    if (!is_coinbase(txvar) && is_pruned(txvar) != cntx.pruned) return false;
    return txvar.visit([&cntx](const auto& tx) { return compare_to_cn_tx(cntx, tx); });
}

bool load_monero_tx_variant_and_compare_cn(const std::string &file_name, const bool pruned = false)
{
    const boost::filesystem::path tx_path = unit_test::data_dir / "txs" / file_name;

    std::string tx_blob;
    CHECK_AND_ASSERT_THROW_MES(epee::file_io_utils::load_file_to_string(tx_path.string(), tx_blob),
        "file " << file_name << " failed to load to string");

    MoneroTxVariant tx;
    {
        binary_archive<false> ar(epee::strspan<std::uint8_t>(tx_blob));
        if (!do_serialize(ar, tx, pruned) || (!pruned && !ar.eof()))
            return false;
    }

    cryptonote::transaction old_tx;
    {
        if (pruned)
            CHECK_AND_ASSERT_THROW_MES(cryptonote::parse_and_validate_tx_base_from_blob(tx_blob, old_tx),
                "Tx base load failed");
        else
            CHECK_AND_ASSERT_THROW_MES(cryptonote::parse_and_validate_tx_from_blob(tx_blob, old_tx),
                "Tx load failed");
    }
    
    return compare_to_cn_tx(old_tx, tx);
}

std::array<std::string, 2> load_and_save_txvariant_blobs(const std::string &file_name, const bool pruned = false)
{
    const boost::filesystem::path tx_path = unit_test::data_dir / "txs" / file_name;

    std::string tx_blob;
    CHECK_AND_ASSERT_THROW_MES(epee::file_io_utils::load_file_to_string(tx_path.string(), tx_blob),
        "file " << file_name << " failed to load to string");

    MoneroTxVariant tx;
    {
        binary_archive<false> ar(epee::strspan<std::uint8_t>(tx_blob));
        CHECK_AND_ASSERT_THROW_MES(::serialization::serialize(ar, tx), "deserialization failed");
    }

    std::stringstream ss;
    {
        binary_archive<true> ar(ss);
        CHECK_AND_ASSERT_THROW_MES(do_serialize(ar, tx, pruned), "serialization failed");
    }

    if (pruned)
    {
        cryptonote::transaction cntx;
        CHECK_AND_ASSERT_THROW_MES(cryptonote::parse_and_validate_tx_base_from_blob(tx_blob, cntx),
            "Pruned tx failed to deserialize");
        CHECK_AND_ASSERT_THROW_MES(cntx.pruned, "BUG: not pruned after loading from base");

        std::stringstream pruned_ss;
        binary_archive<true> ar(pruned_ss);
        CHECK_AND_ASSERT_THROW_MES(do_serialize(ar, cntx), "Tx failed to serialize");

        tx_blob = pruned_ss.str();
    }

    return {std::move(tx_blob), ss.str()};
}

std::array<std::string, 2> load_and_save_txvariant_json_archive_output(const std::string &file_name)
{
    const boost::filesystem::path tx_path = unit_test::data_dir / "txs" / file_name;

    std::string tx_blob;
    CHECK_AND_ASSERT_THROW_MES(epee::file_io_utils::load_file_to_string(tx_path.string(), tx_blob),
        "file " << file_name << " failed to load to string");

    std::stringstream expected_dgb_out;
    {
        cryptonote::transaction tx;
        CHECK_AND_ASSERT_THROW_MES(cryptonote::parse_and_validate_tx_from_blob(tx_blob, tx), "deserialization failed");
        json_archive<true> ar(expected_dgb_out);
        CHECK_AND_ASSERT_THROW_MES(::serialization::serialize(ar, tx), "serialization failed");
    }

    std::stringstream actual_dgb_out;
    {
        MoneroTxVariant tx;
        {
            binary_archive<false> ar(epee::strspan<uint8_t>(tx_blob));
            CHECK_AND_ASSERT_THROW_MES(::serialization::serialize(ar, tx), "deserialization failed");
        }

        {
            json_archive<true> ar(actual_dgb_out);
            CHECK_AND_ASSERT_THROW_MES(::serialization::serialize(ar, tx), "serialization failed");
        }
    }

    return {expected_dgb_out.str(), actual_dgb_out.str()};
}
} // anonymous namespace

//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_serialization, seraphis_coinbase_empty)
{
    // make empty tx
    SpTxCoinbaseV1 tx{};

    // serialize the tx
    std::string serialized_tx;
    EXPECT_TRUE(::serialization::dump_binary(tx, serialized_tx));

    // recover the tx
    SpTxCoinbaseV1 recovered_tx;
    EXPECT_TRUE(::serialization::parse_binary(serialized_tx, recovered_tx));

    // check that the original tx was recovered
    rct::key original_tx_id;
    rct::key recovered_tx_id;

    EXPECT_NO_THROW(get_sp_tx_coinbase_v1_txid(tx, original_tx_id));
    EXPECT_NO_THROW(get_sp_tx_coinbase_v1_txid(recovered_tx, recovered_tx_id));

    EXPECT_TRUE(original_tx_id == recovered_tx_id);
    EXPECT_NO_THROW(EXPECT_TRUE(sp_tx_coinbase_v1_size_bytes(tx) == sp_tx_coinbase_v1_size_bytes(recovered_tx)));
}
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_serialization, seraphis_coinbase_empty_variant)
{
    // make empty tx
    MoneroTxVariant tx = SpTxCoinbaseV1{};

    // serialize the tx
    std::string serialized_tx;
    EXPECT_TRUE(::serialization::dump_binary(tx, serialized_tx));

    // recover the tx
    MoneroTxVariant recovered_tx;
    EXPECT_TRUE(::serialization::parse_binary(serialized_tx, recovered_tx));

    // check that the original tx was recovered
    rct::key original_tx_id;
    rct::key recovered_tx_id;

    EXPECT_NO_THROW(get_sp_tx_coinbase_v1_txid(tx.unwrap<SpTxCoinbaseV1>(), original_tx_id));
    EXPECT_NO_THROW(get_sp_tx_coinbase_v1_txid(recovered_tx.unwrap<SpTxCoinbaseV1>(), recovered_tx_id));

    EXPECT_TRUE(original_tx_id == recovered_tx_id);
    EXPECT_NO_THROW(EXPECT_TRUE(sp_tx_coinbase_v1_size_bytes(tx.unwrap<SpTxCoinbaseV1>())
        == sp_tx_coinbase_v1_size_bytes(recovered_tx.unwrap<SpTxCoinbaseV1>())));
}
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_serialization, seraphis_squashed_empty)
{
    // make empty tx
    SpTxSquashedV1 tx{};

    // serialize the tx
    std::string serialized_tx;
    EXPECT_TRUE(::serialization::dump_binary(tx, serialized_tx));

    // recover the tx
    SpTxSquashedV1 recovered_tx;
    EXPECT_TRUE(::serialization::parse_binary(serialized_tx, recovered_tx));

    // check that the original tx was recovered
    rct::key original_tx_id;
    rct::key recovered_tx_id;

    EXPECT_NO_THROW(get_sp_tx_squashed_v1_txid(tx, original_tx_id));
    EXPECT_NO_THROW(get_sp_tx_squashed_v1_txid(recovered_tx, recovered_tx_id));

    EXPECT_TRUE(original_tx_id == recovered_tx_id);
    EXPECT_NO_THROW(EXPECT_TRUE(sp_tx_squashed_v1_size_bytes(tx) == sp_tx_squashed_v1_size_bytes(recovered_tx)));
}
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_serialization, seraphis_squashed_empty_variant)
{
    // make empty tx
    MoneroTxVariant tx = SpTxSquashedV1{};

    // serialize the tx
    std::string serialized_tx;
    EXPECT_TRUE(::serialization::dump_binary(tx, serialized_tx));

    // recover the tx
    MoneroTxVariant recovered_tx;
    EXPECT_TRUE(::serialization::parse_binary(serialized_tx, recovered_tx));

    // check that the original tx was recovered
    rct::key original_tx_id;
    rct::key recovered_tx_id;

    EXPECT_NO_THROW(get_sp_tx_squashed_v1_txid(tx.unwrap<SpTxSquashedV1>(), original_tx_id));
    EXPECT_NO_THROW(get_sp_tx_squashed_v1_txid(recovered_tx.unwrap<SpTxSquashedV1>(), recovered_tx_id));

    EXPECT_TRUE(original_tx_id == recovered_tx_id);
    EXPECT_NO_THROW(EXPECT_TRUE(sp_tx_squashed_v1_size_bytes(tx.unwrap<SpTxSquashedV1>())
        == sp_tx_squashed_v1_size_bytes(recovered_tx.unwrap<SpTxSquashedV1>())));
}
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_serialization, seraphis_coinbase_standard)
{
    // ledger context
    MockLedgerContext ledger_context{0, 10000};
    const TxValidationContextMock tx_validation_context{ledger_context, {}};

    // make a tx
    SpTxCoinbaseV1 tx;
    make_mock_tx<SpTxCoinbaseV1>(SpTxParamPackV1{.output_amounts = {1}}, ledger_context, tx);

    // serialize the tx
    std::string serialized_tx;
    EXPECT_TRUE(::serialization::dump_binary(tx, serialized_tx));

    // recover the tx
    SpTxCoinbaseV1 recovered_tx;
    EXPECT_TRUE(::serialization::parse_binary(serialized_tx, recovered_tx));

    // check the tx was recovered
    rct::key original_tx_id;
    rct::key recovered_tx_id;

    EXPECT_NO_THROW(get_sp_tx_coinbase_v1_txid(tx, original_tx_id));
    EXPECT_NO_THROW(get_sp_tx_coinbase_v1_txid(recovered_tx, recovered_tx_id));

    EXPECT_TRUE(original_tx_id == recovered_tx_id);
    EXPECT_NO_THROW(EXPECT_TRUE(sp_tx_coinbase_v1_size_bytes(tx) == sp_tx_coinbase_v1_size_bytes(recovered_tx)));
    EXPECT_TRUE(validate_tx(tx, tx_validation_context));
    EXPECT_TRUE(validate_tx(recovered_tx, tx_validation_context));
}
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_serialization, seraphis_coinbase_standard_variant)
{
    // ledger context
    MockLedgerContext ledger_context{0, 10000};
    const TxValidationContextMock tx_validation_context{ledger_context, {}};

    // make a tx
    MoneroTxVariant tx = SpTxCoinbaseV1{};
    make_mock_tx<SpTxCoinbaseV1>(SpTxParamPackV1{.output_amounts = {1}}, ledger_context, tx.unwrap<SpTxCoinbaseV1>());

    // serialize the tx
    std::string serialized_tx;
    EXPECT_TRUE(::serialization::dump_binary(tx, serialized_tx));

    // recover the tx
    MoneroTxVariant recovered_tx;
    EXPECT_TRUE(::serialization::parse_binary(serialized_tx, recovered_tx));

    // check the tx was recovered
    rct::key original_tx_id;
    rct::key recovered_tx_id;

    EXPECT_NO_THROW(get_sp_tx_coinbase_v1_txid(tx.unwrap<SpTxCoinbaseV1>(), original_tx_id));
    EXPECT_NO_THROW(get_sp_tx_coinbase_v1_txid(recovered_tx.unwrap<SpTxCoinbaseV1>(), recovered_tx_id));

    EXPECT_TRUE(original_tx_id == recovered_tx_id);
    EXPECT_NO_THROW(EXPECT_TRUE(sp_tx_coinbase_v1_size_bytes(tx.unwrap<SpTxCoinbaseV1>())
        == sp_tx_coinbase_v1_size_bytes(recovered_tx.unwrap<SpTxCoinbaseV1>())));
    EXPECT_TRUE(validate_tx(tx.unwrap<SpTxCoinbaseV1>(), tx_validation_context));
    EXPECT_TRUE(validate_tx(recovered_tx.unwrap<SpTxCoinbaseV1>(), tx_validation_context));
}
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_serialization, seraphis_squashed_standard)
{
    // config
    SpTxParamPackV1 tx_params;

    tx_params.legacy_ring_size = 2;
    tx_params.ref_set_decomp_n = 2;
    tx_params.ref_set_decomp_m = 2;
    tx_params.bin_config =
        SpBinnedReferenceSetConfigV1{
            .bin_radius = 1,
            .num_bin_members = 1
        };
    tx_params.legacy_input_amounts = {1};
    tx_params.sp_input_amounts = {2, 3};
    tx_params.output_amounts = {3};
    tx_params.discretized_fee = discretize_fee(3);

    const SemanticConfigSpRefSetV1 sp_ref_set_config{
            .decomp_n = tx_params.ref_set_decomp_n,
            .decomp_m = tx_params.ref_set_decomp_m,
            .bin_radius = tx_params.bin_config.bin_radius,
            .num_bin_members = tx_params.bin_config.num_bin_members,
        };

    // ledger context
    MockLedgerContext ledger_context{0, 10000};
    const TxValidationContextMock tx_validation_context{ledger_context, sp_ref_set_config};

    // make a tx
    SpTxSquashedV1 tx;
    make_mock_tx<SpTxSquashedV1>(tx_params, ledger_context, tx);

    // serialize the tx
    std::string serialized_tx;
    EXPECT_TRUE(::serialization::dump_binary(tx, serialized_tx));

    // recover the tx
    SpTxSquashedV1 recovered_tx;
    EXPECT_TRUE(::serialization::parse_binary(serialized_tx, recovered_tx));

    // check the tx was recovered
    rct::key original_tx_id;
    rct::key recovered_tx_id;

    EXPECT_NO_THROW(get_sp_tx_squashed_v1_txid(tx, original_tx_id));
    EXPECT_NO_THROW(get_sp_tx_squashed_v1_txid(recovered_tx, recovered_tx_id));

    EXPECT_TRUE(original_tx_id == recovered_tx_id);
    EXPECT_NO_THROW(EXPECT_TRUE(sp_tx_squashed_v1_size_bytes(tx) == sp_tx_squashed_v1_size_bytes(recovered_tx)));
    EXPECT_TRUE(validate_tx(tx, tx_validation_context));
    EXPECT_TRUE(validate_tx(recovered_tx, tx_validation_context));
}
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_serialization, seraphis_squashed_standard_variant)
{
    // config
    SpTxParamPackV1 tx_params;

    tx_params.legacy_ring_size = 2;
    tx_params.ref_set_decomp_n = 2;
    tx_params.ref_set_decomp_m = 2;
    tx_params.bin_config =
        SpBinnedReferenceSetConfigV1{
            .bin_radius = 1,
            .num_bin_members = 1
        };
    tx_params.legacy_input_amounts = {1};
    tx_params.sp_input_amounts = {2, 3};
    tx_params.output_amounts = {3};
    tx_params.discretized_fee = discretize_fee(3);

    const SemanticConfigSpRefSetV1 sp_ref_set_config{
            .decomp_n = tx_params.ref_set_decomp_n,
            .decomp_m = tx_params.ref_set_decomp_m,
            .bin_radius = tx_params.bin_config.bin_radius,
            .num_bin_members = tx_params.bin_config.num_bin_members,
        };

    // ledger context
    MockLedgerContext ledger_context{0, 10000};
    const TxValidationContextMock tx_validation_context{ledger_context, sp_ref_set_config};

    // make a tx
    MoneroTxVariant tx = SpTxSquashedV1{};
    make_mock_tx<SpTxSquashedV1>(tx_params, ledger_context, tx.unwrap<SpTxSquashedV1>());

    // serialize the tx
    std::string serialized_tx;
    EXPECT_TRUE(::serialization::dump_binary(tx, serialized_tx));

    // recover the tx
    MoneroTxVariant recovered_tx;
    EXPECT_TRUE(::serialization::parse_binary(serialized_tx, recovered_tx));

    // check the tx was recovered
    rct::key original_tx_id;
    rct::key recovered_tx_id;

    EXPECT_NO_THROW(get_sp_tx_squashed_v1_txid(tx.unwrap<SpTxSquashedV1>(), original_tx_id));
    EXPECT_NO_THROW(get_sp_tx_squashed_v1_txid(recovered_tx.unwrap<SpTxSquashedV1>(), recovered_tx_id));

    EXPECT_TRUE(original_tx_id == recovered_tx_id);
    EXPECT_NO_THROW(EXPECT_TRUE(sp_tx_squashed_v1_size_bytes(tx.unwrap<SpTxSquashedV1>())
        == sp_tx_squashed_v1_size_bytes(recovered_tx.unwrap<SpTxSquashedV1>())));
    EXPECT_TRUE(validate_tx(tx.unwrap<SpTxSquashedV1>(), tx_validation_context));
    EXPECT_TRUE(validate_tx(recovered_tx.unwrap<SpTxSquashedV1>(), tx_validation_context));
}
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_serialization, jamtis_destination_v1)
{
    // generate
    JamtisDestinationV1 dest{gen_jamtis_destination_v1()};

    // serialize
    std::string serialized_dest;
    EXPECT_TRUE(::serialization::dump_binary(dest, serialized_dest));

    // deserialize
    JamtisDestinationV1 recovered_dest;
    EXPECT_TRUE(::serialization::parse_binary(serialized_dest, recovered_dest));

    // compare
    EXPECT_EQ(dest, recovered_dest);
}
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_serialization, jamtis_payment_proposal_v1)
{
    // generate
    JamtisPaymentProposalV1 payprop{gen_jamtis_payment_proposal_v1(7, 3)};

    // serialize
    std::string serialized_payprop;
    EXPECT_TRUE(::serialization::dump_binary(payprop, serialized_payprop));

    // deserialize
    JamtisPaymentProposalV1 recovered_payprop;
    EXPECT_TRUE(::serialization::parse_binary(serialized_payprop, recovered_payprop));

    // compare
    EXPECT_EQ(payprop, recovered_payprop);
}
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_serialization, jamtis_payment_proposal_self_send_v1)
{
    // generate
    JamtisPaymentProposalSelfSendV1 payprop{
            gen_jamtis_selfsend_payment_proposal_v1(7, JamtisSelfSendType::SELF_SPEND, 3)
        };

    // serialize
    std::string serialized_payprop;
    EXPECT_TRUE(::serialization::dump_binary(payprop, serialized_payprop));

    // deserialize
    JamtisPaymentProposalSelfSendV1 recovered_payprop;
    EXPECT_TRUE(::serialization::parse_binary(serialized_payprop, recovered_payprop));

    // compare
    EXPECT_EQ(payprop, recovered_payprop);
}
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_serialization, load_and_compare_cn_txs)
{
    EXPECT_TRUE(load_monero_tx_variant_and_compare_cn("rct_full_tx_14056427.bin"));
    EXPECT_TRUE(load_monero_tx_variant_and_compare_cn("rct_simple_tx_c69861bf.bin"));
    EXPECT_TRUE(load_monero_tx_variant_and_compare_cn("rct_bp_tx_a685d68e.bin"));
    EXPECT_TRUE(load_monero_tx_variant_and_compare_cn("rct_bp_compact_tx_10312fd4.bin"));
    EXPECT_TRUE(load_monero_tx_variant_and_compare_cn("rct_clsag_tx_200c3215.bin"));
    EXPECT_TRUE(load_monero_tx_variant_and_compare_cn("bpp_tx_e89415.bin"));
    EXPECT_TRUE(load_monero_tx_variant_and_compare_cn("v1_coinbase_tx_bf4c0300.bin"));
    EXPECT_TRUE(load_monero_tx_variant_and_compare_cn("v1_tx_hf3_effcceb9.bin"));
    EXPECT_TRUE(load_monero_tx_variant_and_compare_cn("v2_coinbase_tx_7f88a52a.bin"));
}
//-------------------------------------------------------------------------------------------------------------------
#define SUBTEST_LOAD_AND_SAVE_COMPARE_BLOB(fname)                \
    do {                                                         \
        const auto blobs = load_and_save_txvariant_blobs(fname); \
        EXPECT_EQ(blobs[0], blobs[1]);                           \
    } while (0);

TEST(seraphis_serialization, load_and_save_cn_txs_compare_blob)
{
    SUBTEST_LOAD_AND_SAVE_COMPARE_BLOB("rct_full_tx_14056427.bin");
    SUBTEST_LOAD_AND_SAVE_COMPARE_BLOB("rct_simple_tx_c69861bf.bin");
    SUBTEST_LOAD_AND_SAVE_COMPARE_BLOB("rct_bp_tx_a685d68e.bin");
    SUBTEST_LOAD_AND_SAVE_COMPARE_BLOB("rct_bp_compact_tx_10312fd4.bin");
    SUBTEST_LOAD_AND_SAVE_COMPARE_BLOB("rct_clsag_tx_200c3215.bin");
    SUBTEST_LOAD_AND_SAVE_COMPARE_BLOB("bpp_tx_e89415.bin");
    SUBTEST_LOAD_AND_SAVE_COMPARE_BLOB("v1_coinbase_tx_bf4c0300.bin");
    SUBTEST_LOAD_AND_SAVE_COMPARE_BLOB("v1_tx_hf3_effcceb9.bin");
    SUBTEST_LOAD_AND_SAVE_COMPARE_BLOB("v2_coinbase_tx_7f88a52a.bin");
}
//-------------------------------------------------------------------------------------------------------------------
#define SUBTEST_LOAD_AND_SAVE_COMPARE_JSON_OUTPUT(fname)                       \
    do {                                                                       \
        const auto blobs = load_and_save_txvariant_json_archive_output(fname); \
        EXPECT_EQ(blobs[0], blobs[1]);                                         \
    } while (0);

TEST(seraphis_serialization, load_and_save_cn_txs_compare_json_archive_output)
{
    SUBTEST_LOAD_AND_SAVE_COMPARE_JSON_OUTPUT("rct_full_tx_14056427.bin");
    SUBTEST_LOAD_AND_SAVE_COMPARE_JSON_OUTPUT("rct_simple_tx_c69861bf.bin");
    SUBTEST_LOAD_AND_SAVE_COMPARE_JSON_OUTPUT("rct_bp_tx_a685d68e.bin");
    SUBTEST_LOAD_AND_SAVE_COMPARE_JSON_OUTPUT("rct_bp_compact_tx_10312fd4.bin");
    SUBTEST_LOAD_AND_SAVE_COMPARE_JSON_OUTPUT("rct_clsag_tx_200c3215.bin");
    SUBTEST_LOAD_AND_SAVE_COMPARE_JSON_OUTPUT("bpp_tx_e89415.bin");
    SUBTEST_LOAD_AND_SAVE_COMPARE_JSON_OUTPUT("v1_coinbase_tx_bf4c0300.bin");
    SUBTEST_LOAD_AND_SAVE_COMPARE_JSON_OUTPUT("v1_tx_hf3_effcceb9.bin");
    SUBTEST_LOAD_AND_SAVE_COMPARE_JSON_OUTPUT("v2_coinbase_tx_7f88a52a.bin");
}
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_serialization, load_and_compare_cn_txs_pruned)
{
    EXPECT_TRUE(load_monero_tx_variant_and_compare_cn("rct_full_tx_14056427.bin", /*pruned=*/true));
    EXPECT_TRUE(load_monero_tx_variant_and_compare_cn("rct_simple_tx_c69861bf.bin", /*pruned=*/true));
    EXPECT_TRUE(load_monero_tx_variant_and_compare_cn("rct_bp_tx_a685d68e.bin", /*pruned=*/true));
    EXPECT_TRUE(load_monero_tx_variant_and_compare_cn("rct_bp_compact_tx_10312fd4.bin", /*pruned=*/true));
    EXPECT_TRUE(load_monero_tx_variant_and_compare_cn("rct_clsag_tx_200c3215.bin", /*pruned=*/true));
    EXPECT_TRUE(load_monero_tx_variant_and_compare_cn("bpp_tx_e89415.bin", /*pruned=*/true));
    EXPECT_TRUE(load_monero_tx_variant_and_compare_cn("v1_coinbase_tx_bf4c0300.bin", /*pruned=*/true));
    EXPECT_TRUE(load_monero_tx_variant_and_compare_cn("v1_tx_hf3_effcceb9.bin", /*pruned=*/true));
    EXPECT_TRUE(load_monero_tx_variant_and_compare_cn("v2_coinbase_tx_7f88a52a.bin", /*pruned=*/true));
}
//-------------------------------------------------------------------------------------------------------------------
#define SUBTEST_LOAD_AND_SAVE_COMPARE_BLOB_PRUNED(fname)                          \
    do {                                                                          \
        const auto blobs = load_and_save_txvariant_blobs(fname, /*pruned=*/true); \
        EXPECT_EQ(blobs[0], blobs[1]);                                            \
    } while (0);

TEST(seraphis_serialization, load_and_save_cn_txs_compare_blob_pruned)
{
    SUBTEST_LOAD_AND_SAVE_COMPARE_BLOB_PRUNED("rct_full_tx_14056427.bin");
    SUBTEST_LOAD_AND_SAVE_COMPARE_BLOB_PRUNED("rct_simple_tx_c69861bf.bin");
    SUBTEST_LOAD_AND_SAVE_COMPARE_BLOB_PRUNED("rct_bp_tx_a685d68e.bin");
    SUBTEST_LOAD_AND_SAVE_COMPARE_BLOB_PRUNED("rct_bp_compact_tx_10312fd4.bin");
    SUBTEST_LOAD_AND_SAVE_COMPARE_BLOB_PRUNED("rct_clsag_tx_200c3215.bin");
    SUBTEST_LOAD_AND_SAVE_COMPARE_BLOB_PRUNED("bpp_tx_e89415.bin");
    SUBTEST_LOAD_AND_SAVE_COMPARE_BLOB_PRUNED("v1_coinbase_tx_bf4c0300.bin");
    SUBTEST_LOAD_AND_SAVE_COMPARE_BLOB_PRUNED("v1_tx_hf3_effcceb9.bin");
    SUBTEST_LOAD_AND_SAVE_COMPARE_BLOB_PRUNED("v2_coinbase_tx_7f88a52a.bin");
}
//-------------------------------------------------------------------------------------------------------------------

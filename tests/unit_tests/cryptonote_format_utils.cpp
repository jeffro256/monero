// Copyright (c) 2025, The Monero Project
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

#include "gtest/gtest.h"

#include "crypto/generators.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "serialization/binary_utils.h"
#include "serialization/string.h"
#include "string_tools.h"

TEST(cn_format_utils, add_extra_nonce_to_tx_extra)
{
    static constexpr std::size_t max_nonce_size = TX_EXTRA_NONCE_MAX_COUNT + 1; // we *can* test higher if desired

    for (int empty_prefix = 0; empty_prefix < 2; ++empty_prefix)
    {
        std::vector<std::uint8_t> extra_prefix;
        if (!empty_prefix)
            cryptonote::add_tx_pub_key_to_extra(extra_prefix, crypto::get_H());

        std::vector<std::uint8_t> extra;
        std::string nonce;
        std::vector<cryptonote::tx_extra_field> tx_extra_fields;
        extra.reserve(extra_prefix.size() + max_nonce_size + 1 + 10);
        nonce.reserve(max_nonce_size);
        tx_extra_fields.reserve(2);
        for (std::size_t nonce_size = 0; nonce_size <= max_nonce_size; ++nonce_size)
        {
            extra = extra_prefix;
            nonce.resize(nonce_size);
            if (nonce.size())
                memset(&nonce[0], '%', nonce.size());
            tx_extra_fields.clear();

            const std::size_t expected_extra_size = extra_prefix.size() + 1
                + tools::get_varint_byte_size(nonce_size) + nonce_size;
            const bool expected_success = nonce_size <= TX_EXTRA_NONCE_MAX_COUNT;

            // add nonce and do detailed test
            const bool add_success = cryptonote::add_extra_nonce_to_tx_extra(extra, nonce);
            ASSERT_EQ(expected_success, add_success);
            if (!expected_success)
                continue;
            ASSERT_EQ(expected_extra_size, extra.size());
            ASSERT_EQ(0, memcmp(extra_prefix.data(), extra.data(), extra_prefix.size()));
            const std::uint8_t *p = extra.data() + extra_prefix.size();
            ASSERT_EQ(TX_EXTRA_NONCE, *p);
            ++p;
            std::size_t read_nonce_size = 0;
            const int varint_size = tools::read_varint((const uint8_t*)(p), // copy p
                (const uint8_t*) extra.data() + extra.size(),
                read_nonce_size);
            ASSERT_EQ(tools::get_varint_byte_size(nonce_size), varint_size);
            p += varint_size;
            for (std::size_t i = 0; i < nonce_size; ++i)
            {
                ASSERT_EQ('%', *p);
                ++p;
            }
            ASSERT_EQ(extra.data() + extra.size(), p);

            // do integration test with higher-level tx_extra parsing code
            ASSERT_TRUE(cryptonote::parse_tx_extra(extra, tx_extra_fields));
            if (empty_prefix)
            {
                ASSERT_EQ(1, tx_extra_fields.size());
                const auto &nonce_field = boost::get<cryptonote::tx_extra_nonce>(tx_extra_fields.at(0));
                ASSERT_EQ(nonce, nonce_field.nonce);
            }
            else
            {
                ASSERT_EQ(2, tx_extra_fields.size());
                const auto &pk_field = boost::get<cryptonote::tx_extra_pub_key>(tx_extra_fields.at(0));
                ASSERT_EQ(crypto::get_H(), pk_field.pub_key);
                const auto &nonce_field = boost::get<cryptonote::tx_extra_nonce>(tx_extra_fields.at(1));
                ASSERT_EQ(nonce, nonce_field.nonce);
            }
        }
    }
}

TEST(cn_format_utils, block_longhash_202612_arbitrary_blob)
{
    const cryptonote::blobdata blob = "not the historical block 202612 hashing blob";
    const crypto::hash pow_hash = cryptonote::get_block_longhash(blob, 202612, 1, crypto::null_hash);

    ASSERT_NE("84f64766475d51837ac9efbef1926486e58563c95a19fef4aec3254f03000000", epee::string_tools::pod_to_hex(pow_hash));
}

TEST(cn_format_utils, block_longhash_202612_mainnet_blob)
{
    cryptonote::blobdata hashing_blob;
    ASSERT_TRUE(epee::string_tools::parse_hexstr_to_binbuff(
        "01009ad29fa0055da0a3d004c352a90cc86b00fab676695d76a4d1de16036c41"
        "ba4dd188c4d76f46090040f353c96de74c53f87389b66fa625ed1f8676beeb"
        "5d47b4f0193bd16b584933be8204",
        hashing_blob));

    crypto::hash block_id;
    ASSERT_TRUE(cryptonote::get_object_hash(hashing_blob, block_id));
    ASSERT_EQ("426d16cff04c71f8b16340b722dc4010a2dd3831c22041431f772547ba6e331a", epee::string_tools::pod_to_hex(block_id));

    const crypto::hash pow_hash = cryptonote::get_block_longhash(hashing_blob, 202612, 1, crypto::null_hash);
    ASSERT_EQ("84f64766475d51837ac9efbef1926486e58563c95a19fef4aec3254f03000000", epee::string_tools::pod_to_hex(pow_hash));
}

TEST(cn_format_utils, block_longhash_202612_stagenet_blob)
{
    cryptonote::blobdata block_blob;
    ASSERT_TRUE(epee::string_tools::parse_hexstr_to_binbuff(
        "0909d4809fdf05d5df6c3eb5891d81c51c6f9fe4c3ae388889dfaf421b689ee8"
        "fe94b01d53d120cc4a87f602b0af0c01fff4ae0c01ecfe92f3aecd0502f887e4"
        "421dee42ee9699484f942b180be8d66d1e24a35f8c945950bed59bf436210164"
        "d9b0ae5889a127970bde60acd99f84fd79f61db7626331f074d062076c3ce40000",
        block_blob));

    cryptonote::block block;
    crypto::hash block_id;
    ASSERT_TRUE(cryptonote::parse_and_validate_block_from_blob(block_blob, block, block_id));
    ASSERT_EQ("f3449e658b5f880c4b0e69007ed5d092c9c883ac3a518166fa652d5cc505e7b1", epee::string_tools::pod_to_hex(block_id));

    const cryptonote::blobdata hashing_blob = cryptonote::get_block_hashing_blob(block);
    ASSERT_TRUE(cryptonote::get_object_hash(hashing_blob, block_id));
    ASSERT_EQ("f3449e658b5f880c4b0e69007ed5d092c9c883ac3a518166fa652d5cc505e7b1", epee::string_tools::pod_to_hex(block_id));

    crypto::hash calculated_block_id;
    ASSERT_TRUE(cryptonote::calculate_block_hash(block, calculated_block_id));
    ASSERT_EQ(block_id, calculated_block_id);

    const crypto::hash pow_hash = cryptonote::get_block_longhash(hashing_blob, 202612, 9, crypto::null_hash);
    ASSERT_EQ("84f64766475d51837ac9efbef1926486e58563c95a19fef4aec3254f03000000", epee::string_tools::pod_to_hex(pow_hash));
}

TEST(cn_format_utils, add_mm_merkle_root_to_tx_extra)
{
    const std::vector<std::uint64_t> depths{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 63, 64, 127, 128, 16383, 16384};

    const crypto::hash mm_merkle_root = crypto::rand<crypto::hash>();

    for (int empty_prefix = 0; empty_prefix < 2; ++empty_prefix)
    {
        std::vector<std::uint8_t> extra_prefix;
        if (!empty_prefix)
            cryptonote::add_tx_pub_key_to_extra(extra_prefix, crypto::get_H());

        std::vector<std::uint8_t> extra;
        std::vector<cryptonote::tx_extra_field> tx_extra_fields;
        extra.reserve(extra_prefix.size() + 1 + 1 + 10 + 32);
        tx_extra_fields.reserve(2);
        for (std::uint64_t mm_merkle_tree_depth : depths)
        {
            extra = extra_prefix;
            tx_extra_fields.clear();

            const std::size_t expected_extra_size = extra_prefix.size() + 1 + 1
                + tools::get_varint_byte_size(mm_merkle_tree_depth) + 32;

            // add nonce and do detailed test
            const bool add_success = cryptonote::add_mm_merkle_root_to_tx_extra(extra, mm_merkle_root, mm_merkle_tree_depth);
            ASSERT_TRUE(add_success);
            ASSERT_EQ(expected_extra_size, extra.size());
            ASSERT_EQ(0, memcmp(extra_prefix.data(), extra.data(), extra_prefix.size()));
            const std::uint8_t *p = extra.data() + extra_prefix.size();
            ASSERT_EQ(TX_EXTRA_MERGE_MINING_TAG, *p);
            ++p;
            ASSERT_EQ(32 + tools::get_varint_byte_size(mm_merkle_tree_depth), *p);
            ++p;
            std::uint64_t read_depth = 0;
            const int varint_size = tools::read_varint((const uint8_t*)(p), // copy p
                (const uint8_t*) extra.data() + extra.size(),
                read_depth);
            ASSERT_EQ(tools::get_varint_byte_size(mm_merkle_tree_depth), varint_size);
            ASSERT_EQ(mm_merkle_tree_depth, read_depth);
            p += varint_size;
            ASSERT_EQ(0, memcmp(p, mm_merkle_root.data, sizeof(mm_merkle_root)));
            p += sizeof(crypto::hash);
            ASSERT_EQ(extra.data() + extra.size(), p);

            // do integration test with higher-level tx_extra parsing code
            ASSERT_TRUE(cryptonote::parse_tx_extra(extra, tx_extra_fields));
            if (empty_prefix)
            {
                ASSERT_EQ(1, tx_extra_fields.size());
                const auto &mm_field = boost::get<cryptonote::tx_extra_merge_mining_tag>(tx_extra_fields.at(0));
                ASSERT_EQ(mm_merkle_root, mm_field.merkle_root);
                ASSERT_EQ(mm_merkle_tree_depth, mm_field.depth);
            }
            else
            {
                ASSERT_EQ(2, tx_extra_fields.size());
                const auto &pk_field = boost::get<cryptonote::tx_extra_pub_key>(tx_extra_fields.at(0));
                ASSERT_EQ(crypto::get_H(), pk_field.pub_key);
                const auto &mm_field = boost::get<cryptonote::tx_extra_merge_mining_tag>(tx_extra_fields.at(1));
                ASSERT_EQ(mm_merkle_root, mm_field.merkle_root);
                ASSERT_EQ(mm_merkle_tree_depth, mm_field.depth);
            }
        }
    }
}

TEST(cn_format_utils, tx_extra_merge_mining_tag_store_load)
{
    const std::vector<std::uint64_t> depths{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 63, 64, 127, 128, 16383, 16384};

    const crypto::hash mm_merkle_root = crypto::rand<crypto::hash>();

    for (int empty_prefix = 0; empty_prefix < 2; ++empty_prefix)
    {
        std::vector<std::uint8_t> extra_prefix;
        if (!empty_prefix)
            cryptonote::add_tx_pub_key_to_extra(extra_prefix, crypto::get_H());

        std::vector<std::uint8_t> extra;
        std::vector<cryptonote::tx_extra_field> tx_extra_fields;
        extra.reserve(extra_prefix.size() + 1 + 1 + 10 + 32);
        tx_extra_fields.reserve(2);
        for (std::uint64_t mm_merkle_tree_depth : depths)
        {
            extra = extra_prefix;
            tx_extra_fields.clear();

            const std::size_t expected_extra_size = extra_prefix.size() + 1 + 1
                + tools::get_varint_byte_size(mm_merkle_tree_depth) + 32;

            // add nonce and do detailed test
            cryptonote::tx_extra_merge_mining_tag mm;
            mm.depth = mm_merkle_tree_depth;
            mm.merkle_root = mm_merkle_root;
            cryptonote::tx_extra_field extra_field = mm;
            std::string mm_blob;
            ASSERT_TRUE(::serialization::dump_binary(extra_field, mm_blob));
            extra.resize(extra.size() + mm_blob.size());
            memcpy(extra.data() + extra.size() - mm_blob.size(), mm_blob.data(), mm_blob.size());
            ASSERT_EQ(expected_extra_size, extra.size());
            ASSERT_EQ(0, memcmp(extra_prefix.data(), extra.data(), extra_prefix.size()));
            const std::uint8_t *p = extra.data() + extra_prefix.size();
            ASSERT_EQ(TX_EXTRA_MERGE_MINING_TAG, *p);
            ++p;
            ASSERT_EQ(32 + tools::get_varint_byte_size(mm_merkle_tree_depth), *p);
            ++p;
            std::uint64_t read_depth = 0;
            const int varint_size = tools::read_varint((const uint8_t*)(p), // copy p
                (const uint8_t*) extra.data() + extra.size(),
                read_depth);
            ASSERT_EQ(tools::get_varint_byte_size(mm_merkle_tree_depth), varint_size);
            ASSERT_EQ(mm_merkle_tree_depth, read_depth);
            p += varint_size;
            ASSERT_EQ(0, memcmp(p, mm_merkle_root.data, sizeof(mm_merkle_root)));
            p += sizeof(crypto::hash);
            ASSERT_EQ(extra.data() + extra.size(), p);

            // do integration test with higher-level tx_extra parsing code
            ASSERT_TRUE(cryptonote::parse_tx_extra(extra, tx_extra_fields));
            if (empty_prefix)
            {
                ASSERT_EQ(1, tx_extra_fields.size());
                const auto &mm_field = boost::get<cryptonote::tx_extra_merge_mining_tag>(tx_extra_fields.at(0));
                ASSERT_EQ(mm_merkle_root, mm_field.merkle_root);
                ASSERT_EQ(mm_merkle_tree_depth, mm_field.depth);
            }
            else
            {
                ASSERT_EQ(2, tx_extra_fields.size());
                const auto &pk_field = boost::get<cryptonote::tx_extra_pub_key>(tx_extra_fields.at(0));
                ASSERT_EQ(crypto::get_H(), pk_field.pub_key);
                const auto &mm_field = boost::get<cryptonote::tx_extra_merge_mining_tag>(tx_extra_fields.at(1));
                ASSERT_EQ(mm_merkle_root, mm_field.merkle_root);
                ASSERT_EQ(mm_merkle_tree_depth, mm_field.depth);
            }
        }
    }
}

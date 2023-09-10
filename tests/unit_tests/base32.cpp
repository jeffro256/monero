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

#include "gtest/gtest.h"

#include <cstddef>
#include <cstdlib>
#include <fstream>
#include <string>
#include <utility>
#include <vector>

#include "common/base32_monero.h"
#include "crypto/crypto.h"
#include "string_tools.h"
#include "unit_tests_utils.h"

TEST(base32, encode_decode)
{
    using base32 = cppcodec::base32_monero;

    for (size_t raw_len = 0; raw_len < 250; ++raw_len)
    {
        for (size_t i = 0; i < 10; ++i)
        {
            std::string raw_buf;
            raw_buf.resize(raw_len);
            crypto::generate_random_bytes_not_thread_safe(raw_buf.size(), &raw_buf[0]);

            const std::string encoded_buf = base32::encode(raw_buf);
            const std::vector<uint8_t> decoded_vec = base32::decode(encoded_buf);
            const std::string decoded_buf(reinterpret_cast<const char*>(decoded_vec.data()), decoded_vec.size());

            EXPECT_EQ(raw_buf, decoded_buf);
        }
    }
}

TEST(base32, jamtis_address_prefix_compat)
{
    using base32 = cppcodec::base32_monero;

    static constexpr const char NETTYPE_CHARS[3] = { 't', 's', 'm' };

    //      use 'v' chars here     VV    since it's invalid and we're forced to overwrite
    std::string addr_prefix = "xmravv00";

    // for version 1..9
    for (int ver = 1; ver <= 9; ++ver)
    {
        addr_prefix[4] = static_cast<char>(ver) + '0'; // xmra1v00, xmra2v00, ..., xmra9v00

        // for nettype in { t, s, m }
        for (const char netype_char : NETTYPE_CHARS)
        {
            addr_prefix[5] = netype_char; // xmravt00, xmravs00, xmravm00

            std::vector<uint8_t> raw_addr_bytes;
            EXPECT_NO_THROW(raw_addr_bytes = base32::decode(addr_prefix));
            EXPECT_EQ(5, raw_addr_bytes.size());

            // re-encode and check equality
            EXPECT_EQ(addr_prefix, base32::encode(raw_addr_bytes));
        }
    }
}

/*
TEST(base32, generate_random_data)
{
    using base32 = cppcodec::base32_monero;

    for (size_t raw_len = 0; raw_len < 250; ++raw_len)
    {
        std::string raw_buf;
        raw_buf.resize(raw_len);
        crypto::generate_random_bytes_not_thread_safe(raw_buf.size(), &raw_buf[0]);

        const std::string encoded_buf = base32::encode(raw_buf);
        const std::vector<uint8_t> decoded_vec = base32::decode(encoded_buf);
        const std::string decoded_buf(reinterpret_cast<const char*>(decoded_vec.data()), decoded_vec.size());

        std::cout << epee::string_tools::buff_to_hex_nodelimer(raw_buf) << " " << encoded_buf << std::endl;

        EXPECT_EQ(raw_buf, decoded_buf);
    }
}
*/

TEST(base32, future_modification_protection)
{
    using base32 = cppcodec::base32_monero;

    const boost::filesystem::path test_file_path = unit_test::data_dir / "base32" / "future_modification_protection.txt";

    // pairs of (hex encoding of random bytes, base32_monero encoding of random bytes)
    std::vector<std::pair<std::string, std::string>> test_cases;

    // read test cases from data file
    std::ifstream ifs(test_file_path.string());
    ASSERT_TRUE(ifs);
    while (ifs)
    {
        std::string hex_enc;
        ifs >> hex_enc;

        if (hex_enc.empty())
            break;

        std::string base32_enc;
        ifs >> base32_enc;

        ASSERT_FALSE(base32_enc.empty()); // we shouldn't run out of data on this part

        test_cases.push_back({hex_enc, base32_enc});
    }

    ASSERT_EQ(249, test_cases.size()); // there should be 249 test cases in the file

    for (const auto& test_case : test_cases)
    {
        // test that base32_encode(hex_decode(test_case.first)) == test_case.second

        std::string raw_buf;
        ASSERT_TRUE(epee::string_tools::parse_hexstr_to_binbuff(test_case.first, raw_buf));

        const std::string encoded_buf = base32::encode(raw_buf);

        EXPECT_EQ(test_case.second, encoded_buf);
    }
}
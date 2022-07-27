// Copyright (c) 2020-2022, The Monero Project

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

#include <cstdint>
#include <gtest/gtest.h>
#include <sstream>

#include "storages/portable_storage.h"
#include "portable_storage/binary/serializer_bin.h"
#include "portable_storage/json/serializer_json.h"
#include "span.h"

namespace {
  struct Data1 {
    int16_t val;

    template<class Serializer>
    void epee_serialize(Serializer& serializer) {
      auto obj = serializer.serialize_object();
      obj.start(1);
      obj.serialize_entry("val", 3, val);
      obj.end();
    }
  };
}

TEST(epee_binary, two_keys)
{
  static constexpr const std::uint8_t data[] = {
    0x01, 0x11, 0x01, 0x1, 0x01, 0x01, 0x02, 0x1, 0x1, 0x08, 0x01, 'a',
    0x0B, 0x00, 0x01, 'b', 0x0B, 0x00
  };

  epee::serialization::portable_storage storage{};
  EXPECT_TRUE(storage.load_from_binary(data));
}

TEST(epee_binary, duplicate_key)
{
  static constexpr const std::uint8_t data[] = {
    0x01, 0x11, 0x01, 0x1, 0x01, 0x01, 0x02, 0x1, 0x1, 0x08, 0x01, 'a',
    0x0B, 0x00, 0x01, 'a', 0x0B, 0x00
  };

  epee::serialization::portable_storage storage{};
  EXPECT_FALSE(storage.load_from_binary(data));
}

#define ARRAY_STR(a) std::string(reinterpret_cast<const char*>(a), sizeof(a))


TEST(epee_serialization, varint_serialize)
{
  constexpr size_t NUM_TESTS = 4;
  static constexpr const std::uint8_t bin_10[] = { 0x28 };
  static constexpr const std::uint8_t bin_100[] = { 0x91, 0x01 };
  static constexpr const std::uint8_t bin_100000[] = { 0x82, 0x1a, 0x06, 0x00};
  static constexpr const std::uint8_t bin_10000000000[] = {
    0x03, 0x90, 0x2f, 0x50,
    0x09, 0x00, 0x00, 0x00
  };

  size_t sizes[NUM_TESTS] = {10, 100, 100000, 10000000000};
  const uint8_t* varint_reps[NUM_TESTS] = { bin_10, bin_100, bin_100000, bin_10000000000 };
  const size_t varint_rep_sizes[NUM_TESTS] = { 1, 2, 4, 8 };

  for (size_t i = 0; i < sizeof(sizes) / sizeof(size_t); i++) {
    std::stringstream ss;
    const size_t varint_val = sizes[i];
    portable_storage::binary::write_varint(ss, varint_val);
    const std::string expected(reinterpret_cast<const char*>(varint_reps[i]), varint_rep_sizes[i]);
    EXPECT_EQ(expected, ss.str());
  }
}


TEST(epee_serialization, bin_serialize_1)
{
  using namespace portable_storage::binary;

  static constexpr const std::uint8_t expected_binary[] = {
    0x01, 0x11, 0x01, 0x01, // Signature A
    0x01, 0x01, 0x02, 0x01, // Signature B
    0x01,                   // Format Version
    0x04,                   // Varint number of entries
    0x03, 'v','a', 'l',     // entry key
    0x03,                   // entry type
    0xe7, 0x07              // INT16 value of 'val'
  };

  Data1 data = { 2023 };
  BinarySerializer<std::stringstream> bs = {std::stringstream()};
  data.epee_serialize(bs);
  std::string result = bs.move_inner_stream().str();

  EXPECT_EQ(ARRAY_STR(expected_binary), result);
}

TEST (epee_serialization, json_serialize_1)
{
  using namespace portable_storage::json;

  const std::string expected_json("{\"val\":2023}");

  Data1 data = { 2023 };
  JsonSerializer<std::stringstream> js = {std::stringstream()};
  data.epee_serialize(js);
  std::string result = js.move_inner_stream().str();

  EXPECT_EQ(expected_json, result);
}

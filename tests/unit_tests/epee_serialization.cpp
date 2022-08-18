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
#include "serde/epee/deserializer.h"
#include "serde/epee/serializer.h"
#include "serde/model/struct.h"
#include "serde/json/deserializer.h"
#include "serde/json/serializer.h"
#include "span.h"

namespace {
  struct Data1: public serde::model::Serializable
  {
    int16_t val;

    Data1(): serde::model::Serializable(), val() {}
    Data1(int64_t val): serde::model::Serializable(), val(val) {}

    PORTABLE_STORAGE_START_STRUCT()
      PORTABLE_STORAGE_FIELD(val)
    PORTABLE_STORAGE_END_STRUCT()

    bool operator==(const Data1& other) const
    {
      return val == other.val;
    }
  };

  struct StringData: public serde::model::Serializable
  {
    std::string str;

    StringData(): serde::model::Serializable(), str() {}
    StringData(std::string str): serde::model::Serializable(), str(str) {}

    PORTABLE_STORAGE_START_STRUCT()
      PORTABLE_STORAGE_FIELD(str)
    PORTABLE_STORAGE_END_STRUCT()
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

TEST(epee_serialization, bin_serialize_1)
{
  using namespace serde::epee;

  static constexpr const std::uint8_t expected_binary[] =
  {
    0x01, 0x11, 0x01, 0x01, // Signature A
    0x01, 0x01, 0x02, 0x01, // Signature B
    0x01,                   // Format Version
    0x04,                   // Varint number of entries
    0x03, 'v','a', 'l',     // entry key
    0x03,                   // entry type
    0xe7, 0x07              // INT16 value of 'val'
  };

  Data1 data = { 2023 };
  Serializer<std::stringstream> bs = {std::stringstream()};
  data.serialize_default(bs);
  std::string result = bs.move_inner_stream().str();

  EXPECT_EQ(ARRAY_STR(expected_binary), result);
}

TEST (epee_serialization, json_serialize_1)
{
  using namespace serde::json;

  const std::string expected_json("{\"val\":2023}");

  const Data1 data = { 2023 };
  Serializer<std::stringstream> js = {std::stringstream()};
  data.serialize_default(js);
  std::string result = js.move_inner_stream().str();

  EXPECT_EQ(expected_json, result);
}

TEST(epee_serialization, json_escape)
{
  using namespace serde::json;

  static const std::pair<StringData, std::string> test_cases[] =
  {
    { { "Howdy, World!" }, R"({"str":"Howdy, World!"})" },
    { { "New\nline"     }, R"({"str":"New\nline"})" },
    { { "\b\ruh"        }, R"({"str":"\b\ruh"})" },
    { { "\u1234"        }, "{\"str\":\"\u1234\"}" }, // not raw
  };

  for (const auto& test_case : test_cases) {
    const auto& input_instance = test_case.first;
    const auto& expected_json = test_case.second;

    Serializer<std::stringstream> js = {std::stringstream()};
    input_instance.serialize_default(js);
    const auto actual_json = js.move_inner_stream().str();

    EXPECT_EQ(expected_json, actual_json);
  }
}

TEST(epee_serialization, bin_deserialize_1)
{
  using namespace serde::epee;

  static constexpr const std::uint8_t source_binary[] =
  {
    0x01, 0x11, 0x01, 0x01, // Signature A
    0x01, 0x01, 0x02, 0x01, // Signature B
    0x01,                   // Format Version
    0x04,                   // Varint number of entries
    0x03, 'v','a', 'l',     // entry key
    0x03,                   // entry type
    0xe7, 0x07              // INT16 value of 'val'
  };

  const Data1 deserialized_data = from_bytes<Data1>(source_binary);
  const Data1 expected_data = { 2023 };
  EXPECT_EQ(expected_data, deserialized_data);
}

TEST(epee_serialization, json_deserialize_1)
{
  using namespace serde::json;

  const Data1 deserialized_data = from_cstr<Data1>("{\"val\":7777}");
  const Data1 expected_data = { 7777 };
  EXPECT_EQ(expected_data, deserialized_data);
}

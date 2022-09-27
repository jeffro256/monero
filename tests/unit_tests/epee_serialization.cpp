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

#include "cryptonote_protocol/cryptonote_protocol_defs.h"
#include "hex.h"
#include "memwipe.h"
#include "mlocker.h"
#include "p2p/net_node.h"
#include "serialization/wire/adapted/vector.h"
#include "serialization/wire/epee.h"
#include "serialization/wire/json.h"
#include "serialization/wire/wrappers_impl.h"
#include "storages/portable_storage_template_helper.h"
#include "span.h"

namespace {
  struct Data1
  {
    int16_t val;

    Data1(): val() {}
    Data1(int64_t val): val(val) {}

    BEGIN_KV_SERIALIZE_MAP()
      KV_SERIALIZE(val)
    END_KV_SERIALIZE_MAP()

    bool operator==(const Data1& other) const { return val == other.val; }
  }; // struct Data1
  WIRE_EPEE_DEFINE_CONVERSION(Data1);
  WIRE_JSON_DEFINE_CONVERSION(Data1);


  struct StringData
  {
    std::string str;

    StringData(): str() {}
    StringData(std::string str): str(str) {}

    BEGIN_KV_SERIALIZE_MAP()
      KV_SERIALIZE(str)
    END_KV_SERIALIZE_MAP()

    bool operator==(const StringData& other) const { return str == other.str; }
  }; // struct StringData
  WIRE_EPEE_DEFINE_CONVERSION(StringData);
  WIRE_JSON_DEFINE_CONVERSION(StringData);

  struct UnsignedData
  {
    uint64_t u64;
    uint32_t u32;
    uint16_t u16;
    uint8_t u8;

    BEGIN_KV_SERIALIZE_MAP()
      KV_SERIALIZE(u64)
      KV_SERIALIZE(u32)
      KV_SERIALIZE(u16)
      KV_SERIALIZE(u8)
    END_KV_SERIALIZE_MAP()

    bool operator==(const UnsignedData& other) const
    {
      return u64 == other.u64 && u32 == other.u32 && u16 == other.u16 && u8 == other.u8;
    }
  }; // struct UnsignedData
  WIRE_EPEE_DEFINE_CONVERSION(UnsignedData);
  WIRE_JSON_DEFINE_CONVERSION(UnsignedData);

  struct Data2
  {
    static_assert(wire::is_array<std::vector<bool>>::value, "vector<bool> can not be serialized as array");

    int64_t i64;
    int32_t i32;
    int16_t i16;
    int8_t i8;
    UnsignedData unsign;
    double triple;
    StringData sd;
    std::vector<int> booleans;

    BEGIN_KV_SERIALIZE_MAP()
      KV_SERIALIZE(i64)
      KV_SERIALIZE(i32)
      KV_SERIALIZE(i16)
      KV_SERIALIZE(i8)
      KV_SERIALIZE(unsign)
      KV_SERIALIZE(triple)
      KV_SERIALIZE(sd)
      KV_SERIALIZE_ARRAY(booleans, wire::min_element_size<1>)
    END_KV_SERIALIZE_MAP()

    bool operator==(const Data2& other) const {
      return i64 == other.i64 && i32 == other.i32 && i16 == other.i16 && i8 == other.i8 &&
        unsign == other.unsign && triple == other.triple && sd == other.sd && booleans == other.booleans;
    }
  }; // struct Data2
  WIRE_JSON_DEFINE_CONVERSION(Data2);

  struct int_blob
  {
    int16_t v;

    bool operator==(const int_blob& other) const {
      return v == other.v;
    }
  };

  template <size_t N>
  struct byte_blob
  {
    char buf[N];

    bool operator==(const byte_blob& other) const {
      return buf == other.buf;
    }
  };

  template <typename T>
  void load_t_from_hex_string_failable(const std::string& hex_src, T& val)
  {
    // convert from hex to binary string
    std::string bin_src;
    if (!epee::from_hex::to_string(bin_src, hex_src))
    {
      throw std::invalid_argument("hex conversion failed");
    }
    const epee::span<const uint8_t> bin_span{reinterpret_cast<const uint8_t*>(bin_src.data()), bin_src.size()};

    // deserialize
    wire::epee_reader deserializer(bin_span);
    read_bytes(deserializer, val);
  }

  template <typename T>
  void load_t_from_json_string_failable(const std::string& json_src, T& val)
  {
    wire::json_reader deserializer({json_src.data(), json_src.size()});
    read_bytes(deserializer, val);
  }
} // anonymous namespace

namespace wire { template <> struct is_blob<int_blob>: std::true_type {}; }
namespace wire { template <size_t N> struct is_blob<byte_blob<N>>: std::true_type {}; }

#define ARRAY_STR(a) std::string(reinterpret_cast<const char*>(a), sizeof(a))

TEST(epee_serialization, bin_serialize_1)
{
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

  const Data1 data = { 2023 };
  const epee::byte_slice actual_slice = epee::serialization::store_t_to_binary(data);
  const std::string expected = ARRAY_STR(expected_binary);
  const std::string actual{reinterpret_cast<const char*>(actual_slice.data()), actual_slice.size()};

  EXPECT_EQ(expected, actual);
}

TEST (epee_serialization, json_serialize_1)
{
  const std::string expected_json("{\"val\":2023}");

  const Data1 data = { 2023 };
  const std::string result = epee::serialization::store_t_to_json(data);

  EXPECT_EQ(expected_json, result);
}

TEST(epee_serialization, json_escape)
{
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

    const std::string actual_json = epee::serialization::store_t_to_json(input_instance);

    EXPECT_EQ(expected_json, actual_json);
  }
}

TEST(epee_serialization, bin_deserialize_1)
{
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

  Data1 deserialized_data;
  EXPECT_TRUE(epee::serialization::load_t_from_binary(deserialized_data, source_binary));
  const Data1 expected_data = { 2023 };
  EXPECT_EQ(expected_data, deserialized_data);
}

TEST(epee_serialization, json_deserialize_1)
{
  Data1 deserialized_data;
  std::string json_src = "{\"val\":7777}";
  //EXPECT_TRUE(epee::serialization::load_t_from_json(deserialized_data, json_src));
  load_t_from_json_string_failable(json_src, deserialized_data);
  const Data1 expected_data = { 7777 };
  EXPECT_EQ(expected_data, deserialized_data);
}

TEST(epee_serialization, json_deserialize_2)
{
  std::string json_data = R"({
    "i8": -5, "i16": -6, "i32": -7, "i64": -8,
    "unsign": { "u64": 1, "u32": 2, "u16": 3, "u8": 4 },
    "triple": 20.23,
    "sd": { "str": "meep meep"},
    "booleans": [1, 0, 1, 1, 0, 1, 0, 0]
  })";

  //const Data2 expected = { -8, -7, -6, -5, { 1, 2, 3, 4 }, 20.23, { "meep meep" }, { true, false, true, true, false, true, false, false } };
  const Data2 expected = { -8, -7, -6, -5, { 1, 2, 3, 4 }, 20.23, { "meep meep" }, { 1, 0, 1, 1, 0, 1, 0, 0 } };

  Data2 actual;
  EXPECT_TRUE(epee::serialization::load_t_from_json(actual, json_data));
  EXPECT_EQ(expected, actual);
}

TEST(epee_serialization, binary_slam_dunks)
{
  // Just throw a bunch of valid binary packets of existing types at the Deserializer and check
  // that it doesn't fail

  const std::string hex_src_1 =
    "0111010101010201010c037478738a089101656565656565656565656565656565656565656565656565656565656"
    "565656565656565656565656565656565656565656565656565656565656565656565656565656565656565656565"
    "656565656565656565656565656565656565656565656565652103666666666666666666666666666666666666666"
    "666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666"
    "666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666"
    "666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666"
    "6666666666666666666666666666666666666666666666666666666666666666666666666666666666015f0a9d0a2"
    "020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020"
    "202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202"
    "020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020"
    "202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202"
    "020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020"
    "202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202"
    "020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020"
    "202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202"
    "020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020"
    "202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202"
    "020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020"
    "202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202"
    "020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020"
    "202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202"
    "02020202020202020202020202020202020202020202020202020201164616e64656c696f6e70705f666c7566660b"
    "00";

  cryptonote::NOTIFY_NEW_TRANSACTIONS::request_t t_1;
  load_t_from_hex_string_failable(hex_src_1, t_1);

  std::cout << "meep" << std::endl;

  const std::string hex_src_2 =
    "0111010101010201010c096e6f64655f646174610c180a6e6574776f726b5f69640a401230f171610441611731008"
    "216a1a11007706565725f6964055cec85ffed1e9a42076d795f706f727406d0bb0000087270635f706f7274070000"
    "147270635f637265646974735f7065725f6861736806000000000d737570706f72745f666c61677306010000000c7"
    "061796c6f61645f646174610c180e63757272656e745f6865696768740500000000000000001563756d756c617469"
    "76655f646966666963756c74790500000000000000001b63756d756c61746976655f646966666963756c74795f746"
    "f70363405000000000000000006746f705f69640a8000000000000000000000000000000000000000000000000000"
    "000000000000000b746f705f76657273696f6e08000c7072756e696e675f736565640600000000126c6f63616c5f7"
    "06565726c6973745f6e6577";

  nodetool::COMMAND_HANDSHAKE_T<cryptonote::CORE_SYNC_DATA>::response t_2;
  load_t_from_hex_string_failable(hex_src_2, t_2);
}

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
#include "portable_storage/binary/deserializer.h"
#include "portable_storage/binary/serializer.h"
#include "portable_storage/model/deserialization.h"
#include "portable_storage/model/serialization.h"
#include "portable_storage/model/visitor.h"
#include "portable_storage/json/serializer.h"
#include "span.h"

#include "portable_storage/internal/external/byte_span.h" // @TODO: catch in main header
#include "portable_storage/internal/external/optional.h" // @TODO: catch in main header

using namespace portable_storage;

namespace {
  class SingleKeyVisitor: public model::GetSetVisitor<bool>
  {
  public:
    SingleKeyVisitor(const std::string key): m_key(key), model::GetSetVisitor<bool>() {}

    std::string expecting() const noexcept override final
    {
      return "key '" + m_key + "'";
    }

    void visit_key(const const_byte_span& deserialized_key) override final
    {
      this->set_visited(internal::byte_span_to_string(deserialized_key) == m_key);
    }

  private:
    std::string m_key;
  };

  struct Data1: public model::Serializable
  {
    int16_t val;

    Data1(): model::Serializable(), val() {}
    Data1(int64_t val): model::Serializable(), val(val) {}

    void serialize_default(model::Serializer& serializer) const override final {
      serializer.serialize_start_object(1);
      serializer.serialize_key(internal::cstr_to_byte_span("val"));
      serializer.serialize_int16(this->val);
      serializer.serialize_end_object();
    }

    static Data1 deserialize_default(model::Deserializer& deserializer);

    bool operator==(const Data1& other) const
    {
      return val == other.val;
    }
  };

  struct Data1Visitor: public model::GetSetVisitor<Data1>
  {
    std::string expecting() const noexcept override final
    {
      return "Data1 object";
    }

    void visit_object(optional<size_t> size, model::Deserializer& deserializer) override final
    {
      CHECK_AND_ASSERT_THROW_MES
      (
        size && *size == 1,
        "Got wrong number of entries"
      );

      CHECK_AND_ASSERT_THROW_MES
      (
        deserializer.continue_collection(),
        "Can't get first entry"
      );

      SingleKeyVisitor key_visitor("val");
      deserializer.deserialize_key(key_visitor);
      const bool got_key = key_visitor.get_visited();
      CHECK_AND_ASSERT_THROW_MES
      (
        got_key,
        "got bad key"
      );

      const int16_t val = model::Deserialize<int16_t>::dflt(deserializer);

      CHECK_AND_ASSERT_THROW_MES
      (
        !deserializer.continue_collection(),
        "entries aren't over"
      );

      this->set_visited({val});
    }
  };

  // @TODO: incomplete type nonsense
  Data1 Data1::deserialize_default(model::Deserializer& deserializer)
  { 
    Data1Visitor d1vis;
    deserializer.deserialize_object(1, d1vis);
    return d1vis.get_visited();
  }

  struct StringData: public model::Serializable
  {
    std::string str;

    StringData(std::string str): model::Serializable(), str(str) {}

    void serialize_default(model::Serializer& serializer) const override final {
      serializer.serialize_start_object(1);
      serializer.serialize_key(internal::cstr_to_byte_span("str"));
      serializer.serialize_string(this->str);
      serializer.serialize_end_object();
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

/*
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
*/

TEST(epee_serialization, bin_serialize_1)
{
  using namespace portable_storage::binary;

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
  using namespace portable_storage::json;

  const std::string expected_json("{\"val\":2023}");

  const Data1 data = { 2023 };
  Serializer<std::stringstream> js = {std::stringstream()};
  data.serialize_default(js);
  std::string result = js.move_inner_stream().str();

  EXPECT_EQ(expected_json, result);
}

TEST(epee_serialization, json_escape)
{
  using namespace portable_storage::json;

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
  using namespace portable_storage::binary;

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

  Deserializer deserializer(source_binary);
  const Data1 deserialized_data = model::Deserialize<Data1>::dflt(deserializer);
  const Data1 expected_data = { 2023 };
  EXPECT_EQ(expected_data, deserialized_data);
}
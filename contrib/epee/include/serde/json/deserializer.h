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

#pragma once

#include <vector>

#include "./deps.h"
#include "../internal/deps.h"
#include "../model/operator_deserialize.h"

namespace serde::json
{
    class Deserializer: public model::SelfDescribingDeserializer
    {
    public:

        // Rapidjson streams need null terminators so src string should have a null terminator.
        // The internal stream type is also non-owning so the src buffer must remain valid
        // throughout the entire lifetime of this Deserializer instance.
        Deserializer(const char* src);
        ~Deserializer() = default;

    ///////////////////////////////////////////////////////////////////////////
    // Deserializer interface                                                //
    ///////////////////////////////////////////////////////////////////////////

        void deserialize_any(model::BasicVisitor& visitor) override final;

        bool is_human_readable() const noexcept override final;

    ///////////////////////////////////////////////////////////////////////////
    // private helper methods / fields                                       //
    ///////////////////////////////////////////////////////////////////////////
    private:

        friend class JsonVisitorHandler;

        rapidjson::Reader m_json_reader;
        // Non-owning stream so buffer must remain valid the entire lifetime of the Deserializer.
        rapidjson::InsituStringStream m_istream;
    }; // class Deserializer

    template <typename T>
    T from_cstr(const char* src)
    {
        T value;
        Deserializer deserializer(src);
        CHECK_AND_ASSERT_THROW_MES
        (
            deserialize_default(deserializer, value),
            "JSON deserializer returned no data"
        );
        return value;
    }

    template <typename T>
    T from_file(const std::string& file_path)
    {
        std::string file_contents;
        // @TODO: maybe put a file size limit
        // @TODO: stream file contents into deserializer, not load entire file into memory
        CHECK_AND_ASSERT_THROW_MES(
            ::epee::file_io_utils::load_file_to_string(file_path, file_contents),
            "Could not read file contents from path '" << file_path << "'"
        );

        return from_cstr<T>(file_contents.c_str());
    }
} // namespace serde::json


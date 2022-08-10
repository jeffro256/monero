#pragma once

#include <string>

#include "../internal/container.h"
#include "../internal/endianness.h"
#include "../internal/external_libs.h"

namespace portable_storage::model
{
    ///////////////////////////////////////////////////////////////////////////
    // Forward declarations for compound Visitors                            //
    ///////////////////////////////////////////////////////////////////////////
    class Deserializer;

    template <typename Deserializable>
    struct Deserialize
    {
        static Deserializable dflt(Deserializer&);
    };

    ///////////////////////////////////////////////////////////////////////////
    // Visitor                                                               //
    ///////////////////////////////////////////////////////////////////////////

    template <typename Value>
    struct Visitor
    {
        using value_type = Value;

        Visitor() = default;
        virtual ~Visitor() {};

        virtual std::string expecting() const = 0;

        virtual Value visit_int64(int64_t value)
        {
            return this->visit_float64(value);
        }

        virtual Value visit_int32(int32_t value)
        {
            return this->visit_int64(value);
        }

        virtual Value visit_int16 (int16_t value)
        {
            return this->visit_int32(value);
        }

        virtual Value visit_int8(int8_t value)
        {
            return this->visit_int16(value);
        }

        virtual Value visit_uint64(uint64_t value)
        {
            return this->visit_float64(value);
        }

        virtual Value visit_uint32(uint32_t value)
        {
            return this->visit_uint64(value);
        }

        virtual Value visit_uint16(uint16_t value)
        {
            return this->visit_uint32(value);
        }

        virtual Value visit_uint8(uint8_t value)
        {
            return this->visit_uint16(value);
        }

        virtual Value visit_float64(double value)
        {
            ASSERT_MES_AND_THROW("visit_double() called while expecting: " << this->expecting());
        }

        virtual Value visit_bytes(const char* buf, size_t length)
        {
            ASSERT_MES_AND_THROW("visit_bytes() called while expecting: " << this->expecting());
        }

        virtual Value visit_boolean(bool value)
        {
            ASSERT_MES_AND_THROW("visit_boolean() called while expecting: " << this->expecting());
        }

        virtual Value visit_array(optional<size_t> size_hint, Deserializer& deserializer)
        {
            ASSERT_MES_AND_THROW("visit_array() called while expecting: " << this->expecting());
        }

        virtual Value visit_object(optional<size_t> size_hint, Deserializer& deserializer)
        {
            ASSERT_MES_AND_THROW("visit_object() called while expecting: " << this->expecting());
        }

        virtual Value visit_key(const char* str, uint8_t key_len)
        {
            ASSERT_MES_AND_THROW("visit_key() called while expecting: " << this->expecting());
        }
    }; // class Visitor
} // namespace portable_storage::model

namespace portable_storage::internal {
    ///////////////////////////////////////////////////////////////////////////
    // Default Visitor                                                       //
    //                                                                       //
    // Acts as a selector for visiting all primitive suported types          //
    ///////////////////////////////////////////////////////////////////////////
    template <typename Value>
    struct DefaultVisitor: public model::Visitor<Value> {};

    // Default Visitor for types which can be coerced using boost::numeric_cast
    template <typename Numeric>
    struct NumericVisitor: public model::Visitor<Numeric>
    {
        std::string expecting() const override final
        {
            return "numeric type";
        }

        #define DEF_NUM_VISIT_METHOD(mname, numtype)                                    \
            Numeric visit_##mname(numtype value) override final                         \
            {                                                                           \
                return internal::safe_numeric_cast<Numeric>(value);                     \
            }                                                                           \

        DEF_NUM_VISIT_METHOD(int64, int64_t)
        DEF_NUM_VISIT_METHOD(int32, int32_t)
        DEF_NUM_VISIT_METHOD(int16, int16_t)
        DEF_NUM_VISIT_METHOD(int8, int8_t)
        DEF_NUM_VISIT_METHOD(uint64, uint64_t)
        DEF_NUM_VISIT_METHOD(uint32, uint32_t)
        DEF_NUM_VISIT_METHOD(uint16, uint16_t)
        DEF_NUM_VISIT_METHOD(uint8, uint8_t)
        DEF_NUM_VISIT_METHOD(float64, double)
        DEF_NUM_VISIT_METHOD(boolean, bool)
    };

    #define SPECIALIZE_DEFAULT_VISITOR_FOR_NUMERIC(numty)                         \
        template<> struct DefaultVisitor<numty>: public NumericVisitor<numty> {}; \

    SPECIALIZE_DEFAULT_VISITOR_FOR_NUMERIC(int64_t)
    SPECIALIZE_DEFAULT_VISITOR_FOR_NUMERIC(int32_t)
    SPECIALIZE_DEFAULT_VISITOR_FOR_NUMERIC(int16_t)
    SPECIALIZE_DEFAULT_VISITOR_FOR_NUMERIC(int8_t)
    SPECIALIZE_DEFAULT_VISITOR_FOR_NUMERIC(uint64_t)
    SPECIALIZE_DEFAULT_VISITOR_FOR_NUMERIC(uint32_t)
    SPECIALIZE_DEFAULT_VISITOR_FOR_NUMERIC(uint16_t)
    SPECIALIZE_DEFAULT_VISITOR_FOR_NUMERIC(uint8_t)
    SPECIALIZE_DEFAULT_VISITOR_FOR_NUMERIC(double)
    SPECIALIZE_DEFAULT_VISITOR_FOR_NUMERIC(bool)

    template<>
    struct DefaultVisitor<std::string>: public model::Visitor<std::string>
    {
        std::string expecting() const override final
        {
            return "string";
        }

        std::string visit_bytes(const char* buf, size_t length) override final
        {
            return std::string(buf, length);
        }
    };

    template <typename Container>
    struct DefaultContainerVisitor: public model::Visitor<Container> {
        std::string expecting() const override final
        {
            return "array";
        }

        Container visit_array(optional<size_t> size, model::Deserializer& deserializer) override final
        {
            typedef typename Container::value_type value_type;

            Container cont;
            if (size)
            {
                internal::container_reserve(cont);
            }

            while (deserializer.continue_collection())
            {
                const auto element = model::Deserialize<value_type>::dflt(deserializer);
                cont.push_back(element);
            }

            return cont;
        }
    };

    #define SPECIALIZE_DEFAULT_VISITOR_FOR_CONTAINER(contname)                                    \
        template<typename Elem>                                                                   \
        struct DefaultVisitor<contname<Elem>>: public DefaultContainerVisitor<contname<Elem>> {}; \

    SPECIALIZE_DEFAULT_VISITOR_FOR_CONTAINER(std::list)
    SPECIALIZE_DEFAULT_VISITOR_FOR_CONTAINER(std::vector)

    ///////////////////////////////////////////////////////////////////////////
    // Blob Visitor                                                          //
    //                                                                       //
    // Acts as a selector for visiting all primitive suported types as blobs //
    ///////////////////////////////////////////////////////////////////////////

    template <typename T>
    struct BlobVisitor: public model::Visitor<T>
    {
        static_assert(std::is_pod<T>::value);

        std::string expecting() const override final
        {
            return "blob string";
        }

        T visit_bytes(const char* blob, size_t length) override final
        {
            CHECK_AND_ASSERT_THROW_MES
            (
                length == sizeof(T),
                "trying to visit blob of incorrect lenngth"
            );

            T raw_val = *reinterpret_cast<const T*>(blob);
            return CONVERT_POD(raw_val);
        }
    };

    template <typename Container>
    struct BlobContainerVisitor: public model::Visitor<Container>
    {
        typedef typename Container::value_type value_type;
        static_assert(std::is_pod<value_type>::value);

        std::string expecting() const override final
        {
            return "container blob string";
        }

        Container visit_bytes(const char* blob, size_t blob_length) override final
        {
            constexpr size_t elem_size = sizeof(value_type);

            CHECK_AND_ASSERT_THROW_MES
            (
                blob_length % elem_size == 0,
                "blob length " << blob_length << " not a multiple of element size " << elem_size
            );

            Container container;
            const value_type* const typed_blob_ptr = reinterpret_cast<const value_type*>(blob);
            const size_t num_elements = blob_length / elem_size;
            for (size_t i = 0; i < num_elements; i++)
            {
                container.push_back(CONVERT_POD(typed_blob_ptr[i]));
            }

            return container;
        }
    };

    #define SPECIALIZE_BLOB_VISITOR_FOR_DISCONTIGUOUS_CONTAINER(contname)                   \
        template<typename Elem>                                                             \
        struct BlobVisitor<contname<Elem>>: public BlobContainerVisitor<contname<Elem>> {}; \
    
    SPECIALIZE_BLOB_VISITOR_FOR_DISCONTIGUOUS_CONTAINER(std::list)

    template <typename Container>
    struct BlobContiguousContainerVisitor: public model::Visitor<Container>
    {
        typedef typename Container::value_type value_type;
        static_assert(std::is_pod<value_type>::value);

        std::string expecting() const override final
        {
            return "container blob string";
        }

        Container visit_bytes(const char* blob, size_t blob_length) override final
        {
            constexpr size_t elem_size = sizeof(value_type);

            CHECK_AND_ASSERT_THROW_MES
            (
                blob_length % elem_size == 0,
                "blob length " << blob_length << " not a multiple of element size " << elem_size
            );

            if (internal::le_conversion<value_type>::needed())
            {
                return BlobContainerVisitor<Container>().visit_bytes(blob, blob_length);
            }
            else
            {
                const size_t num_elements = blob_length / elem_size;
                Container container(num_elements); // default fill constructor
                memcpy(&container[0], blob, blob_length);
                return container;
            }   
        }
    };

    #define SPECIALIZE_BLOB_VISITOR_FOR_CONTIGUOUS_CONTAINER(contname)                            \
        template<typename Em>                                                                     \
        struct BlobVisitor<contname<Em>>: public BlobContiguousContainerVisitor<contname<Em>> {}; \
    
    SPECIALIZE_BLOB_VISITOR_FOR_CONTIGUOUS_CONTAINER(std::vector)
} // namespace portable_storage::model

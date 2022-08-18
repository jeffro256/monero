#pragma once

#include "deserializer.h"
#include "visitor.h"
#include "../internal/container.h"
#include "../internal/endianness.h"
#include "../internal/external/logging.h"
#include "../internal/external/numeric_cast.h"

namespace serde::internal
{
    // Default Visitor for types which can be coerced using boost::numeric_cast
    template <typename Numeric>
    struct NumericVisitor: public model::GetSetVisitor<Numeric>
    {
        std::string expecting() const override final
        {
            return "numeric type";
        }

        #define DEF_NUM_VISIT_METHOD(mname, numtype)                            \
            void visit_##mname(numtype value) override final                    \
            {                                                                   \
                this->set_visited(internal::safe_numeric_cast<Numeric>(value)); \
            }                                                                   \

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

    struct StringVisitor: public model::GetSetVisitor<std::string>
    {
        std::string expecting() const override final
        {
            return "string";
        }

        void visit_bytes(const const_byte_span& bytes) override final
        {
            this->set_visited(internal::byte_span_to_string(bytes));
        }
    };

    struct CollectionBoundVisitor: public model::BasicVisitor
    {
        using Deserializer = model::Deserializer;
        using SizeHint = optional<size_t>;

        enum struct BoundStatus
        {
            Unvisted,
            ArrayBegin,
            ArrayEnd,
            ObjectBegin,
            ObjectEnd
        };

        CollectionBoundVisitor(): bound_status(BoundStatus::Unvisted), size_hint() {}

        std::string expecting() const override final
        {
            return "the beginning or end of an array or object";
        }

        void visit_array(SizeHint hint) override final
        {
            CHECK_AND_ASSERT_THROW_MES(bound_status == BoundStatus::Unvisted, "already visited");
            bound_status = BoundStatus::ArrayBegin;
            size_hint = hint;
        }

        void visit_end_array() override final
        {
            CHECK_AND_ASSERT_THROW_MES(bound_status == BoundStatus::Unvisted, "already visited");
            bound_status = BoundStatus::ArrayEnd;
        }

        void visit_object(SizeHint hint) override final
        {
            CHECK_AND_ASSERT_THROW_MES(bound_status == BoundStatus::Unvisted, "already visited");
            bound_status = BoundStatus::ObjectBegin;
            size_hint = hint;
        }

        void visit_end_object() override final
        {
            CHECK_AND_ASSERT_THROW_MES(bound_status == BoundStatus::Unvisted, "already visited");
            bound_status = BoundStatus::ObjectEnd;
        }

        static SizeHint expect_array(SizeHint size_hint, Deserializer& deserializer)
        {
            CollectionBoundVisitor visitor;
            deserializer.deserialize_object(size_hint, visitor);
            CHECK_AND_ASSERT_THROW_MES
            (
                visitor.bound_status == BoundStatus::ArrayBegin,
                "Got some other bound besides ArrayBegin"
            );
            return visitor.size_hint;
        }

        static SizeHint expect_object(SizeHint size_hint, Deserializer& deserializer)
        {
            CollectionBoundVisitor visitor;
            deserializer.deserialize_object(size_hint, visitor);
            CHECK_AND_ASSERT_THROW_MES
            (
                visitor.bound_status == BoundStatus::ObjectBegin,
                "Got some other bound besides ObjectBegin"
            );
            return visitor.size_hint;
        }

        BoundStatus bound_status;
        SizeHint size_hint;
    };

    ///////////////////////////////////////////////////////////////////////////
    // Blob Visitor                                                          //
    //                                                                       //
    // Acts as a selector for visiting all primitive suported types as blobs //
    ///////////////////////////////////////////////////////////////////////////

    #define ENABLE_IF_IS_POD(T) typename = typename std::enable_if<std::is_pod<T>::value>::type

    template <typename PodValue, ENABLE_IF_IS_POD(PodValue)>
    struct BlobVisitor: public model::GetSetVisitor<PodValue>
    {
        std::string expecting() const override final
        {
            return "blob string";
        }

        void visit_bytes(const const_byte_span& blob) override final
        {
            CHECK_AND_ASSERT_THROW_MES
            (
                blob.size() == sizeof(PodValue),
                "trying to visit blob of incorrect lenngth"
            );

            PodValue val = *reinterpret_cast<const PodValue*>(blob.begin());
            val = CONVERT_POD(val);
            this->set_visited(std::move(val));
        }
    };

    struct BlobStringVisitor: public model::GetSetVisitor<std::string>
    {
        std::string expecting() const override final
        {
            return "blob string";
        }

        void visit_bytes(const const_byte_span& blob) override final
        {
            this->set_visited(internal::byte_span_to_string(blob));
        }
    };

    template <typename Container, ENABLE_IF_IS_POD(typename Container::value_type)>
    struct BlobContainerVisitor: public model::GetSetVisitor<Container>
    {
        typedef typename Container::value_type value_type;

        std::string expecting() const override final
        {
            return "container blob string";
        }

        void visit_bytes(const const_byte_span& blob) override final
        {
            constexpr size_t elem_size = sizeof(value_type);

            CHECK_AND_ASSERT_THROW_MES
            (
                blob.size() % elem_size == 0,
                "blob length " << blob.size() << " not a multiple of element size " << elem_size
            );

            Container container;
            const value_type* const value_ptr = reinterpret_cast<const value_type*>(blob.begin());
            const size_t num_elements = blob.size() / elem_size;
            for (size_t i = 0; i < num_elements; i++)
            {
                container.push_back(CONVERT_POD(value_ptr[i]));
            }

            this->set_visited(std::move(container));
        }
    };

    template <typename Container, ENABLE_IF_IS_POD(typename Container::value_type)>
    struct BlobContiguousContainerVisitor: public model::GetSetVisitor<Container>
    {
        typedef typename Container::value_type value_type;

        std::string expecting() const override final
        {
            return "container blob string";
        }

        void visit_bytes(const const_byte_span& blob) override final
        {
            constexpr size_t elem_size = sizeof(value_type);

            CHECK_AND_ASSERT_THROW_MES
            (
                blob.size() % elem_size == 0,
                "blob length " << blob.size() << " not a multiple of element size " << elem_size
            );

            if (internal::le_conversion<value_type>::needed())
            {
                // If endianess conversion is needed, passthru visitation to BlobContainerVisitor
                BlobContainerVisitor<Container> default_container_visitor;
                default_container_visitor.visit_bytes(blob);
                this->set_visited(default_container_visitor.get_visited());
            }
            else // Container stores raw blob data in memory exactly as it will be deserialized
            {
                const size_t num_elements = blob.size() / elem_size;
                Container container(num_elements); // default fill constructor
                memcpy(&container[0], blob, blob.size());
                this->set_visited(container);
            }   
        } // visit_bytes
    };
} // namespace serde::model

#pragma once

// Do not include directly!

namespace portable_storage::model {
    ///////////////////////////////////////////////////////////////////////////
    // Default Visitor implementations/specializations                       //
    ///////////////////////////////////////////////////////////////////////////

    // Default Visitor for types which can be coerced using boost::numeric_cast
    template <typename NumericValue>
    struct DefaultNumericVisitor: public Visitor<NumericValue> {
        // Defines an number visiting method using boost::numeric_cast, with better error msgs
        #define DEF_NUM_VISIT_METHOD(mname, numtype)                                    \
            NumericValue mname(numtype value) override final {                          \
                try {                                                                   \
                    return boost::numeric_cast<NumericValue>(value);                    \
                } catch(...) {                                                          \
                    ASSERT_MES_AND_THROW(                                               \
                        #numtype " value " << value << " can not be losslessly visited" \
                    );                                                                  \
                }                                                                       \
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

        // yeah
        NumericValue boolean(bool value) override final {
            return value ? 1 : 0;
        }
    };

    struct DefaultStringVisitor: public Visitor<std::string> {
        std::string bytes(const char* buf, size_t length) override final {
            return std::string(buf, length);
        }
    };

    // @TODO
    //template <class ontainer>


    ///////////////////////////////////////////////////////////////////////////
    // Blob Visitor implementations/specializations                          //
    ///////////////////////////////////////////////////////////////////////////

    template <typename T>
    struct BlobVisitor: public Visitor<T> {
        static_assert(std::is_pod<T>::value);

        T bytes(const char* buf, size_t length) override final {
            CHECK_AND_ASSERT_THROW_MES(
                length == sizeof(T),
                "trying to visit blob of incorrect lenngth"
            );

            return *reinterpret_cast<const T*>(buf);
        }
    };

} // namespace portable_storage::model
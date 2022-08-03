#pragma once

#include "external_libs.h"
#include "../model/visitor.h"

namespace portable_storage::internal {
    ///////////////////////////////////////////////////////////////////////////
    // Base Visitor class                                                    //
    ///////////////////////////////////////////////////////////////////////////
    template <typename T>
    class OwnedVisitor: public Visitor {
    public:
        T get() const {
            CHECK_AND_ASSERT_THROW_MES(
                !m_assigned,
                "OwnedVisitor must be set before being get"
            );

            return m_val;
        }

    protected:
        OwnedVisitor(): m_val(), assigned(false) {}

        void set(T val) {
            CHECK_AND_ASSERT_THROW_MES(
                !m_assigned,
                "OwnedVisitor disallows assigning to internal value twice"
            );

            m_val = val;
            m_assigned = true;
        }

    private:
        T m_val;
        bool m_assigned;
    };

    template <class MT>
    class MoveVisitor: public Visitor {
    public:
        MT collect() {
            CHECK_AND_ASSERT_THROW_MES(
                !m_assigned,
                "MoveVisitor must be assigned before being collected"
            );

            return std::move(m_val);
        }
    
    protected:
        MoveVisitor(): m_val(), assigned(false) {}

        void assign(MT val) {
            CHECK_AND_ASSERT_THROW_MES(
                !m_assigned,
                "MoveVisitor disallows assigning to internal value twice"
            );

            m_val = std::move(val);
            m_assigned = true;
        }

    private:

        T m_val;
        bool m_assigned;
    };

    ///////////////////////////////////////////////////////////////////////////
    // Default Visitor implementations/specializations                       //
    ///////////////////////////////////////////////////////////////////////////

    // Default Visitor for types which can be coerced using boost::numeric_cast
    template <typename numeric>
    struct DefaultNumericVisitor: public OwnedVisitor<numeric> {
        // Defines an number visiting method using boost::numeric_cast, with better error msgs
        #define DEF_NUM_VISIT_METHOD(mname, numtype)                                    \
            void visit_##mname(numtype value) override final {                          \
                numeric val;                                                            \
                try {                                                                   \
                    val = safe_numeric_cast<numeric>(value);                          \
                } catch(...) {                                                          \
                    ASSERT_MES_AND_THROW(                                               \
                        #numtype " value " << value << " can not be losslessly visited" \
                    );                                                                  \
                }                                                                       \
                this->set(val);                                                         \
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

    struct DefaultStringVisitor: public MoveVisitor<std::string> {
        void visit_bytes(const char* buf, size_t length) override final {
            this->assign(std::string(buf, length));
        }
    };

    template <typename Container>
    struct DefaultContainerVisitor: public MoveVisitor<Container> {
        void visit_array(optional<size_t>, Deserializer& deserializer) override final {
            Container cont;
            // @TODO: size hint ?
            while (!deserializer.has_array_elements()) {

            }
        }
    };

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
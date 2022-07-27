/* For type X to be Serializable, there must exist some function in the namespace epee_format::ser of this type:
 *
 * ```
 * template <class Serializer>
 * size_t serialize(const X& x, Serializer& serializer) {
 *     ...
 * }
 * ```
 * 
 * This function should call methods of Serializer with data from X to build a format-independent model of X,
 * analagous to Rust's serde's Serialize trait.
 */

// @TODO might not be needed

#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

#include <list>
#include <vector>

namespace portable_storage::model {
    ///////////////////////////////////////////////////////////////////////////
    // Serializing primitives                                                //
    ///////////////////////////////////////////////////////////////////////////

    #define DEF_SERIALIZE_PRIMITIVE(tyname, mname)                          \
        template <class Serializer>                                         \
        void serialize(const tyname& value, Serializer& serializer) { \
            serializer.serialize_##mname(value);                            \
        }                                                                   \

    DEF_SERIALIZE_PRIMITIVE(    int64_t,  int64)
    DEF_SERIALIZE_PRIMITIVE(    int32_t,  int32)
    DEF_SERIALIZE_PRIMITIVE(    int16_t,  int16)
    DEF_SERIALIZE_PRIMITIVE(     int8_t,   int8)
    DEF_SERIALIZE_PRIMITIVE(   uint64_t, uint64)
    DEF_SERIALIZE_PRIMITIVE(   uint32_t, uint32)
    DEF_SERIALIZE_PRIMITIVE(   uint16_t, uint16)
    DEF_SERIALIZE_PRIMITIVE(    uint8_t,  uint8)
    DEF_SERIALIZE_PRIMITIVE(       bool,   bool)
    DEF_SERIALIZE_PRIMITIVE(std::string, string)

    ///////////////////////////////////////////////////////////////////////////
    // Serializing containers                                                //
    ///////////////////////////////////////////////////////////////////////////

    /*

    #define DEF_SERIALIZE_PRIMITIVE_CONTAINER(contname, valtype, sermeth)       \
        template<class Serializer>                                              \
        void serialize(const contname<valtype>& cont, Serializer& serializer) { \

            serializer.sermeth(cont.begin(), cont.size());                      \
        }                                                                       \
    
    #define DEF_SERIALIZE_OBJECT_CONTAINER(contname)                      \
        template <typename T, class Serializer>                           \
        void serialize(const contname<T>& cont, Serializer& serializer) { \
            auto seq = serializer.serialize_object_array(cont.size());    \
            seq.start();                                                  \
            for (const T& value : cont) {                                 \
                value.serialize(serializer);                              \
            }                                                             \
            seq.end();                                                    \
        }                                                                 \

    #define DEF_SERIALIZE_CONTAINER_ALL_TYPES(contname)                            \
        DEF_SERIALIZE_PRIMITIVE_CONTAINER(contname,     int64_t,  serialize_int64) \
        DEF_SERIALIZE_PRIMITIVE_CONTAINER(contname,     int32_t,  serialize_int32) \
        DEF_SERIALIZE_PRIMITIVE_CONTAINER(contname,     int16_t,  serialize_int16) \
        DEF_SERIALIZE_PRIMITIVE_CONTAINER(contname,      int8_t,   serialize_int8) \
        DEF_SERIALIZE_PRIMITIVE_CONTAINER(contname,    uint64_t, serialize_uint64) \
        DEF_SERIALIZE_PRIMITIVE_CONTAINER(contname,    uint32_t, serialize_uint32) \
        DEF_SERIALIZE_PRIMITIVE_CONTAINER(contname,    uint16_t, serialize_uint16) \
        DEF_SERIALIZE_PRIMITIVE_CONTAINER(contname,     uint8_t,  serialize_uint8) \
        DEF_SERIALIZE_PRIMITIVE_CONTAINER(contname,        bool,  serialize_uint8) \
        DEF_SERIALIZE_PRIMITIVE_CONTAINER(contname, std::string,  serialize_sring) \
        DEF_SERIALIZE_PRIMITIVE_CONTAINER(contname,     uint8_t,  serialize_uint8) \
        DEF_SERIALIZE_OBJECT_CONTAINER(contname)                                   \
    
    DEF_SERIALIZE_CONTAINER_ALL_TYPES(std::vector)
    DEF_SERIALIZE_CONTAINER_ALL_TYPES(std::list)

    */

    ///////////////////////////////////////////////////////////////////////////
    // Serializing user-defined types                                        //
    ///////////////////////////////////////////////////////////////////////////

    // User-defined type needs method:
    // 
    // template<class Serializer>
    // void epee_serialize(Serializer& serializer);
    //
    // Will usually be defined through macros KV_SERIALIZE*, but in the case
    // of more complicated serializations, may have to be handwritten

    template<class Serializable, class Serializer>
    void serialize(const Serializable& value, Serializer& serializer) {
        value.epee_serialize(serializer);
    }
}
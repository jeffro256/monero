#pragma once

#include "int-util.h"
#include <iostream> // @TODO REMOVE

namespace portable_storage::internal {
    template <typename T>
    struct le_conversion {
        static constexpr bool needed_for_type() { return false; }
        static constexpr bool needed() {
            #if BYTE_ORDER == BIG_ENDIAN
                constexpr bool is_big_endian = true;
            #else
                constexpr bool is_big_endian = false;
            #endif

            constexpr bool is_pod = std::is_pod<T>::value;
            constexpr bool is_needed_for_type = le_conversion<T>::needed_for_type();

            return is_big_endian && is_pod && is_needed_for_type;
        }

        inline static constexpr T convert(T value) {
            return value;
        }
    };

    #ifndef SWAP8LE
    #define SWAP8LE(x) x
    #endif

    #define SPECIALIZE_INT_CONVERSION(b)                                                          \
        template<> constexpr                                                                      \
        bool le_conversion<int##b##_t>::needed_for_type() { return true; }                        \
        template<> constexpr                                                                      \
        int##b##_t le_conversion<int##b##_t>::convert(int##b##_t v) { return SWAP##b##LE(v); }    \
        template<> constexpr                                                                      \
        bool le_conversion<uint##b##_t>::needed_for_type() { return true; }                       \
        template<> constexpr                                                                      \
        uint##b##_t le_conversion<uint##b##_t>::convert(uint##b##_t v) { return SWAP##b##LE(v); } \

    SPECIALIZE_INT_CONVERSION(64)
    SPECIALIZE_INT_CONVERSION(32)
    SPECIALIZE_INT_CONVERSION(16)
    SPECIALIZE_INT_CONVERSION(8)
} // namespace portable_storage::internal

// @TODO passthough if LE system
#ifndef CONVERT_POD
    #define CONVERT_POD(x)                                                    \
        (portable_storage::internal::le_conversion<decltype(x)>::needed()     \
        ? portable_storage::internal::le_conversion<decltype(x)>::convert(x)  \
        : x)
#endif
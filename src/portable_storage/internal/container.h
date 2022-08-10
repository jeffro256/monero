#pragma once

#include <cstddef>
#include <vector>

namespace portable_storage::internal {
    template <class Container> inline
    void container_reserve(Container& container, size_t new_capacity) {
        // by default, do nothing
    }

    template<typename T> inline
    void container_reserve(std::vector<T>& vec, size_t new_capacity) {
        vec.reserve(new_size);
    }
}
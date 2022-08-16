#pragma once

#include <cstddef>
#include <tuple>
#include <vector>

namespace portable_storage::internal {
    template <class Container> inline
    void container_reserve(Container& container, size_t new_capacity) {
        // by default, do nothing
    }

    template<typename T> inline
    void container_reserve(std::vector<T>& vec, size_t new_capacity) {
        vec.reserve(new_capacity);
    }

    template <class Functor, size_t Index = 0>
    struct t_tuple_for_each
    {
        // If Index < length of tuple, instantiate Functor and call with Index-th element as arg.
        // If the functor returns true, continue onto next element
        template <typename... T> typename std::enable_if<Index < sizeof...(T)>::type
        operator()(std::tuple<T...>& tup, Functor& f)
        {
            const bool should_continue = f(std::get<Index>(tup));
            if (should_continue) t_tuple_for_each<Functor, Index + 1>()(tup, f);
        }

        // Same as above but for constant tuples
        template <typename... T> typename std::enable_if<Index < sizeof...(T)>::type
        operator()(const std::tuple<T...>& tup, Functor& f)
        {
            const bool should_continue = f(std::get<Index>(tup));
            if (should_continue) t_tuple_for_each<Functor, Index + 1>()(tup, f);
        }

        // If Index >= length of tuple, then do nothing
        template <typename... T> typename std::enable_if<Index >= sizeof...(T)>::type
        operator()(std::tuple<T...>& tup, Functor& f) { }

        // Same as above but for constant tuples
        template <typename... T> typename std::enable_if<Index >= sizeof...(T)>::type
        operator()(const std::tuple<T...>& tup, Functor& f) { }
    };

    template <class Tuple, class Functor>
    void tuple_for_each(Tuple& tup, Functor& f)
    {
        t_tuple_for_each<Functor, 0>()(tup, f);
    }

    // @TODO: remove if unused
    /*
    template <class Tuple, class Functor>
    void tuple_for_each(Tuple& tup)
    {
        Functor f;
        t_tuple_for_each<Functor, 0>()(tup, f);
    }*/

}

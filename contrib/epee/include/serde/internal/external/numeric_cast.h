#pragma once

#include <boost/numeric/conversion/cast.hpp>
#include <sstream>
#include <stdexcept>

namespace portable_storage::internal
{
    // wrapper exception
    class safe_numeric_cast_exception: public std::runtime_error
    {
    public:

        safe_numeric_cast_exception(const std::string& what)
            : std::runtime_error(what)
        {}
    };
    
    // wrapper for boost::mpl::numeric_cast
    template <typename Target, typename Source> inline
    Target safe_numeric_cast(Source arg)
    {
        try
        {
            return boost::numeric_cast<Target>(arg);
        }
        catch (const std::exception& e)
        {
            std::stringstream err_stream;
            err_stream << "Could not losslessly convert " << arg;
            throw safe_numeric_cast_exception(err_stream.str());
        }
    } // safe_numeric_cast
}
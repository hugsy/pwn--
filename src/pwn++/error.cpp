#include "error.hpp"

#include "log.hpp"

// clang-format off
#if defined(PWN_BUILD_FOR_WINDOWS)
#include <phnt_windows.h>
#include <phnt.h>
#elif defined(PWN_BUILD_FOR_LINUX)
#include <errno.h>
#else
#error "noooope"
#endif // PWN_BUILD_FOR_WINDOWS
// clang-format on


Err::Err(ErrorCode ec) :
#if defined(PWN_BUILD_FOR_WINDOWS)
    ErrorType(ec, ::GetLastError())
#elif defined(PWN_BUILD_FOR_LINUX)
    ErrorType(ec, errno)
#else
#error "noooope"
#endif
{
    std::ostringstream os;
    os << *this << std::endl;
    err(os);
}

bool
ErrorType::operator==(const ErrorType& rhs) const
{
    return this->code == rhs.code && this->number == rhs.number;
}

bool
ErrorType::operator==(ErrorCode code) const
{
    return this->code == code;
}

bool
Err::operator==(const Err& rhs) const
{
    return this->code == rhs.code;
}

bool
Err::operator==(ErrorCode code) const
{
    return this->code == code;
}

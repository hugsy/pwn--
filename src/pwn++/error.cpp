#include "error.hpp"

// clang-format off
#ifdef _WIN32
// #include <windows.h>
#include <phnt_windows.h>
#include <phnt.h>
#else
#include <errno.h>
#endif // _WIN32
// clang-format on


Err::Err(ErrorCode ErrCode) :
#ifdef _WIN32
    ErrorType(ErrCode, ::GetLastError())
#else
    ErrorType(ErrCode, errno)
#endif
{
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

#include "error.hpp"

#ifdef _WIN32
#include <windows.h>
#else
#include <errno.h>
#endif // _WIN32


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

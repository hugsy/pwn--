#include "error.hpp"

#include "log.hpp"

// clang-format off
#ifdef _WIN32
// #include <windows.h>
#include <phnt_windows.h>
#include <phnt.h>
#else
#include <errno.h>
#endif // _WIN32
// clang-format on


Err::Err(ErrorCode ec) :
#ifdef _WIN32
    ErrorType(ec, ::GetLastError())
#else
    ErrorType(ec, errno)
#endif
{
    err(L"ERROR_{}_{}", (uint32_t)this->code, this->number);
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

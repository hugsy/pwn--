#include "Error.hpp"

#include "Log.hpp"

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

using namespace pwn;

std::wstring_view PWNAPI
FormatErrorCode(ErrorCode const& code)
{
    switch ( code )
    // clang-format off
    {
    case ErrorCode::UnknownError:                      return L"UnknownError";
    case ErrorCode::GenericError:                      return L"GenericError";
    case ErrorCode::RuntimeError:                      return L"RuntimeError";
    case ErrorCode::InvalidProcess:                    return L"InvalidProcess";
    case ErrorCode::InvalidThread:                     return L"InvalidThread";
    case ErrorCode::InvalidObject:                     return L"InvalidObject";
    case ErrorCode::InvalidInput:                      return L"InvalidInput";
    case ErrorCode::InvalidParameter:                  return L"InvalidParameter";
    case ErrorCode::InvalidState:                      return L"InvalidState";
    case ErrorCode::PermissionDenied:                  return L"PermissionDenied";
    case ErrorCode::InsufficientPrivilegeError:        return L"InsufficientPrivilegeError";
    case ErrorCode::UnexpectedType:                    return L"UnexpectedType";
    case ErrorCode::ArithmeticError:                   return L"ArithmeticError";
    case ErrorCode::OverflowError:                     return L"OverflowError";
    case ErrorCode::UnderflowError:                    return L"UnderflowError";
    case ErrorCode::IllegalValue:                      return L"IllegalValue";
    case ErrorCode::NotImplementedError:               return L"NotImplementedError";
    case ErrorCode::PendingIoError:                    return L"PendingIoError";
    case ErrorCode::ConnectionError:                   return L"ConnectionError";
    case ErrorCode::TerminationError:                  return L"TerminationError";
    case ErrorCode::AllocationError:                   return L"AllocationError";
    case ErrorCode::ParsingError:                      return L"ParsingError";
    case ErrorCode::BufferTooBig:                      return L"BufferTooBig";
    case ErrorCode::BufferTooSmall:                    return L"BufferTooSmall";
    case ErrorCode::NotInitialized:                    return L"NotInitialized";
    case ErrorCode::InitializationFailed:              return L"InitializationFailed";
    case ErrorCode::ServiceError:                      return L"ServiceError";
    case ErrorCode::FilesystemError:                   return L"FilesystemError";
    case ErrorCode::AlpcError:                         return L"AlpcError";
    case ErrorCode::ExternalError:                     return L"ExternalError";
    case ErrorCode::ExternalApiCallFailed:             return L"ExternalApiCallFailed";
    case ErrorCode::NoMoreData:                        return L"NoMoreData";
    case ErrorCode::PartialResult:                     return L"PartialResult";
    case ErrorCode::BadVersion:                        return L"BadVersion";
    case ErrorCode::BadSignature:                      return L"BadSignature";
    case ErrorCode::NotFound:                          return L"NotFound";
    case ErrorCode::NotConnected:                      return L"NotConnected";
    case ErrorCode::AlreadyExists:                     return L"AlreadyExists";
    case ErrorCode::SizeMismatch:                      return L"SizeMismatch";
    case ErrorCode::MalformedFile:                     return L"MalformedFile";
    }
    // clang-format on
    return L"";
}


/*
Err::Err(ErrorCode ec, uint32_t en) :
#if defined(PWN_BUILD_FOR_WINDOWS)
    ErrorType(ec, en ? en : ::GetLastError())
#elif defined(PWN_BUILD_FOR_LINUX)
    ErrorType(ec, en || errno)
#else
#error "noooope"
#endif
{
#if defined(PWN_BUILD_FOR_WINDOWS)
    std::wostringstream os;
    os << *this << L" : " << this->Code();
    if ( this->number )
    {
        os << L" - " << Log::FormatLastError(this->number);
    }
    os << std::endl;

#elif defined(PWN_BUILD_FOR_LINUX)
    std::ostringstream os;
    os << *this << std::endl;
#endif // PWN_BUILD_FOR_WINDOWS
    err(os);
}


Err::Err(Err const& e) : Err(e.code, e.number)
{
}


Err::Err(ErrorType const& e) : Err(e.code, e.number)
{
}

std::wstring
ErrorType::Code()
{
    return FormatErrorCode(this->code);
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
*/

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
FormatErrorCode(Error const code)
{
    switch ( code )
    // clang-format off
    {
    case Error::UnknownError:                      return L"UnknownError"sv;
    case Error::GenericError:                      return L"GenericError"sv;
    case Error::RuntimeError:                      return L"RuntimeError"sv;
    case Error::InvalidProcess:                    return L"InvalidProcess"sv;
    case Error::InvalidThread:                     return L"InvalidThread"sv;
    case Error::InvalidObject:                     return L"InvalidObject"sv;
    case Error::InvalidInput:                      return L"InvalidInput"sv;
    case Error::InvalidParameter:                  return L"InvalidParameter"sv;
    case Error::InvalidState:                      return L"InvalidState"sv;
    case Error::PermissionDenied:                  return L"PermissionDenied"sv;
    case Error::InsufficientPrivilegeError:        return L"InsufficientPrivilegeError"sv;
    case Error::UnexpectedType:                    return L"UnexpectedType"sv;
    case Error::ArithmeticError:                   return L"ArithmeticError"sv;
    case Error::OverflowError:                     return L"OverflowError"sv;
    case Error::UnderflowError:                    return L"UnderflowError"sv;
    case Error::IllegalValue:                      return L"IllegalValue"sv;
    case Error::NotImplementedError:               return L"NotImplementedError"sv;
    case Error::PendingIoError:                    return L"PendingIoError"sv;
    case Error::ConnectionError:                   return L"ConnectionError"sv;
    case Error::TerminationError:                  return L"TerminationError"sv;
    case Error::AllocationError:                   return L"AllocationError"sv;
    case Error::ParsingError:                      return L"ParsingError"sv;
    case Error::BufferTooBig:                      return L"BufferTooBig"sv;
    case Error::BufferTooSmall:                    return L"BufferTooSmall"sv;
    case Error::NotInitialized:                    return L"NotInitialized"sv;
    case Error::InitializationFailed:              return L"InitializationFailed"sv;
    case Error::ServiceError:                      return L"ServiceError"sv;
    case Error::FilesystemError:                   return L"FilesystemError"sv;
    case Error::AlpcError:                         return L"AlpcError"sv;
    case Error::ExternalError:                     return L"ExternalError"sv;
    case Error::ExternalApiCallFailed:             return L"ExternalApiCallFailed"sv;
    case Error::NoMoreData:                        return L"NoMoreData"sv;
    case Error::PartialResult:                     return L"PartialResult"sv;
    case Error::BadVersion:                        return L"BadVersion"sv;
    case Error::BadSignature:                      return L"BadSignature"sv;
    case Error::NotFound:                          return L"NotFound"sv;
    case Error::NotConnected:                      return L"NotConnected"sv;
    case Error::AlreadyExists:                     return L"AlreadyExists"sv;
    case Error::SizeMismatch:                      return L"SizeMismatch"sv;
    case Error::MalformedFile:                     return L"MalformedFile"sv;
    }
    // clang-format on

    throw std::runtime_error("unknown error type");
}

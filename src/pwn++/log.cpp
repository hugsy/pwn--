#include "log.hpp"

#include <cassert>
#include <cstdio>
#include <iostream>

#include "pwn.hpp"

extern struct GlobalContext Context;

namespace pwn::log
{

const char*
GetPriorityString(const LogLevel level)
{
    switch ( level )
    {
    case LogLevel::Debug:
        return PWN_COLOR_BOLD PWN_LOG_STRINGS_DEBUG PWN_COLOR_RESET;

    case LogLevel::Success:
        return PWN_COLOR_BOLD PWN_COLOR_FG_GREEN PWN_LOG_STRINGS_SUCCESS PWN_COLOR_RESET;

    case LogLevel::Info:
        return PWN_COLOR_BOLD PWN_COLOR_FG_CYAN PWN_LOG_STRINGS_INFO PWN_COLOR_RESET;

    case LogLevel::Warning:
        return PWN_COLOR_BOLD PWN_COLOR_FG_YELLOW PWN_LOG_STRINGS_WARN PWN_COLOR_RESET;

    case LogLevel::Error:
        return PWN_COLOR_BOLD PWN_COLOR_FG_RED PWN_LOG_STRINGS_ERROR PWN_COLOR_RESET;

    case LogLevel::Critical:
        return PWN_COLOR_BOLD PWN_COLOR_FG_MAGENTA PWN_LOG_STRINGS_CRITICAL PWN_COLOR_RESET;

    default:
        return "";
    }
}


void
Log(const LogLevel level, std::source_location const& location, std::ostringstream& msg)
{
    if ( Context.LogLevel > level )
    {
        return;
    }

    std::ostringstream prefix;
    prefix << GetPriorityString(level);

    if ( level == LogLevel::Debug )
    {
        prefix << "{";
        prefix << location.file_name() << ":" << location.line() << ":";
        prefix << location.function_name() << "()";
        prefix << "} ";
    }

    std::cerr << prefix.str() << msg.str() << std::flush;
}


#ifdef PWN_BUILD_FOR_WINDOWS
const wchar_t*
GetPriorityWideString(const LogLevel level)
{
    switch ( level )
    {
    case LogLevel::Debug:
        return WIDECHAR2(PWN_COLOR_BOLD) WIDECHAR2(PWN_LOG_STRINGS_DEBUG) WIDECHAR2(PWN_COLOR_RESET);

    case LogLevel::Success:
        return WIDECHAR2(PWN_COLOR_BOLD) WIDECHAR2(PWN_COLOR_FG_GREEN) WIDECHAR2(PWN_LOG_STRINGS_SUCCESS)
            WIDECHAR2(PWN_COLOR_RESET);

    case LogLevel::Info:
        return WIDECHAR2(PWN_COLOR_BOLD) WIDECHAR2(PWN_COLOR_FG_CYAN) WIDECHAR2(PWN_LOG_STRINGS_INFO)
            WIDECHAR2(PWN_COLOR_RESET);

    case LogLevel::Warning:
        return WIDECHAR2(PWN_COLOR_BOLD) WIDECHAR2(PWN_COLOR_FG_YELLOW) WIDECHAR2(PWN_LOG_STRINGS_WARN)
            WIDECHAR(PWN_COLOR_RESET);

    case LogLevel::Error:
        return WIDECHAR2(PWN_COLOR_BOLD) WIDECHAR2(PWN_COLOR_FG_RED) WIDECHAR2(PWN_LOG_STRINGS_ERROR)
            WIDECHAR2(PWN_COLOR_RESET);

    case LogLevel::Critical:
        return WIDECHAR2(PWN_COLOR_BOLD) WIDECHAR2(PWN_COLOR_FG_MAGENTA) WIDECHAR2(PWN_LOG_STRINGS_CRITICAL)
            WIDECHAR2(PWN_COLOR_RESET);

    default:
        return L"";
    }
}


void
Log(const LogLevel level, std::source_location const& location, std::wostringstream& msg)
{
    if ( Context.LogLevel > level )
    {
        return;
    }

    std::wostringstream prefix;
    prefix << GetPriorityWideString(level);

    if ( level == LogLevel::Debug )
    {
        prefix << L"{";
        prefix << location.file_name() << L":" << location.line() << L":";
        prefix << location.function_name() << L"()";
        prefix << L"} ";
    }

    std::wcerr << prefix.str() << msg.str() << std::flush;
}

std::wstring PWNAPI
FormatErrorCode(ErrorCode const& code)
{
    switch ( code )
    {
    // clang-format off
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
        // clang-format on
    }

    return L"";
}

std::wstring
FormatLastError(const u32 gle)
{
    wchar_t msg[1024] = {0};

    ::FormatMessageW(
        FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_MAX_WIDTH_MASK,
        nullptr,
        gle,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        msg,
        __countof(msg),
        nullptr);

    return std::wstring(msg);
}


void PWNAPI
perror(const std::wstring_view& prefix)
{
    const auto eNum = ::GetLastError();
    auto msg        = FormatLastError(eNum);
    err(L"{}, errcode={:#x}: {}", prefix, eNum, msg.c_str());
}


void
ntperror(_In_ const std::wstring_view& prefix, _In_ NTSTATUS Status)
{
    auto dwDosError = ::RtlNtStatusToDosError(Status);
    auto hResult    = HRESULT_FROM_WIN32(dwDosError);
    ::SetLastError(hResult);
    perror(prefix);
}


void PWNAPI
perror(const std::string_view& prefix)
{
    const u32 sysMsgSz = 1024;
    auto sysMsg        = std::string();
    sysMsg.reserve(sysMsgSz);
    const auto eNum = ::GetLastError();

    ::FormatMessageA(
        FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_MAX_WIDTH_MASK,
        nullptr,
        eNum,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        sysMsg.data(),
        sysMsgSz,
        nullptr);

    const usize max_len  = ::strlen((char*)sysMsg.c_str());
    const auto sysMsgStr = std::string_view(sysMsg.c_str(), max_len);
    err("{}, errcode={:#x}: {}", prefix, eNum, sysMsgStr);
}


void
ntperror(_In_ const std::string_view& prefix, _In_ NTSTATUS Status)
{
    auto dwDosError = ::RtlNtStatusToDosError(Status);
    auto hResult    = HRESULT_FROM_WIN32(dwDosError);
    ::SetLastError(hResult);
    log::perror(prefix);
}

#endif


} // namespace pwn::log

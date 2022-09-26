#pragma once

#include <format>
#include <optional>
#include <variant>

///
/// @file Provide an easier way to report errors without resorting to exceptions
///
/// Error types can be specified in the signature as such
/// Result<$anyType = int> MyFunction()
/// {
///   if( $bad_case ){ return Err(ErrorCode::RuntimeError); }
///   return Ok(1)
/// }

enum class ErrorCode
{
    UnknownError,
    GenericError,
    RuntimeError,
    PermissionDenied,
    InvalidProcess,
    InvalidThread,
    InvalidObject,
    InvalidInput,
    InvalidParameter,
    UnexpectedType,
    ArithmeticError,
    OverflowError,
    UnderflowError,
    BufferTooBig,
    BufferTooSmall,
    IllegalValue,
    NotImplementedError,
    PendingIoError,
    ConnectionError,
    TerminationError,
    VmNotInitialized,
    ServiceError,
    FilesystemError,
    AlpcError,
    AllocationError,
    ExternalApiCallFailed,
    ExternalError,
    PartialResult,
    BadVersion,
};

///
/// @brief Rust-like type of error handling
///
struct ErrorType
{
    ErrorCode code;
    uint32_t number;
};

template<class T>
using SuccessType = std::optional<T>;

template<class T>
using Result = std::variant<SuccessType<T>, ErrorType>;

struct Err : ErrorType
{
    Err(ErrorCode ErrCode = ErrorCode::GenericError);

    bool
    operator==(const Err& rhs) const;

    bool
    operator==(ErrorCode code) const;
};

template<class T>
struct Ok : SuccessType<T>
{
    Ok(T&& value) : SuccessType<T>(std::move(value))
    {
    }

    Ok(T& value) : SuccessType<T>(value)
    {
    }
};

template<class T>
constexpr bool
Success(Result<T> const& f)
{
    if ( const SuccessType<T>* c = std::get_if<SuccessType<T>>(&f); c != nullptr )
    {
        return true;
    }
    return false;
}

template<class T>
constexpr bool
Failed(Result<T> const& f)
{
    if ( Success(f) )
    {
        return false;
    }

    if ( const ErrorType* c = std::get_if<ErrorType>(&f); c != nullptr )
    {
        return true;
    }

    throw std::bad_variant_access();
}

template<class T>
constexpr T const&
Value(Result<T> const& f)
{
    if ( const SuccessType<T>* c = std::get_if<SuccessType<T>>(&f); c != nullptr && c->has_value() )
    {
        return c->value();
    }
    throw std::bad_variant_access();
}

template<class T>
constexpr ErrorType const&
Error(Result<T> const& f)
{
    if ( const ErrorType* c = std::get_if<ErrorType>(&f); c != nullptr )
    {
        return *c;
    }
    throw std::bad_variant_access();
}


template<>
struct std::formatter<ErrorType, wchar_t> : std::formatter<std::wstring, wchar_t>
{
    auto
    format(ErrorType const a, wformat_context& ctx)
    {
        return formatter<wstring, wchar_t>::format(std::format(L"ERROR_{}", a), ctx);
    }
};

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

enum class ErrorCode : uint32_t
{
    UnknownError = 0,
    GenericError,
    RuntimeError,

    InvalidProcess,
    InvalidThread,
    InvalidObject,
    InvalidInput,
    InvalidParameter,
    InvalidState,

    PermissionDenied,
    InsufficientPrivilegeError,

    UnexpectedType,
    ArithmeticError,
    OverflowError,
    UnderflowError,
    IllegalValue,
    NotImplementedError,
    PendingIoError,
    ConnectionError,
    TerminationError,

    AllocationError,
    BufferTooBig,
    BufferTooSmall,

    ///
    ///@brief Indicates the object initialization has not been completed properly
    ///
    NotInitialized,
    ServiceError,
    FilesystemError,
    AlpcError,
    ExternalApiCallFailed,

    ///
    ///@brief Object initialization (typically constructor) has failed
    ///
    InitializationFailed,

    ///
    ///@brief Typically used for external API call failures
    ///
    ExternalError,

    ///
    ///@brief Indicates that the operation succeeded, but no more data is available.
    ///
    NoMoreData,

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

template<class T = void>
using Result = std::variant<SuccessType<T>, ErrorType>;

struct Err : ErrorType
{
    Err(ErrorCode ErrCode = ErrorCode::GenericError);

    Err(Err const& e) : Err(e.code)
    {
    }

    bool
    operator==(const Err& rhs) const;

    bool
    operator==(ErrorCode code) const;

    friend std::wostream&
    operator<<(std::wostream& wos, Err const& e)
    {
        wos << L"Error(Code=" << (uint32_t)e.code << L", GLE=" << (uint32_t)e.number << L")";
        return wos;
    }

    friend std::ostream&
    operator<<(std::ostream& os, Err const& e)
    {
        os << "Error(Code=" << (uint32_t)e.code << ", GLE=" << (uint32_t)e.number << ")";
        return os;
    }
};

template<class T>
struct Ok : SuccessType<T>
{
    Ok(T value) : SuccessType<T>(value)
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
struct std::formatter<ErrorType, char> : std::formatter<std::string, char>
{
    auto
    format(ErrorType const a, format_context& ctx)
    {
        return formatter<string, char>::format(std::format("ERROR_{}", a), ctx);
    }
};

///
/// @file Provide an easier way to report errors without resorting to exceptions
///
/// Error types can be specified in the signature as such
/// Result<$anyType = int> MyFunction()
/// {
///   if( $bad_case ){ return Err(ErrorCode::RuntimeError); }
///   return Ok(1)
/// }
///
#pragma once

#include <cstdint>
#include <iomanip>
#include <iostream>
#include <string_view>
#include <variant>

///
///@brief Custom error codes
///
enum class ErrorCode : uint32_t
{
    /// @brief Error code `UnknownError`
    UnknownError = 0,

    /// @brief Error code `GenericError`
    GenericError,

    /// @brief Error code `RuntimeError`
    RuntimeError,

    /// @brief Error code `InvalidProcess`
    InvalidProcess,

    /// @brief Error code `InvalidThread`
    InvalidThread,

    /// @brief Error code `InvalidObject`
    InvalidObject,

    /// @brief Error code `InvalidInput`
    InvalidInput,

    /// @brief Error code `InvalidParameter`
    InvalidParameter,

    /// @brief Error code `InvalidState`
    InvalidState,

    /// @brief Error code `PermissionDenied`
    PermissionDenied,

    /// @brief Error code `InsufficientPrivilegeError`
    InsufficientPrivilegeError,

    /// @brief Error code `UnexpectedType`
    UnexpectedType,

    /// @brief Error code `ArithmeticError`
    ArithmeticError,

    /// @brief Error code `OverflowError`
    OverflowError,

    /// @brief Error code `UnderflowError`
    UnderflowError,

    /// @brief Error code `IllegalValue`
    IllegalValue,

    /// @brief Error code `NotImplementedError`
    NotImplementedError,

    /// @brief Error code `PendingIoError`
    PendingIoError,

    /// @brief Error code `ConnectionError`
    ConnectionError,

    /// @brief Error code `TerminationError`
    TerminationError,

    /// @brief Error code `AllocationError`
    AllocationError,

    /// @brief An error happened while parsing data
    ParsingError,

    /// @brief Error code `BufferTooBig`
    BufferTooBig,

    /// @brief Error code `BufferTooSmall`
    BufferTooSmall,

    ///@brief Indicates the object initialization has not been completed properly
    NotInitialized,

    ///@brief Object initialization (typically constructor) has failed
    InitializationFailed,

    /// @brief Error code `ServiceError`
    ServiceError,

    /// @brief Error code `FilesystemError`
    FilesystemError,

    /// @brief Error code `AlpcError`
    AlpcError,

    ///@brief Typically used when errors occured outside of the scope of pwn++
    ExternalError,

    ///@brief Typically used for OS (Linux, Win32) API call failures
    ExternalApiCallFailed,

    ///@brief Indicates that the operation succeeded, but no more data is available.
    NoMoreData,

    ///@brief The operation succeeded partially
    PartialResult,

    ///@brief Version mismatch between expected vs provided
    BadVersion,

    ///@brief Signature mismatch between expected vs provided
    BadSignature,

    /// @brief Expected entry (file, pipe, registry key, etc.) was not found
    NotFound,

    /// @brief An established connection was expected, but not found
    NotConnected,

    /// @brief The requested resource already exists
    AlreadyExists,

    /// @brief Unexpected size comparison
    SizeMismatch,

    /// @brief Malformed file
    MalformedFile,

    /// @brief Malformed data
    MalformedData,
};


///
///@brief Templated return value for success cases
///
///@tparam T
///
template<typename T>
constexpr auto
Ok(T&& arg)
{
    return std::forward<T>(arg);
}

///
/// @brief Templated return value for failure cases
///
struct Err
{
    ErrorCode Code {ErrorCode::UnknownError};
    uint32_t LastError {0};

    bool
    operator==(const Err& rhs) const
    {
        return rhs.Code == this->Code && rhs.LastError == this->LastError;
    }

    bool
    operator==(ErrorCode Code) const
    {
        return Code == this->Code;
    }
};


///
///@brief A Result is nothing more than a std::variant between some return value and an error object
///
///@tparam T
///
template<typename T>
using Result = std::variant<T, Err>;


///
///@brief Determines whether the result is a failure. Opposite is `Success()`
///
///@tparam T
///@param Res
///@return true
///@return false
///
template<typename T>
constexpr bool
Failed(Result<T> const& Res) noexcept
{
    return std::get_if<Err>(&Res) != nullptr;
}


///
///@brief Determines whether the result is a success. Opposite is `Failed()`
///
///@tparam T
///@param Res
///@return true
///@return false
///
template<class T>
constexpr bool
Success(Result<T> const& Result) noexcept
{
    return !Failed(Result);
}


///
///@brief Get the return value. This function will throw `std::bad_variant_access` if the parameter is not a success
/// value
///
///@tparam T
///@param SuccessResult
///@return auto
///
template<typename T>
T
Value(Result<T>&& SuccessResult)
{
    return std::move(std::get<T>(SuccessResult));
}

template<typename T>
T
Value(Result<T>& SuccessResult)
{
    T copy = std::get<T>(SuccessResult);
    return copy;
}

///
///@brief Get the error object
///
///@tparam T
///@param ErrorResult
///@return auto
///
template<typename T>
const Err&
Error(Result<T> const& ErrorResult)
{
    return std::get<Err>(ErrorResult);
}


///
///@brief
///
///@tparam T
///@param Result
///@param AlternativeValue
///@return T
///
template<typename T>
T
ValueOr(Result<T>&& Result, T AlternativeValue)
{
    return Success(Result) ? std::move(Value(Result)) : AlternativeValue;
}

template<typename T>
T
ValueOr(Result<T>& Result, T AlternativeValue)
{
    return Success(Result) ? Value(Result) : AlternativeValue;
}

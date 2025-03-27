///
/// @file Provide an easier way to report errors without resorting to exceptions
///
/// Error types can be specified in the signature as such
/// Result<$anyType = int> MyFunction()
/// {
///   if( $bad_case ){ return Err(Error::RuntimeError); }
///   return Ok(1)
/// }
///
#pragma once

#include <cstdint>
#include <expected>

///
///@brief Custom error codes
///
enum class Error : uint32_t
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

    /// @brief MalformedFile
    MalformedFile,
};

///
///@brief The expected result type
///
///@tparam T
///
template<typename T>
using Result = std::expected<T, Error>;

///
/// @brief
///
///
using Err = std::unexpected<Error>;

#define Ok

#define Success(res) (res.has_value())
#define Failed(res) (Success(res) == false)
#define Value(res) (res.value())

#pragma once


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

    /// @brief MalformedFile
    MalformedFile,
};


///
/// @brief Rust-like type of error handling
///
struct ErrorType
{
    ErrorCode code  = ErrorCode::UnknownError;
    uint32_t number = 0;

    bool
    operator==(const ErrorType& rhs) const;

    bool
    operator==(ErrorCode code) const;

    friend std::wostream&
    operator<<(std::wostream& wos, ErrorType const& e)
    {
        wos << L"ErrorType(Code=" << (uint32_t)e.code << L", GLE=" << (uint32_t)e.number << L")";
        return wos;
    }

    friend std::ostream&
    operator<<(std::ostream& os, ErrorType const& e)
    {
        os << "ErrorType(Code=" << (uint32_t)e.code << ", GLE=" << (uint32_t)e.number << ")";
        return os;
    }

    std::wstring
    Code();
};


struct Err : ErrorType
{
    Err(ErrorCode ErrCode = ErrorCode::GenericError, uint32_t ErrNumber = 0);

    Err(Err const& e);

    Err(ErrorType const& e);

    bool
    operator==(const Err& rhs) const;

    bool
    operator==(ErrorCode code) const;

    friend std::wostream&
    operator<<(std::wostream& wos, Err const& e)
    {
        wos << L"Err(Code=" << (uint32_t)e.code << L", GLE=0x" << std::hex << std::setfill(L'0') << std::setw(8)
            << (uint32_t)e.number << L")";
        return wos;
    }

    friend std::ostream&
    operator<<(std::ostream& os, Err const& e)
    {
        os << "Err(Code=" << (uint32_t)e.code << ", GLE=0x" << std::hex << std::setfill('0') << std::setw(8)
           << (uint32_t)e.number << ")";
        return os;
    }
};

template<class T>
struct Ok
{
    Ok(T const& value) : Value(value)
    {
    }

    Ok(T&& value) : Value(std::move(value))
    {
    }

    T Value;
};

template<class T = void>
using Result = std::variant<Ok<T>, ErrorType>;

template<class T>
constexpr bool
Failed(Result<T> const& Result) noexcept
{
    if ( const ErrorType* c = std::get_if<ErrorType>(&Result); c != nullptr )
    {
        return true;
    }

    return false;
}


template<class T>
constexpr bool
Success(Result<T> const& Result) noexcept
{
    return !Failed(Result);
}


template<class T>
T
Value(Result<T> const& SuccessResult)
{
    //
    // if `SuccessResult` has failed the following line will throw `std::bad_variant_access` anyway, which is consistent
    // with what we'd expect
    //
    return std::move(std::get<Ok<T>>(SuccessResult).Value);
}


template<class T>
constexpr ErrorType const&
Error(Result<T> const& ErrorResult)
{
    if ( const ErrorType* c = std::get_if<ErrorType>(&ErrorResult); c != nullptr )
    {
        return *c;
    }
    throw std::bad_variant_access();
}


template<class T>
constexpr T const
ValueOr(Result<T> const& res, T AlternativeValue)
{
    return Success(res) ? Value(res) : AlternativeValue;
}

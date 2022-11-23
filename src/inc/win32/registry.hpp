#pragma once

///
///@file registry.hpp
///
///@brief Interface to pwn::windows::Registry, a class to easily manipulate Windows registry
///
/// @link https://docs.microsoft.com/en-us/windows/win32/sysinfo/registry-element-size-limits
///

// clang-format off
#include "common.hpp"

#include "handle.hpp"
#include "utils.hpp"
// clang-format on

#define MAX_REGSZ_KEY_SIZE 255
#define MAX_REGSZ_VALUE_NAME_SIZE 16383
#define MAX_REGSZ_VALUE_SIZE 1 * 1024 * 1024 // arbirary value, todo: fix


namespace pwn::windows
{

///
///@brief Managed handle for registry key, autocall to `RegCloseKey` on destruction
///
///@note HKEY = struct HKEY__
///
using RegistryHandle = pwn::GenericHandle<HKEY__, RegCloseKey>;

class Registry
{
public:
    ///
    ///@brief Alias to `HKEY_LOCAL_MACHINE`
    ///
    static inline HKEY const HKLM = HKEY_LOCAL_MACHINE;

    ///
    ///@brief Alias to `HKEY_CURRENT_USER`
    ///
    static inline HKEY const HKCU = HKEY_CURRENT_USER;

    ///
    ///@brief Alias to `HKEY_USERS`
    ///
    static inline HKEY const HKU = HKEY_USERS;

    ///
    ///@brief Alias to `HKEY_CLASSES_ROOT`
    ///
    static inline HKEY const HKCR = HKEY_CLASSES_ROOT;

    ///
    ///@brief Alias to `HKEY_CURRENT_CONFIG`
    ///
    static inline HKEY const HKCC = HKEY_CURRENT_CONFIG;


    ///
    ///@brief The generic function to query the registry for a specific value in the given key.
    ///
    ///@tparam T the expected output type - is used to infer the type of data to get
    ///@param hKeyRoot
    ///@param SubKey
    ///@param KeyName
    ///@return Result<T>
    ///
    template<typename T>
    Result<T> static Read(
        const HKEY hKeyRoot,
        const std::wstring_view& SubKey,
        const std::wstring_view& KeyName,
        const usize Size = sizeof(T))
    {
        auto hKey =
            RegistryHandle {[&hKeyRoot, &SubKey]()
                            {
                                HKEY h;
                                if ( ::RegOpenKeyExW(hKeyRoot, SubKey.data(), 0, KEY_READ, &h) != ERROR_SUCCESS )
                                {
                                    return static_cast<HKEY>(INVALID_HANDLE_VALUE);
                                }
                                return h;
                            }()};
        if ( !hKey )
        {
            return Err(ErrorCode::ExternalApiCallFailed);
        }

        T KeyValue;
        DWORD ValueSize = Size;
        u32 res         = 0;

        if constexpr ( std::is_same_v<T, std::wstring> ) // REG_SZ
        {
            DWORD ValueLength = ValueSize / sizeof(wchar_t);
            do
            {
                KeyValue.resize(ValueLength);
                res = ::RegQueryValueExW(hKey.get(), KeyName.data(), 0, nullptr, (PBYTE)&KeyValue[0], &ValueSize);
                ValueLength = ValueSize / sizeof(wchar_t);
            } while ( res == ERROR_MORE_DATA );

            KeyValue.resize(ValueLength - 1); // because null byte
            KeyValue.shrink_to_fit();
        }
        else if constexpr ( std::is_same_v<T, std::vector<std::wstring>> ) // REG_MULTI_SZ
        {
            std::wstring TempValue;
            DWORD TempValueLength = ValueSize / sizeof(wchar_t);
            do
            {
                TempValue.resize(TempValueLength);
                res = ::RegQueryValueExW(hKey.get(), KeyName.data(), 0, nullptr, (PBYTE)&TempValue[0], &ValueSize);
                TempValueLength = ValueSize / sizeof(wchar_t);
            } while ( res == ERROR_MORE_DATA );

            TempValue.resize(TempValueLength - 1); // because null byte
            TempValue.shrink_to_fit();

            KeyValue = std::move(pwn::utils::StringLib::Split(TempValue, L'\0'));
        }
        else if constexpr ( std::is_same_v<T, std::vector<u8>> ) // REG_BINARY
        {
            do
            {
                KeyValue.resize(ValueSize);
                res = ::RegQueryValueExW(hKey.get(), KeyName.data(), 0, nullptr, (PBYTE)&KeyValue[0], &ValueSize);
            } while ( res == ERROR_MORE_DATA );
        }
        else // REG_DWORD, REG_QWORD, TODO
        {
            res = ::RegQueryValueExW(hKey.get(), KeyName.data(), 0, nullptr, (PBYTE)&KeyValue, &ValueSize);
        }

        switch ( res )
        {
        case ERROR_SUCCESS:
            break;

        case ERROR_MORE_DATA:
            return Err(ErrorCode::BufferTooSmall);

        case ERROR_FILE_NOT_FOUND:
            return Err(ErrorCode::NotFound);

        default:
            return Err(ErrorCode::ExternalApiCallFailed);
        }

        return Ok(KeyValue);
    }


    ///
    ///@brief Helper to the templated `Read` function, to directly extract a DWORD from registry
    ///
    ///@param hKeyRoot
    ///@param SubKey
    ///@param KeyName
    ///@return Result<DWORD>
    ///
    static Result<DWORD>
    ReadDword(const HKEY hKeyRoot, const std::wstring_view& SubKey, const std::wstring_view& KeyName);


    ///
    ///@brief Helper to the templated `Read` function, to directly extract a QWORD from registry
    ///
    ///@param hKeyRoot
    ///@param SubKey
    ///@param KeyName
    ///@return Result<DWORD64>
    ///
    static Result<DWORD64>
    ReadQword(const HKEY hKeyRoot, const std::wstring_view& SubKey, const std::wstring_view& KeyName);


    ///
    ///@brief Helper to the templated `Read` function, to directly extract a string from registry
    ///
    ///@param hKeyRoot
    ///@param SubKey
    ///@param KeyName
    ///@return Result<std::wstring>
    ///
    static Result<std::wstring>
    ReadWideString(const HKEY hKeyRoot, const std::wstring_view& SubKey, const std::wstring_view& KeyName);


    ///
    ///@brief Helper to the templated `Read` function, to directly extract an array of string from registry
    ///
    ///@param hKeyRoot
    ///@param SubKey
    ///@param KeyName
    ///@return Result<std::vector<std::wstring>>
    ///
    static Result<std::vector<std::wstring>>
    ReadWideStringArray(const HKEY hKeyRoot, const std::wstring_view& SubKey, const std::wstring_view& KeyName);


    ///
    ///@brief Helper to the templated `Read` function, to directly extract a vector of bytes from registry
    ///
    ///@param hKeyRoot
    ///@param SubKey
    ///@param KeyName
    ///@return Result<std::vector<u8>>
    ///
    static Result<std::vector<u8>>
    ReadBytes(const HKEY hKeyRoot, const std::wstring_view& SubKey, const std::wstring_view& KeyName);


    ///
    ///@brief Sets the registry for a specific value in the given key.
    ///
    ///@tparam T
    ///@param hKeyRoot
    ///@param SubKey
    ///@param KeyName
    ///@return Result<T>
    ///
    template<typename T>
    Result<u32> static Write(
        const HKEY hKeyRoot,
        std::wstring_view const& SubKey,
        std::wstring_view const& KeyName,
        T const& KeyValue)
    {
        u32 res            = 0;
        DWORD KeyValueSize = 0;
        auto hKey =
            RegistryHandle {[&hKeyRoot, &SubKey]()
                            {
                                HKEY h;
                                if ( ::RegOpenKeyExW(hKeyRoot, SubKey.data(), 0, KEY_SET_VALUE, &h) != ERROR_SUCCESS )
                                {
                                    return static_cast<HKEY>(INVALID_HANDLE_VALUE);
                                }
                                return h;
                            }()};
        if ( !hKey )
        {
            return Err(ErrorCode::ExternalApiCallFailed);
        }

        if constexpr ( std::is_same_v<T, std::wstring> ) // REG_SZ
        {
            KeyValueSize = KeyValue.size() * sizeof(wchar_t);
            res          = ::RegSetValueExW(hKey.get(), KeyName.data(), 0, REG_SZ, (PBYTE)&KeyValue[0], KeyValueSize);
        }
        else if constexpr ( std::is_same_v<T, std::vector<u8>> ) // REG_BINARY
        {
            KeyValueSize = KeyValue.size();
            res = ::RegSetValueExW(hKey.get(), KeyName.data(), 0, REG_BINARY, (PBYTE)&KeyValue[0], KeyValueSize);
        }
        else // REG_QWORD, REG_DWORD, REG_NONE
        {
            KeyValueSize             = sizeof(T);
            const DWORD KeyValueType = (KeyValueSize == 8) ? REG_QWORD : (KeyValueSize == 0) ? REG_NONE : REG_DWORD;
            res = ::RegSetValueExW(hKey.get(), KeyName.data(), 0, KeyValueType, (PBYTE)&KeyValue, KeyValueSize);
        }

        switch ( res )
        {
        case ERROR_SUCCESS:
            break;

        case ERROR_MORE_DATA:
            return Err(ErrorCode::BufferTooSmall);

        case ERROR_FILE_NOT_FOUND:
            return Err(ErrorCode::NotFound);

        default:
            return Err(ErrorCode::ExternalApiCallFailed);
        }

        return Ok(KeyValue);
    }


    ///
    ///@brief Enumerates the subkeys of the specified open registry key.
    ///
    ///@param hKeyRoot
    ///@param SubKey
    ///@return Result<std::vector<std::wstring>>
    ///
    static Result<std::vector<std::wstring>>
    ListKeys(const HKEY hKeyRoot, std::wstring_view const& SubKey);


    ///
    ///@brief Enumerates the values for the specified open registry key.
    ///
    ///@param hKeyRoot
    ///@param SubKey
    ///@return Result<std::vector<std::wstring>>
    ///
    static Result<std::vector<std::wstring>>
    ListValues(const HKEY hKeyRoot, std::wstring_view const& SubKey);


private:
};


} // namespace pwn::windows

#pragma once

///
///@file registry.hpp
///
///@brief Interface to pwn::windows::Registry, a class to easily manipulate Windows registry
///
/// @link https://docs.microsoft.com/en-us/windows/win32/sysinfo/registry-element-size-limits
///

#include "common.hpp"

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
    ///@brief
    ///
    static inline HKEY const HKLM = HKEY_LOCAL_MACHINE;

    ///
    ///@brief
    ///
    static inline HKEY const HKCU = HKEY_CURRENT_USER;

    ///
    ///@brief
    ///
    static inline HKEY const HKU = HKEY_USERS;


    static inline HKEY const HKCR = HKEY_CLASSES_ROOT;


    static inline HKEY const HKCC = HKEY_CURRENT_CONFIG;


    ///
    ///@brief Query the registry for a specific value in the given key.
    ///
    ///@tparam T
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

        if constexpr ( std::is_same_v<T, std::wstring> )
        {
            do
            {
                KeyValue.resize(ValueSize);
                res = ::RegQueryValueExW(hKey.get(), KeyName.data(), 0, nullptr, (PBYTE)&KeyValue[0], &ValueSize);
                ValueSize /= sizeof(wchar_t);
            } while ( res == ERROR_MORE_DATA );

            KeyValue.resize(ValueSize - 1); // because null byte
            KeyValue.shrink_to_fit();
        }
        else if constexpr ( std::is_same_v<T, std::vector<u8>> )
        {
            do
            {
                KeyValue.resize(ValueSize);
                res = ::RegQueryValueExW(hKey.get(), KeyName.data(), 0, nullptr, (PBYTE)&KeyValue[0], &ValueSize);
            } while ( res == ERROR_MORE_DATA );
        }
        else
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
    ReadDword(const HKEY hKeyRoot, const std::wstring_view& SubKey, const std::wstring_view& KeyName)
    {
        return Read<DWORD>(hKeyRoot, SubKey, KeyName);
    }

    ///
    ///@brief Helper to the templated `Read` function, to directly extract a QWORD from registry
    ///
    ///@param hKeyRoot
    ///@param SubKey
    ///@param KeyName
    ///@return Result<DWORD64>
    ///
    static Result<DWORD64>
    ReadQword(const HKEY hKeyRoot, const std::wstring_view& SubKey, const std::wstring_view& KeyName)
    {
        return Read<DWORD64>(hKeyRoot, SubKey, KeyName);
    }

    ///
    ///@brief Helper to the templated `Read` function, to directly extract a string from registry
    ///
    ///@param hKeyRoot
    ///@param SubKey
    ///@param KeyName
    ///@return Result<std::wstring>
    ///
    static Result<std::wstring>
    ReadWideString(const HKEY hKeyRoot, const std::wstring_view& SubKey, const std::wstring_view& KeyName)
    {
        return Read<std::wstring>(hKeyRoot, SubKey, KeyName, 256);
    }

    ///
    ///@brief Helper to the templated `Read` function, to directly extract a vector of bytes from registry
    ///
    ///@param hKeyRoot
    ///@param SubKey
    ///@param KeyName
    ///@return Result<std::vector<u8>>
    ///
    static Result<std::vector<u8>>
    ReadBytes(const HKEY hKeyRoot, const std::wstring_view& SubKey, const std::wstring_view& KeyName)
    {
        return Read<std::vector<u8>>(hKeyRoot, SubKey, KeyName, 16);
    }


private:
};


} // namespace pwn::windows

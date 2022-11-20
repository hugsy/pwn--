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


    static Result<DWORD>
    ReadDword(const HKEY hKeyRoot, const std::wstring_view& SubKey, const std::wstring_view& KeyName)
    {
        return Read<DWORD>(hKeyRoot, SubKey, KeyName);
    }

    static Result<DWORD64>
    ReadQword(const HKEY hKeyRoot, const std::wstring_view& SubKey, const std::wstring_view& KeyName)
    {
        return Read<DWORD64>(hKeyRoot, SubKey, KeyName);
    }

    static Result<std::wstring>
    ReadString(const HKEY hKeyRoot, const std::wstring_view& SubKey, const std::wstring_view& KeyName)
    {
        // auto res = Read<WCHAR[256]>(hKeyRoot, SubKey, KeyName);
        // if ( Failed(res) )
        // {
        //     return Err(Error(res).code);
        // }
        // return Ok(std::wstring(Value(res)));
        return Err(ErrorCode::NotImplementedError);
    }

    static Result<std::vector<u8>>
    ReadBytes(const HKEY hKeyRoot, const std::wstring_view& SubKey, const std::wstring_view& KeyName)
    {
        // auto res = Read<u8[256]>(hKeyRoot, SubKey, KeyName);
        // if ( Failed(res) )
        // {
        //     return Err(Error(res).code);
        // }
        // return Ok(std::move(Value(res)));
        return Err(ErrorCode::NotImplementedError);
    }


private:
    template<typename T, usize S = sizeof(T)>
    Result<T> static Read(const HKEY hKeyRoot, const std::wstring_view& SubKey, const std::wstring_view& KeyName)
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
        DWORD ValueSize = S;
        switch ( ::RegQueryValueExW(hKey.get(), KeyName.data(), 0, nullptr, (PBYTE)&KeyValue, &ValueSize) )
        {
        case ERROR_SUCCESS:
            break;

        case ERROR_MORE_DATA:
            // TODO: handle case
            return Err(ErrorCode::BufferTooSmall);

        case ERROR_FILE_NOT_FOUND:
            return Err(ErrorCode::NotFound);

        default:
            return Err(ErrorCode::ExternalApiCallFailed);
        }

        return Ok(KeyValue);
    }
};


} // namespace pwn::windows

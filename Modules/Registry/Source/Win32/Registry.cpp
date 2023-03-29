#include "Win32/Registry.hpp"


namespace pwn::Registry
{

#pragma region Registry::Read

Result<DWORD>
Registry::ReadDword(const HKEY hKeyRoot, const std::wstring_view& SubKey, const std::wstring_view& KeyName)
{
    return Read<DWORD>(hKeyRoot, SubKey, KeyName);
}


Result<DWORD64>
Registry::ReadQword(const HKEY hKeyRoot, const std::wstring_view& SubKey, const std::wstring_view& KeyName)
{
    return Read<DWORD64>(hKeyRoot, SubKey, KeyName);
}


Result<std::wstring>
Registry::ReadWideString(const HKEY hKeyRoot, const std::wstring_view& SubKey, const std::wstring_view& KeyName)
{
    return Read<std::wstring>(hKeyRoot, SubKey, KeyName, 256);
}


Result<std::vector<std::wstring>>
Registry::ReadWideStringArray(const HKEY hKeyRoot, const std::wstring_view& SubKey, const std::wstring_view& KeyName)
{
    return Read<std::vector<std::wstring>>(hKeyRoot, SubKey, KeyName, 16);
}


Result<std::vector<u8>>
Registry::ReadBytes(const HKEY hKeyRoot, const std::wstring_view& SubKey, const std::wstring_view& KeyName)
{
    return Read<std::vector<u8>>(hKeyRoot, SubKey, KeyName, 16);
}

#pragma endregion


#pragma region Registry::Enumerate

Result<std::vector<std::wstring>>
Registry::ListKeys(const HKEY hKeyRoot, std::wstring_view const& SubKey)
{
    auto hKey = RegistryHandle {
        [&hKeyRoot, &SubKey]()
        {
            HKEY h;
            if ( ::RegOpenKeyExW(hKeyRoot, SubKey.data(), 0, KEY_ENUMERATE_SUB_KEYS, &h) != ERROR_SUCCESS )
            {
                return static_cast<HKEY>(INVALID_HANDLE_VALUE);
            }
            return h;
        }()};
    if ( !hKey )
    {
        return Err(ErrorCode::ExternalApiCallFailed);
    }

    std::vector<std::wstring> Entries;
    DWORD dwIndex = 0;

    DWORD CurrentKeySize = 256;
    DWORD CurrentKeyType = 0;
    std::wstring CurrentKeyName;
    CurrentKeyName.resize(CurrentKeySize);

    bool bHasMoreKey = true;

    while ( bHasMoreKey )
    {
        CurrentKeyName.clear();

        LONG res = ::RegEnumKeyExW(
            hKey.get(),
            dwIndex,
            &CurrentKeyName[0],
            &CurrentKeySize,
            nullptr,
            nullptr,
            nullptr,
            nullptr);

        switch ( res )
        {
        case ERROR_NO_MORE_ITEMS:
            bHasMoreKey = false;
            break;

        case ERROR_MORE_DATA:
            CurrentKeySize *= 2;
            CurrentKeyName.resize(CurrentKeySize);
            break;

        case ERROR_SUCCESS:
            dwIndex++;
            Entries.push_back(CurrentKeyName);
            break;

        default:
            return Err(ErrorCode::ExternalApiCallFailed);
        }
    }

    return Ok(Entries);
}


Result<std::vector<std::wstring>>
Registry::ListValues(const HKEY hKeyRoot, std::wstring_view const& SubKey)
{
    auto hKey =
        RegistryHandle {[&hKeyRoot, &SubKey]()
                        {
                            HKEY h;
                            if ( ::RegOpenKeyExW(hKeyRoot, SubKey.data(), 0, KEY_QUERY_VALUE, &h) != ERROR_SUCCESS )
                            {
                                return static_cast<HKEY>(INVALID_HANDLE_VALUE);
                            }
                            return h;
                        }()};
    if ( !hKey )
    {
        return Err(ErrorCode::ExternalApiCallFailed);
    }

    std::vector<std::wstring> Entries;
    DWORD dwIndex = 0;

    DWORD CurrentValueSize = 256;
    DWORD CurrentValueType = 0;
    std::wstring CurrentValueName;
    CurrentValueName.resize(CurrentValueSize);

    bool bHasMoreValue = true;

    while ( bHasMoreValue )
    {
        CurrentValueName.clear();

        LONG res = ::RegEnumValueW(
            hKey.get(),
            dwIndex,
            &CurrentValueName[0],
            &CurrentValueSize,
            nullptr,
            &CurrentValueType,
            nullptr,
            nullptr);

        switch ( res )
        {
        case ERROR_NO_MORE_ITEMS:
            bHasMoreValue = false;
            break;

        case ERROR_MORE_DATA:
            CurrentValueSize *= 2;
            CurrentValueName.resize(CurrentValueSize);
            break;

        case ERROR_SUCCESS:
            dwIndex++;
            Entries.push_back(CurrentValueName);
            break;

        default:
            return Err(ErrorCode::ExternalApiCallFailed);
        }
    }

    return Ok(Entries);
}


// TODO registry watch NtNotifyChangeKey() -> https://gist.github.com/hugsy/356da2e86e41a0cd3502a38bdce6e4ce

#pragma endregion

} // namespace pwn::Registry

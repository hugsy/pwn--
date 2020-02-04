#include "process.h"



_Success_(return == ERROR_SUCCESS)
DWORD pwn::process::get_integrity_level(_In_ DWORD dwProcessId, _Out_ std::wstring & IntegrityLevelName)
{
    HANDLE hProcessHandle = INVALID_HANDLE_VALUE;
    HANDLE hProcessToken = INVALID_HANDLE_VALUE;
    DWORD dwRes = ERROR_SUCCESS;
    PTOKEN_MANDATORY_LABEL pTIL = NULL;
    DWORD dwIntegrityLevel = SECURITY_MANDATORY_MEDIUM_RID;

    do
    {
        hProcessHandle = ::OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);
        if (hProcessHandle == NULL)
        {
            dwRes = ::GetLastError();
            break;
        }

        if (!::OpenProcessToken(hProcessHandle, TOKEN_QUERY, &hProcessToken))
        {
            dwRes = ::GetLastError();
            break;
        }

        DWORD dwLengthNeeded;

        if (!::GetTokenInformation(hProcessToken, TokenIntegrityLevel, NULL, 0, &dwLengthNeeded))
        {
            dwRes = ::GetLastError();
            if (dwRes != ERROR_INSUFFICIENT_BUFFER)
            {
                dwRes = ::GetLastError();
                break;
            }
        }

        pTIL = (PTOKEN_MANDATORY_LABEL)::LocalAlloc(LPTR, dwLengthNeeded);
        if (!pTIL)
        {
            dwRes = ::GetLastError();
            break;
        }


        if (!::GetTokenInformation(hProcessToken, TokenIntegrityLevel, pTIL, dwLengthNeeded, &dwLengthNeeded))
        {
            dwRes = ::GetLastError();
            if (dwRes != ERROR_INSUFFICIENT_BUFFER)
            {
                dwRes = ::GetLastError();
                break;
            }
        }

        dwIntegrityLevel = *::GetSidSubAuthority(
            pTIL->Label.Sid,
            (DWORD)(UCHAR)(*::GetSidSubAuthorityCount(pTIL->Label.Sid) - 1)
        );

        ::LocalFree(pTIL);


        if (dwIntegrityLevel == SECURITY_MANDATORY_LOW_RID)
            IntegrityLevelName = L"Low";

        else if (SECURITY_MANDATORY_MEDIUM_RID < dwIntegrityLevel && dwIntegrityLevel < SECURITY_MANDATORY_HIGH_RID)
            IntegrityLevelName = L"Medium";

        else if (dwIntegrityLevel >= SECURITY_MANDATORY_HIGH_RID)
            IntegrityLevelName = L"High";

        else if (dwIntegrityLevel >= SECURITY_MANDATORY_SYSTEM_RID)
            IntegrityLevelName = L"System";

        else
            IntegrityLevelName = L"Unknown";

    } while (0);

    if (hProcessToken != INVALID_HANDLE_VALUE)
        ::CloseHandle(hProcessToken);

    if (hProcessHandle)
        ::CloseHandle(hProcessHandle);

    return ERROR_SUCCESS;
}


_Success_(return == ERROR_SUCCESS)
DWORD pwn::process::get_integrity_level(_Out_ std::wstring & IntegrityLevelName)
{
    return get_integrity_level(::GetCurrentProcessId(), IntegrityLevelName);
}
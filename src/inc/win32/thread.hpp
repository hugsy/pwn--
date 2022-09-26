#pragma once

#include <optional>

#include "common.hpp"
#include "nt.hpp"

extern "C"
{
    NTSTATUS
    NTAPI
    NtSetInformationThread(
        _In_ HANDLE ThreadHandle,
        _In_ THREADINFOCLASS ThreadInformationClass,
        _In_reads_bytes_(ThreadInformationLength) PVOID ThreadInformation,
        _In_ ULONG ThreadInformationLength);

    NTSTATUS NTAPI
    NtQueryInformationThread(
        IN HANDLE ThreadHandle,
        IN THREADINFOCLASS ThreadInformationClass,
        OUT PVOID ThreadInformation,
        IN ULONG ThreadInformationLength,
        OUT PULONG ReturnLength OPTIONAL);
}


namespace pwn::windows
{

class Thread
{
public:
    Thread(u32 Tid = ::GetCurrentThreadId()) : m_Tid(Tid), m_Teb(0), m_ThreadHandle(nullptr)
    {
        ReOpenHandleWith(TOKEN_ALL_ACCESS);
    }

    ~Thread()
    {
    }

    ///
    /// @brief Get the thread name
    ///
    /// @return std::optional<std::wstring>
    ///
    Result<std::wstring>
    Name();

    ///
    /// @brief Set the thread name
    ///
    /// @param NewName
    /// @return true
    /// @return false
    ///
    Result<bool>
    Name(std::wstring const& NewName);

    ///
    /// @brief Update the thread handle with new access
    ///
    /// @param DesiredAccess
    /// @return true
    /// @return false
    ///
    Result<bool>
    ReOpenHandleWith(DWORD DesiredAccess);

private:
    u32 m_Tid;
    uptr m_Teb;
    std::optional<std::wstring> m_Name;
    UniqueHandle m_ThreadHandle;
};

} // namespace pwn::windows

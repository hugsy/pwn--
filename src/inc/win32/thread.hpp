#pragma once

#include <optional>

#include "common.hpp"
#include "handle.hpp"
#include "log.hpp"
#include "nt.hpp"
/*
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
*/

namespace pwn::windows
{

class Thread
{
public:
    Thread() :
        m_Tid(0),
        m_Valid(false),
        m_ProcessHandle(nullptr),
        m_ThreadHandle(nullptr),
        m_ThreadHandleAccessMask(0),
        m_Teb(0)
    {
    }

    Thread(u32 Tid, SharedHandle ProcessHandle) :
        m_Tid(Tid),
        m_Valid(false),
        m_ProcessHandle(ProcessHandle),
        m_ThreadHandle(nullptr),
        m_ThreadHandleAccessMask(0),
        m_Teb(0)
    {
        if ( Success(ReOpenHandleWith(THREAD_QUERY_LIMITED_INFORMATION)) )
        {
            m_Valid = (m_ThreadHandle != nullptr);
        }
    }

    Thread(Thread const& OldCopy) : m_ThreadHandle(nullptr), m_ThreadHandleAccessMask(0)
    {
        m_ProcessHandle = OldCopy.m_ProcessHandle;
        m_Tid           = OldCopy.m_Tid;
        m_Teb           = OldCopy.m_Teb;
        m_Name          = OldCopy.m_Name;

        const HANDLE hProcess   = m_ProcessHandle->get();
        const HANDLE hSource    = OldCopy.m_ThreadHandle.get();
        HANDLE hDupThreadHandle = INVALID_HANDLE_VALUE;
        if ( ::DuplicateHandle(hProcess, hSource, hProcess, &hDupThreadHandle, 0, false, DUPLICATE_SAME_ACCESS) )
        {
            m_ThreadHandle           = pwn::UniqueHandle {hDupThreadHandle};
            m_ThreadHandleAccessMask = OldCopy.m_ThreadHandleAccessMask;
        }
        else
        {
            log::perror(L"DuplicateHandle()");
        }

        m_Valid = (m_ThreadHandle != nullptr);
    }

    Thread&
    operator=(Thread const& OldCopy)
    {
        m_ProcessHandle = OldCopy.m_ProcessHandle;
        m_Tid           = OldCopy.m_Tid;
        m_Teb           = OldCopy.m_Teb;
        m_Name          = OldCopy.m_Name;

        const HANDLE hProcess   = m_ProcessHandle->get();
        const HANDLE hSource    = OldCopy.m_ThreadHandle.get();
        HANDLE hDupThreadHandle = INVALID_HANDLE_VALUE;
        if ( ::DuplicateHandle(hProcess, hSource, hProcess, &hDupThreadHandle, 0, false, DUPLICATE_SAME_ACCESS) )
        {
            m_ThreadHandle           = pwn::UniqueHandle {hDupThreadHandle};
            m_ThreadHandleAccessMask = OldCopy.m_ThreadHandleAccessMask;
        }
        else
        {
            log::perror(L"DuplicateHandle()");
        }

        m_Valid = (m_ThreadHandle != nullptr);

        return *this;
    }

    bool
    IsValid() const
    {
        return m_Valid;
    }


    ///
    /// @brief Get the thread Id
    ///
    /// @return u32 const
    ///
    u32 const
    ThreadId() const;


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

    ///
    /// @brief
    ///
    /// @return Result<Thread>
    ///
    static Result<Thread>
    Current();

    ///
    /// @brief
    ///
    /// @param ProcessInformationClass
    /// @return Result<std::shared_ptr<u8[]>>
    ///
    Result<std::shared_ptr<u8[]>>
    Query(THREADINFOCLASS ThreadInformationClass);

private:
    u32 m_Tid;
    bool m_Valid;
    uptr m_Teb;
    std::optional<std::wstring> m_Name;
    SharedHandle m_ProcessHandle;
    UniqueHandle m_ThreadHandle;
    u32 m_ThreadHandleAccessMask;
};


class ThreadGroup
{
public:
    ThreadGroup() : m_ProcessHandle(nullptr)
    {
    }

    ThreadGroup(SharedHandle ProcessHandle) : m_ProcessHandle(ProcessHandle)
    {
    }

    Result<std::vector<u32>>
    List();

    Thread
    operator[](const u32 Tid);

private:
    SharedHandle m_ProcessHandle;
};

} // namespace pwn::windows

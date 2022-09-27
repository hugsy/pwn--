#pragma once

#include <optional>

#include "common.hpp"
#include "handle.hpp"
#include "log.hpp"
#include "nt.hpp"


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
        if ( Success(ReOpenThreadWith(THREAD_QUERY_LIMITED_INFORMATION)) )
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
    ReOpenThreadWith(DWORD DesiredAccess);

    ///
    /// @brief
    ///
    /// @return Result<Thread>
    ///
    static Result<Thread>
    Current();

    ///
    /// @brief Query thread information
    ///
    /// @tparam T
    /// @param ThreadInformationClass
    /// @return Result<std::shared_ptr<T>>
    ///
    template<class T>
    Result<std::shared_ptr<T>>
    Query(THREADINFOCLASS ThreadInformationClass)
    {
        auto res = QueryInternal(ThreadInformationClass, sizeof(T));
        if ( Failed(res) )
        {
            return Err(Error(res).code);
        }

        const auto p = reinterpret_cast<T*>(Value(res));
        auto deleter = [](T* x)
        {
            ::LocalFree(x);
        };
        return Ok(std::shared_ptr<T>(p, deleter));
    }

private:
    ///
    /// @brief Should not be called directly
    ///
    /// @param ThreadInformationClass
    ///
    /// @return Result<PVOID>
    ///
    Result<PVOID>
    QueryInternal(const THREADINFOCLASS, const usize);

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
    at(const u32 Tid);

    Thread
    operator[](const u32 Tid);

private:
    SharedHandle m_ProcessHandle;
};

} // namespace pwn::windows

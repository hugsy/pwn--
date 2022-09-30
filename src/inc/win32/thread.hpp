#pragma once

#include <optional>

#include "common.hpp"
#include "handle.hpp"
#include "log.hpp"
#include "nt.hpp"
#include "token.hpp"


namespace pwn::windows
{

class Thread
{
public:
    Thread() = default;

    Thread(u32 Tid, SharedHandle ProcessHandle) :
        m_Tid {Tid},
        m_Valid {false},
        m_ProcessHandle {ProcessHandle},
        m_ThreadHandle {nullptr},
        m_ThreadHandleAccessMask {0},
        m_Teb {0},
        Token {}
    {
        if ( Success(ReOpenThreadWith(THREAD_QUERY_INFORMATION)) )
        {
            m_Valid = (m_ThreadHandle != nullptr);
            Token   = windows::Token(m_ThreadHandle, Token::TokenType::Thread);
        }
    }


    Thread(Thread const& OldCopy)
    {
        m_ProcessHandle          = OldCopy.m_ProcessHandle;
        m_ThreadHandle           = OldCopy.m_ThreadHandle;
        m_Tid                    = OldCopy.m_Tid;
        m_Teb                    = OldCopy.m_Teb;
        m_Name                   = OldCopy.m_Name;
        m_ThreadHandleAccessMask = OldCopy.m_ThreadHandleAccessMask;
        Token                    = windows::Token(m_ThreadHandle, Token::TokenType::Thread);
        m_Valid                  = (m_ThreadHandle != nullptr);
    }


    Thread&
    operator=(Thread const& OldCopy)
    {
        m_ProcessHandle          = OldCopy.m_ProcessHandle;
        m_ThreadHandle           = OldCopy.m_ThreadHandle;
        m_Tid                    = OldCopy.m_Tid;
        m_Teb                    = OldCopy.m_Teb;
        m_Name                   = OldCopy.m_Name;
        m_ThreadHandleAccessMask = OldCopy.m_ThreadHandleAccessMask;
        Token                    = windows::Token(m_ThreadHandle, Token::TokenType::Thread);
        m_Valid                  = (m_ThreadHandle != nullptr);
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

    Token Token;

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

    u32 m_Tid                          = 0;
    bool m_Valid                       = false;
    uptr m_Teb                         = 0;
    std::optional<std::wstring> m_Name = std::nullopt;
    SharedHandle m_ProcessHandle       = nullptr;
    SharedHandle m_ThreadHandle        = nullptr;
    u32 m_ThreadHandleAccessMask       = 0;
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

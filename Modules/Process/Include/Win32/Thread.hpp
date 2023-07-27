#pragma once

#include "Common.hpp"
#include "Handle.hpp"
#include "Log.hpp"
#include "Win32/Process.hpp"
#include "Win32/Token.hpp"


namespace pwn::Process
{

class Process;

class Thread
{
public:
    ///
    /// @brief
    ///
    Thread() = default;


    ///
    ///@brief Construct a new Thread object from a TID.
    ///
    ///@param Tid
    ///
    Thread(u32 Tid, u32 Pid = 0);


    ///
    ///@brief Get the thread ID
    ///
    ///@return u32
    ///
    u32
    Id() const
    {
        return m_Tid;
    }


    ///
    /// @brief Get the thread Id
    ///
    /// @return u32 const
    ///
    u32
    ThreadId() const
    {
        return Id();
    }

    ///
    ///@brief
    ///
    ///@return true
    ///@return false
    ///
    bool
    IsRemote() const
    {
        return ::GetCurrentProcessId() != m_Pid;
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
    Name(std::wstring_view NewName);

    ///
    /// @brief Update the thread handle with new access
    ///
    /// @param DesiredAccess
    /// @return true
    /// @return false
    ///
    Result<bool>
    ReOpenThreadWith(DWORD DesiredAccess);


    HANDLE const
    Handle() const
    {
        return m_ThreadHandle.get();
    }


    ///
    /// @brief Query thread information
    ///
    /// @tparam T
    /// @param ThreadInformationClass
    /// @return Result<std::shared_ptr<T>>
    ///
    template<class T>
    Result<std::unique_ptr<T>>
    Query(THREADINFOCLASS ThreadInformationClass)
    {
        auto res = QueryInternal(ThreadInformationClass, sizeof(T));
        if ( Failed(res) )
        {
            return Error(res);
        }

        auto RawResult = Value(std::move(res));
        std::unique_ptr<T> TypedResult {(T*)RawResult.release()};
        return Ok(std::move(TypedResult));
    }


    ///
    ///@brief
    ///
    ///@return PTEB
    ///
    PTEB
    ThreadInformationBlock();

    // Security::Token Token;


    ///
    /// @brief
    ///
    /// @return Result<Thread>
    ///
    static Thread
    Current();

private:
    ///
    /// @brief Should not be called directly
    ///
    /// @param ThreadInformationClass
    ///
    /// @return Result<PVOID>
    ///
    Result<std::unique_ptr<u8[]>>
    QueryInternal(const THREADINFOCLASS, const usize);


    u32 m_Tid {0};
    u32 m_Pid {0};
    PTEB m_Teb {nullptr};
    UniqueHandle m_ThreadHandle {nullptr};
    u32 m_ThreadHandleAccessMask {0};
};

using ThreadGroup = IndexedVector<Thread>;


} // namespace pwn::Process

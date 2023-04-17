#pragma once

#include "Common.hpp"
#include "Handle.hpp"
#include "Log.hpp"
#include "Win32/Process.hpp"
#include "Win32/Token.hpp"


namespace pwn::Process
{

class Thread
{
public:
    Thread() = default;

    Thread(u32 Tid, std::shared_ptr<Process> const& Process);

    Thread(Thread const& OldCopy);

    Thread&
    operator=(Thread const& OldCopy);

    bool
    IsValid() const;

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

    SharedHandle const&
    Handle() const
    {
        return m_ThreadHandle;
    }

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

    ///
    ///@brief
    ///
    ///@return PTEB
    ///
    PTEB
    ThreadInformationBlock();

    Security::Token Token;

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
    bool m_IsSelf                      = false;
    PTEB m_Teb                         = nullptr;
    std::optional<std::wstring> m_Name = std::nullopt;
    std::shared_ptr<Process> m_Process = nullptr;
    SharedHandle m_ProcessHandle       = nullptr;
    SharedHandle m_ThreadHandle        = nullptr;
    u32 m_ThreadHandleAccessMask       = 0;
};


} // namespace Process

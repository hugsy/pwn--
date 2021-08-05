#pragma once

#include "common.h"

static const u64 __magic = 0xdeadbeef;
static auto dummy        = []() { throw __magic; };

namespace pwn::utils
{
template <typename T, typename D = decltype(dummy)>
class GenericHandle
{
public:
    GenericHandle(T h = nullptr, D d = dummy) : m_handle(h), m_closure_function(d)
    {
    }


    ~GenericHandle()
    {
        close();
    }


    GenericHandle(const GenericHandle &) = delete;


    auto
    operator=(const GenericHandle &) -> GenericHandle & = delete;


    GenericHandle(GenericHandle &&other) noexcept : m_handle(other.m_handle)
    {
        other.m_handle = nullptr;
    }


    auto
    operator=(GenericHandle &&other) noexcept -> GenericHandle &
    {
        if (this != &other)
        {
            close();
            m_handle       = other.m_handle;
            other.m_handle = nullptr;
        }
        return *this;
    }

    operator bool() const
    {
        return m_handle != nullptr && m_handle != INVALID_HANDLE_VALUE;
    }


    [[nodiscard]] auto
    get() const -> T
    {
        return m_handle;
    }

    virtual auto
    close() -> bool
    {
        bool res = false;

        if (bool(m_handle))
        {
            try
            {
                m_closure_function();
            }
            catch (u64 e)
            {
                if (e == __magic)
                {
                    ::CloseHandle(m_handle);
                }
            }
            m_handle = nullptr;
        }

        return res;
    }

protected:
    T m_handle;
    D m_closure_function;
};
} // namespace pwn::utils

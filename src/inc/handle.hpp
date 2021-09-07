#pragma once

#include "common.hpp"

static const u64 ______magic = 0xdeadbeef;
static auto _______dummy        = []()
{
    throw ______magic;
};

#ifdef __linux__
#define InvalidHandleValue    -1
#else
#define InvalidHandleValue    INVALID_HANDLE_VALUE
#endif

namespace pwn::utils
{
template<typename T, typename D = decltype(_______dummy)>
class GenericHandle
{
public:
    GenericHandle(T h = nullptr, D d = _______dummy) : m_handle(h), m_closure_function(d)
    {
    }


    ~GenericHandle()
    {
        close();
    }


    operator bool() const
    {
        return m_handle != nullptr && m_handle != InvalidHandleValue;
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

        if ( bool(m_handle) )
        {
            try
            {
                m_closure_function();
            }
            catch ( u64 e )
            {
                if ( e == ______magic )
                {
#ifdef __linux__
                    close(m_handle);
#else
                    ::CloseHandle(m_handle);
#endif
                }
            }
            m_handle = nullptr;
        }

        return res;
    }

    T m_handle = nullptr;

protected:
    D m_closure_function;
};
} // namespace pwn::utils

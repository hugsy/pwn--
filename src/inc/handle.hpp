#pragma once

#include <functional>

#include "common.hpp"


static auto ___dummy = []() {};

#ifdef __linux__
#define InvalidHandleValue -1
#else
#define InvalidHandleValue INVALID_HANDLE_VALUE
#endif

//
// TODO: replace everything with decltype() using lambda of unevaluated context when fixed in msvc
// @ref https://andreasfertig.blog/2022/08/cpp-insights-lambdas-in-unevaluated-contexts/
// @link bug -> https://developercommunity.visualstudio.com/t/c20-internal-compiler-error-for-lambda-in-decltype/1631476
//
namespace pwn::utils
{
template<typename T, typename D = decltype(___dummy)>
class GenericHandle
{
public:
    constexpr GenericHandle(T h = nullptr, D d = ___dummy) : m_handle(h), m_onCloseCallback(d)
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

    // Direct affectation
    auto
    operator=(T const& other)
    {
        m_handle = other;
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
            const uptr p1 = *((uptr*)&m_onCloseCallback);
            const uptr p2 = *((uptr*)&___dummy);
            if ( p1 != p2 )
            {
                m_onCloseCallback();
            }
            else
            {
#ifdef __linux__
                close(m_handle);
#else
                ::CloseHandle(m_handle);
#endif
            }
            m_handle = nullptr;
            res      = true;
        }

        return res;
    }

    T m_handle = nullptr;

protected:
    D m_onCloseCallback;
};

} // namespace pwn::utils

#pragma once

#include "common.h"

static const u64 __magic = 0xdeadbeef;
static auto dummy = []() { throw __magic; };

namespace pwn::utils
{
    template<typename T, typename D = decltype(dummy)>
    class GenericHandle
    {
    public:
        GenericHandle(T h = nullptr, D d = dummy) :m_handle(h), m_closure_function(d) {}
        ~GenericHandle() { close(); }
        GenericHandle(const GenericHandle&) = delete;
        GenericHandle& operator=(const GenericHandle&) = delete;
        GenericHandle(GenericHandle&& other) noexcept : m_handle(other.m_handle) { other.m_handle = nullptr; }
        GenericHandle& operator=(GenericHandle&& other) noexcept
        {
            if (this != &other)
            {
                close();
                m_handle = other.m_handle;
                other.m_handle = nullptr;
            }

            return *this;
        }

        operator bool() const { return m_handle != nullptr && m_handle != INVALID_HANDLE_VALUE; }
        T get() const { return m_handle; }

        virtual bool close()
        {
            bool res = false;
            
            if (bool(m_handle))
            {
                try
                {
                    m_closure_function();
                    ::wprintf(L"using lambda destructor\n");
                }
                catch(u64 e)
                {
                    if (e == __magic)
                    {
                        ::CloseHandle(m_handle);
                        ::wprintf(L"using default destructor\n");
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
}
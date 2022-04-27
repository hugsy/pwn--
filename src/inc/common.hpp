#pragma once

#include "constants.hpp"
#include "pwn_export.hpp"

#define __STR(x) #x
#define STR(x) __STR(x)
#define __WIDE(x) L#x
#define WIDECHAR(x) __WIDE(x)
#define __WIDE2(x) L##x
#define WIDECHAR2(x) __WIDE2(x)
#define CONCAT(x, y) (x##y)


#if defined(__PWNLIB_WINDOWS_BUILD__)
#include "win32/framework.hpp"

#elif defined(__PWNLIB_LINUX_BUILD__)
#include "linux/framework.hpp"
#endif


#ifndef __countof
#define __countof(x) (sizeof(x) / sizeof(x[0]))
#endif


#ifndef MIN
#define MIN(x, y) (((size_t)x) < ((size_t)y))
#endif


using u8  = uint8_t;
using u16 = uint16_t;
using u32 = uint32_t;
using u64 = uint64_t;

using uptr  = uintptr_t;
using usize = size_t;

using i8  = int8_t;
using i16 = int16_t;
using i32 = int32_t;
using i64 = int64_t;

namespace
{
auto static inline LoadLibraryWrapper(wchar_t const* name)
{
#if defined(__PWNLIB_WINDOWS_BUILD__)
    return ::LoadLibraryW(name);
#elif defined(__PWNLIB_LINUX_BUILD__)
    return dlopen(name, RTLD_LAZY);
#else
#error "invalid os"
#endif
}


template<typename M>
auto inline GetProcAddressWrapper(M hMod, std::string_view const& lpszProcName)
{
#if defined(__PWNLIB_WINDOWS_BUILD__)
    auto address = ::GetProcAddress(hMod, lpszProcName.data());
#elif defined(__PWNLIB_LINUX_BUILD__)
    auto address = dlsym(hMod, lpszProcName.data());
#else
#error "invalid os"
#endif
    if ( !address )
    {
        std::stringstream ss;
        ss << "Error importing '" << lpszProcName << "'";
        throw std::runtime_error(ss.str());
    }
    return address;
}
} // namespace


#define IMPORT_EXTERNAL_FUNCTION(Dll, Func, Ret, ...)                                                                  \
    typedef Ret(NTAPI* CONCAT(pwnFn_, Func))(__VA_ARGS__);                                                             \
                                                                                                                       \
    template<typename... Ts>                                                                                           \
    auto Func(Ts... ts)->Ret                                                                                           \
    {                                                                                                                  \
        auto __func = (pwnFn_##Func)GetProcAddressWrapper(LoadLibraryWrapper(Dll), STR(Func));                         \
        return __func(std::forward<Ts>(ts)...);                                                                        \
    }


///
/// @brief A constexpr map
/// @link https://xuhuisun.com/post/c++-weekly-2-constexpr-map/
///
/// @tparam Key
/// @tparam Value
/// @tparam Size
///
template<typename Key, typename Value, std::size_t Size>
struct CMap
{
    std::array<std::pair<Key, Value>, Size> data;

    [[nodiscard]] constexpr Value
    at(const Key& key) const
    {
        const auto itr = std::find_if(
            cbegin(data),
            cend(data),
            [&key](const auto& v)
            {
                return v.first == key;
            });
        if ( itr != end(data) )
        {
            return itr->second;
        }
        else
        {
            throw std::range_error("Not Found");
        }
    }
};


///
/// @brief A constexpr generic buffer
/// @link https://www.cppstories.com/2021/constexpr-new-cpp20/
///
/// @tparam T
///
template<typename T>
class CBuffer
{
public:
    constexpr CBuffer(size_t n) noexcept : size_(n), mem_(new T[n])
    {
    }
    constexpr ~CBuffer() noexcept
    {
        delete[] mem_;
    }

    constexpr CBuffer(const CBuffer& other) noexcept : size_(other.size_)
    {
        if ( &other != this )
        {
            mem_ = new T[size_];
            std::copy(other.mem_, other.mem_ + size_, mem_);
        }
    }

    constexpr CBuffer(CBuffer&& other) noexcept
    {
        if ( &other != this )
        {
            mem_        = other.mem_;
            size_       = other.size_;
            other.mem_  = nullptr;
            other.size_ = 0;
        }
    }

    constexpr CBuffer&
    operator=(const CBuffer& other) noexcept
    {
        if ( &other != this )
        {
            mem_ = new T[size_];
            std::copy(other.mem_, other.mem_ + size_, mem_);
        }
        return *this;
    }

    constexpr CBuffer&
    operator=(CBuffer&& other) noexcept
    {
        if ( &other != this )
        {
            mem_        = other.mem_;
            size_       = other.size_;
            other.mem_  = nullptr;
            other.size_ = 0;
        }
        return *this;
    }

    constexpr T&
    operator[](size_t id) noexcept
    {
        return mem_[id];
    }
    constexpr const T&
    operator[](size_t id) const noexcept
    {
        return mem_[id];
    }

    constexpr T*
    data() const noexcept
    {
        return mem_;
    }
    constexpr size_t
    size() const noexcept
    {
        return size_;
    }

private:
    T* mem_ {nullptr};
    size_t size_ {0};
};

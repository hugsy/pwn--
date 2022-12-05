#pragma once

#include <type_traits>
#include <utility>

#include "constants.hpp"
#include "error.hpp"
#include "pwn_export.hpp"

#define __STR(x) #x
#define STR(x) __STR(x)
#define __WIDE(x) L#x
#define WIDECHAR(x) __WIDE(x)
#define __WIDE2(x) L##x
#define WIDECHAR2(x) __WIDE2(x)
#define CONCAT(x, y) (x##y)


#if defined(PWN_BUILD_FOR_WINDOWS)
#include "win32/framework.hpp"

#elif defined(PWN_BUILD_FOR_LINUX)
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

#if defined(PWN_BUILD_FOR_WINDOWS)
using uptr  = ULONG_PTR;
using usize = SIZE_T;
using ssize = SSIZE_T;

#elif defined(PWN_BUILD_FOR_LINUX)
using uptr  = uintptr_t;
using usize = size_t;
using ssize = ssize_t;

#endif

using i8  = int8_t;
using i16 = int16_t;
using i32 = int32_t;
using i64 = int64_t;

namespace
{
auto static inline LoadLibraryWrapper(wchar_t const* name)
{
#if defined(PWN_BUILD_FOR_WINDOWS)
    return ::LoadLibraryW(name);
#elif defined(PWN_BUILD_FOR_LINUX)
    return dlopen(name, RTLD_LAZY);
#else
#error "invalid os"
#endif
}


template<typename M>
auto inline GetProcAddressWrapper(M hMod, std::string_view const& lpszProcName)
{
#if defined(PWN_BUILD_FOR_WINDOWS)
    auto address = ::GetProcAddress(hMod, lpszProcName.data());
#elif defined(PWN_BUILD_FOR_LINUX)
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


#ifndef UnreferencedParameter
#define UnreferencedParameter(x)                                                                                       \
    {                                                                                                                  \
        (void)(x);                                                                                                     \
    }
#endif // UnreferencedParameter

///
/// @brief A constexpr map
/// @ref https://xuhuisun.com/post/c++-weekly-2-constexpr-map/
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
/// @ref https://www.cppstories.com/2021/constexpr-new-cpp20/
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


///
/// @brief constexpr bitmask class
///
/// @tparam T
/// @tparam std::enable_if<std::is_enum<T>::value>::type
///
template<typename T, typename = typename std::enable_if<std::is_enum<T>::value>::type>
class CBitMask
{
    using N = typename std::underlying_type<T>::type;

    static constexpr N
    get(T a)
    {
        return static_cast<N>(a);
    }

    explicit constexpr CBitMask(N a) : m_val(a)
    {
    }

public:
    constexpr CBitMask() : m_val(0)
    {
    }

    constexpr CBitMask(T a) : m_val(get(a))
    {
    }

    constexpr CBitMask
    operator|(T t)
    {
        return CBitMask(m_val | get(t));
    }

    constexpr bool
    operator&(T t)
    {
        return m_val & get(t);
    }

    constexpr N const
    get() const
    {
        return m_val;
    }

private:
    N m_val = 0;
};


template<typename T>
concept Flattenable = std::same_as<T, std::vector<u8>> || std::same_as<T, std::string> || std::same_as<T, std::wstring>;

template<Flattenable T, Flattenable... Args>
constexpr usize
SumSizeOfFlattenable(T arg, Args... args)
{
    usize sz = 0;

    if constexpr ( std::is_same_v<T, std::string> )
    {
        sz += arg.size();
    }
    else if constexpr ( std::is_same_v<T, std::wstring> )
    {
        sz += arg.size() * sizeof(wchar_t);
    }
    else if constexpr ( std::is_same_v<T, std::vector<u8>> )
    {
        sz += arg.size();
    }
    else
    {
        sz += sizeof(arg);
    }

    if constexpr ( sizeof...(args) > 0 )
    {
        return sz + SumSizeOfFlattenable(args...);
    }

    return sz;
}

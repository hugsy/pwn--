#pragma once

#include <type_traits>
#include <utility>

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


///
/// @brief Rust-like type of error handling
///
struct ErrorType
{
    enum class Code
    {
        GenericError,
        RuntimeError,
        InvalidInput,
        InvalidParameter,
        UnexpectedType,
        ArithmeticError,
        OverflowError,
        UnderflowError,
        IllegalValue,
    };

    Code m_code;
    u32 m_errno;
};

template<class T>
using SuccessType = std::optional<T>;

template<class T>
using Result = std::variant<SuccessType<T>, ErrorType>;

struct Err : ErrorType
{
    Err(ErrorType::Code ErrCode = ErrorType::Code::GenericError) :
#ifdef _WIN32
        ErrorType(ErrCode, ::GetLastError())
#else
        ErrorType(ErrCode, errno)
#endif
    {
    }
};

template<class T>
struct Ok : SuccessType<T>
{
    Ok(T value) : SuccessType<T>(value)
    {
    }
};

template<class T>
constexpr bool
Success(Result<T> const& f)
{
    if ( const SuccessType<T>* c = std::get_if<SuccessType<T>>(&f); c != nullptr )
    {
        return true;
    }
    return false;
}

template<class T>
constexpr T const&
Value(Result<T> const& f)
{
    if ( const SuccessType<T>* c = std::get_if<SuccessType<T>>(&f); c != nullptr && c->has_value() )
    {
        return c->value();
    }
    throw std::bad_variant_access();
}

template<class T>
constexpr ErrorType const&
Error(Result<T> const& f)
{
    if ( const ErrorType* c = std::get_if<ErrorType>(&f); c != nullptr )
    {
        return *c;
    }
    throw std::bad_variant_access();
}


template<>
struct std::formatter<ErrorType, wchar_t> : std::formatter<std::wstring, wchar_t>
{
    auto
    format(ErrorType const a, wformat_context& ctx)
    {
        return formatter<wstring, wchar_t>::format(std::format(L"ERROR_{}", a), ctx);
    }
};

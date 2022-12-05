#pragma once

///
///@file Create a memory view from a raw u8* and a size, allowing to iterate, fill, read/write & more
///

#include <limits>

#include "common.hpp"


namespace pwn::utils
{

class MemoryView
{

public:
    using value_type             = u8;
    using difference_type        = std::ptrdiff_t;
    using iterator               = u8*;
    using const_iterator         = const u8*;
    using reverse_iterator       = std::reverse_iterator<iterator>;
    using const_reverse_iterator = std::reverse_iterator<const_iterator>;

#undef min
#undef max
    static const usize npos = std::numeric_limits<usize>::max();

    constexpr MemoryView(const MemoryView& other) = default;

    constexpr MemoryView(MemoryView&& other) = default;

    MemoryView&
    operator=(const MemoryView& other) noexcept = default;

    MemoryView&
    operator=(MemoryView&& other) noexcept = default;

    // construct from u8* and size
    constexpr MemoryView(u8* begin, usize size) : m_Pointer {begin}, m_Size {size}
    {
    }

    // construct from begin and end u8*
    constexpr MemoryView(u8* begin, u8* end) : m_Pointer {begin}, m_Size {(uptr)end - (uptr)begin}
    {
    }

    // construct from std::array
    template<std::size_t N>
    constexpr MemoryView(std::array<u8, N>& arr) : m_Pointer {arr.data()}, m_Size {N}
    {
    }

    // construct from std::vector
    constexpr MemoryView(std::vector<u8>& vec) : m_Pointer {vec.data()}, m_Size {vec.size()}
    {
    }

    // construct from std::string
    constexpr MemoryView(std::basic_string<u8>& str) : m_Pointer {str.data()}, m_Size {str.size()}
    {
    }

    void
    swap(MemoryView& other) noexcept
    {
        using std::swap;
        swap(m_Pointer, other.m_Pointer);
        swap(m_Size, other.m_Size);
    }

    // iterators:
    constexpr iterator
    begin() noexcept
    {
        return iterator(data());
    }
    constexpr const_iterator
    begin() const noexcept
    {
        return const_iterator(data());
    }
    constexpr iterator
    end() noexcept
    {
        return iterator(data() + size());
    }
    constexpr const_iterator
    end() const noexcept
    {
        return const_iterator(data() + size());
    }

    // reverse iterators
    constexpr reverse_iterator
    rbegin() noexcept
    {
        return reverse_iterator(end());
    }
    constexpr const_reverse_iterator
    rbegin() const noexcept
    {
        return const_reverse_iterator(end());
    }
    constexpr reverse_iterator
    rend() noexcept
    {
        return reverse_iterator(begin());
    }
    constexpr const_reverse_iterator
    rend() const noexcept
    {
        return const_reverse_iterator(begin());
    }

    // const iterators
    constexpr const_iterator
    cbegin() const noexcept
    {
        return begin();
    }
    constexpr const_iterator
    cend() const noexcept
    {
        return end();
    }
    constexpr const_reverse_iterator
    crbegin() const noexcept
    {
        return rbegin();
    }
    constexpr const_reverse_iterator
    crend() const noexcept
    {
        return rend();
    }

    // capacity:
    constexpr bool
    empty() const noexcept
    {
        return size() == 0;
    }
    constexpr usize
    size() const noexcept
    {
        return m_Size;
    }

    constexpr usize
    itemsize() const noexcept
    {
        return sizeof(u8);
    }

    constexpr usize
    nbytes() const noexcept
    {
        return itemsize() * size();
    }

    // element access:
    constexpr u8&
    operator[](usize n) noexcept
    {
        return m_Pointer[n];
    }
    constexpr u8 const&
    operator[](usize n) const noexcept
    {
        return m_Pointer[n];
    }
    constexpr u8&
    at(usize n)
    {
        if ( n >= size() )
        {
            std::out_of_range("MemoryView::at");
        }

        return m_Pointer[n];
    }
    constexpr u8 const&
    at(usize n) const
    {
        if ( n >= size() )
        {
            std::out_of_range("MemoryView::at");
        }

        return m_Pointer[n];
    }

    constexpr u8&
    front() noexcept
    {
        return m_Pointer[0];
    }
    constexpr u8 const&
    front() const noexcept
    {
        return m_Pointer[0];
    }
    constexpr u8&
    back() noexcept
    {
        return m_Pointer[size() - 1];
    }
    constexpr u8 const&
    back() const noexcept
    {
        return m_Pointer[size() - 1];
    }

    constexpr u8*
    data() noexcept
    {
        return m_Pointer;
    }
    constexpr const u8*
    data() const noexcept
    {
        return m_Pointer;
    }

    constexpr void
    remove_prefix(usize n) noexcept
    {
        m_Pointer += n;
        m_Size -= n;
    }
    constexpr void
    remove_suffix(usize n) noexcept
    {
        m_Size -= n;
    }

    constexpr MemoryView
    View(usize pos = 0, usize count = npos) const
    {
        if ( pos >= size() )
        {
            throw std::out_of_range("MemoryView::view");
        }

        u8* ptr  = (u8*)(data() + pos);
        usize sz = std::min(count, size() - pos);
        return MemoryView(ptr, sz);
    }

    void
    Fill(u8 c = 0x20)
    {
        std::memset(m_Pointer, c, m_Size);
    }

    template<Flattenable T, Flattenable... Args>
    constexpr void
    Flatten(T arg, Args... args)
    {
        if constexpr ( std::is_same_v<T, std::string> )
        {
            std::string s(arg);
            usize sz = std::min(s.size(), m_Size);
            std::memcpy(m_Pointer + m_Cursor, s.c_str(), sz);
            m_Cursor += sz;
        }

        if constexpr ( std::is_same_v<T, std::vector<u8>> )
        {
            std::vector<u8> s(arg);
            usize sz = std::min(s.size(), m_Size);
            std::memcpy(m_Pointer + m_Cursor, s.data(), sz);
            m_Cursor += sz;
        }

        if constexpr ( sizeof...(args) > 0 )
        {
            Flatten(args...);
        }
        else
        {
            m_Cursor = 0;
        }
    }

private:
    u8* m_Pointer {nullptr};
    uptr m_Cursor {0};
    usize m_Size {0};
};

constexpr bool
operator==(const MemoryView& lhs, const MemoryView& rhs) noexcept
{
    if ( !(lhs.size() == rhs.size()) )
    {
        return false;
    }

    return std::memcmp(lhs.data(), rhs.data(), lhs.size());
}

constexpr bool
operator!=(const MemoryView& lhs, const MemoryView& rhs) noexcept
{
    return !(lhs == rhs);
}

constexpr bool
operator<(const MemoryView& lhs, const MemoryView& rhs) noexcept
{
    return std::lexicographical_compare(lhs.begin(), lhs.end(), rhs.begin(), rhs.end());
}

constexpr bool
operator>(const MemoryView& lhs, const MemoryView& rhs) noexcept
{
    return rhs < lhs;
}

constexpr bool
operator<=(const MemoryView& lhs, const MemoryView& rhs) noexcept
{
    return !(rhs < lhs);
}

constexpr bool
operator>=(const MemoryView& lhs, const MemoryView& rhs) noexcept
{
    return !(lhs < rhs);
}


void
swap(MemoryView& x, MemoryView& y) noexcept(noexcept(x.swap(y)));

} // namespace pwn::utils

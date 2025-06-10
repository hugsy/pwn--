module;
#include <iostream>
export module pwn.common;

export using u8  = std::uint8_t;
export using u16 = std::uint16_t;
export using u32 = std::uint32_t;
export using u64 = std::uint64_t;
export using i8  = std::int8_t;
export using i16 = std::int16_t;
export using i32 = std::int32_t;
export using i64 = std::int64_t;
#ifdef _M_IX86
export using usize = unsigned long;
#else
export using usize = std::size_t;
#endif
export using ssize = std::intptr_t;
export using uptr  = std::uintptr_t;

export void
test()
{
    std::cout << "test modules\n";
}

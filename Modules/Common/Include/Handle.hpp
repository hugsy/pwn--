#pragma once

#include <functional>

#include "Common.hpp"

///
/// @brief Scope-managed handles
///
/// @ref https://andreasfertig.blog/2022/08/cpp-insights-lambdas-in-unevaluated-contexts/
///
template<typename T, auto Deleter>
using GenericHandle = std::unique_ptr<
    T,
    decltype(
        [](T* h)
        {
            if ( h )
            {
                Deleter(h);
                h = nullptr;
            }
        })>;

#ifdef __linux__
using UniqueHandle = GenericHandle<FILE, ::fclose>;
#else

///
/// @brief A unique (as-in `unique_ptr`) Windows handle. It will close itself on scope-exit.
///
using UniqueHandle = GenericHandle<void, ::CloseHandle>;

///
/// @brief A unique (as-in `unique_ptr`) Windows module handle.
///
using UniqueLibraryHandle = GenericHandle<HINSTANCE__, ::FreeLibrary>;

///
/// @brief A unique Windows Critical Section.
///
using UniqueCriticalSection = GenericHandle<
    RTL_CRITICAL_SECTION,
    [](RTL_CRITICAL_SECTION* p)
    {
        if ( p )
        {
            ::LeaveCriticalSection(p);
            p = nullptr;
        }
    }>;
#endif // __linux__

using SharedHandle = std::shared_ptr<UniqueHandle>;

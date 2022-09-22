#pragma once

#include <functional>

#include "common.hpp"

///
/// Scope-managed handles
///
/// @ref https://andreasfertig.blog/2022/08/cpp-insights-lambdas-in-unevaluated-contexts/
/// @link https://developercommunity.visualstudio.com/t/c20-internal-compiler-error-for-lambda-in-decltype/1631476
///
namespace pwn
{

template<typename T, auto Deleter>
using GenericHandle = std::unique_ptr<
    T,
    decltype(
        [](T* h)
        {
            Deleter(h);
            h = nullptr;
        })>;

#ifdef __linux__
using UniqueHandle = GenericHandle<int, close>;
#else
using UniqueHandle = GenericHandle<void, ::CloseHandle>;
#endif // __linux__

using SharedHandle = std::shared_ptr<UniqueHandle>;

} // namespace pwn

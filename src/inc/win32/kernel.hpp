#pragma once

#include "common.hpp"


namespace pwn::windows
{
class Kernel
{
    class Shellcode
    {
    public:
        static std::vector<u8>
        StealSystemToken();

        static std::vector<u8>
        DebugBreak();

    private:
    };


    ///
    /// @brief Get a vector of big pool chunks with the specified Tag
    ///
    /// @param Tag DWORD of the big pool tag to search for. If 0, all big pool chunks are returned.
    /// @return Result<std::vector<uptr>> A vector with the big pool kernel address with the specified tag
    ///
    Result<std::vector<uptr>>
    FindBigPoolAddressesFromTag(const u32 Tag);
};

} // namespace pwn::windows

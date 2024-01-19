#include "Pattern.hpp"

#include <vector>

namespace pwn::Shellcode
{

// ssize PatternFind(Utils::MemoryView const& View, , std::vector<u8> const& Needle, std::vector<u8> const& NeedleMask)

ssize
PatternFind(std::vector<u8> const& Bytes, std::vector<u8> const& Needle, std::vector<u8> const& NeedleMask)
{
    if ( Needle.size() > Bytes.size() )
    {
        return -1;
    }

    if ( Needle.size() != NeedleMask.size() )
    {
        return -1;
    }

    ssize i       = 0;
    ssize offset1 = 0;
    ssize offset2 = 0;
    usize match   = 0;

    for ( auto byte : Bytes )
    {
        //
        // Compare the current byte
        //
        if ( (byte & NeedleMask[offset2]) == Needle[offset2] )
        {
            offset2++;
            match++;
        }
        else
        {
            offset1 = i + 1;
            offset2 = 0;
            match   = 0;
        }

        //
        // Exit if found a complete sequence
        //
        if ( match == Needle.size() )
        {
            return offset1;
        }

        i++;
    }

    return -1;
}

ssize
PatternFind(std::vector<u8> const& Bytes, std::vector<u8> const& Needle)
{
    std::vector<u8> NeedleMask;
    NeedleMask.resize(Needle.size());
    std::for_each(
        NeedleMask.begin(),
        NeedleMask.end(),
        [](auto& c)
        {
            c = 0xff;
        });
    return PatternFind(Bytes, Needle, NeedleMask);
}

} // namespace pwn::Shellcode

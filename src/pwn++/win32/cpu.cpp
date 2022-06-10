#include "win32/cpu.hpp"

#include "log.hpp"
using namespace pwn::log;

#include <optional>


auto
pwn::windows::cpu::nb_cores() -> std::optional<u32>
{
    DWORD dwNbMax  = 0x100;
    DWORD dwLen    = dwNbMax * sizeof(SYSTEM_LOGICAL_PROCESSOR_INFORMATION);
    auto proc_info = std::make_unique<SYSTEM_LOGICAL_PROCESSOR_INFORMATION[]>(dwLen);

    if ( ::GetLogicalProcessorInformation(proc_info.get(), &dwLen) == 0 )
    {
        perror(L"GetLogicalProcessorInformation()");
        return {};
    }

    DWORD dwLogicalProcessorCount = 0;
    DWORD dwNbEntries             = dwLen / sizeof(SYSTEM_LOGICAL_PROCESSOR_INFORMATION);
    for ( size_t i = 0; i < dwNbEntries; i++ )
    {
        if ( proc_info[i].Relationship == RelationProcessorCore )
        {
            dwLogicalProcessorCount++;
        }
    }

    return dwLogicalProcessorCount;
}

#include "cpu.h"

#include "log.h"
using namespace pwn::log;


_Success_(return != -1)
PWNAPI auto pwn::cpu::nb_cores() -> DWORD
{
	DWORD dwNbMax = 0x100;
    DWORD dwLen = dwNbMax * sizeof(SYSTEM_LOGICAL_PROCESSOR_INFORMATION);
	auto proc_info = std::make_unique<SYSTEM_LOGICAL_PROCESSOR_INFORMATION[]>(dwLen);

    if (::GetLogicalProcessorInformation(proc_info.get(), &dwLen) == 0)
    {
        perror(L"GetLogicalProcessorInformation()");
		return -1;
    }

    DWORD dwLogicalProcessorCount = 0;
	DWORD dwNbEntries = dwLen / sizeof(SYSTEM_LOGICAL_PROCESSOR_INFORMATION);
	for (size_t i = 0; i < dwNbEntries; i++)
	{
		if (proc_info[i].Relationship == RelationProcessorCore) {
			dwLogicalProcessorCount++;
}
	}
	
    return dwLogicalProcessorCount;
}

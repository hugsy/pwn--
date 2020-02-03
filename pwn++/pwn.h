#pragma once
#include <Windows.h>

#ifndef PWNAPI
#define PWNAPI __declspec(dllexport)
#endif



#ifndef __countof
#define __countof(x) (sizeof(x)/x[0])
#endif 


/*++

Base namespace

--*/
namespace pwn
{
	namespace globals
	{
		HANDLE g_ConsoleMutex;
	}

}


#include "log.h"

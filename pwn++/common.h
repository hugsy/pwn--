#pragma once

#include "framework.h"

#include "constants.h"


#ifndef PWNAPI
#define PWNAPI __declspec(dllexport)
#endif

#ifndef __countof
#define __countof(x) (sizeof(x)/x[0])
#endif 

typedef DWORD64 QWORD;


#include <array>
#include <vector>
#include <string>
#include <memory>


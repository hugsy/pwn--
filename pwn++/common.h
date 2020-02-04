#pragma once

#include "framework.h"

#ifndef PWNAPI
#define PWNAPI __declspec(dllexport)
#endif

#ifndef __countof
#define __countof(x) (sizeof(x)/x[0])
#endif 


#include <array>
#include <vector>
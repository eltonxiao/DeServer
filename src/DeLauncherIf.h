#pragma once
#include <stdint.h>

namespace dengine {
class DecodeEngineIf;
}
using namespace dengine;

class DeLauncherIf
{
public:
	virtual ~DeLauncherIf() {}
	virtual DecodeEngineIf *LaunchDEngine(uint16_t* pport = 0) = 0;
};


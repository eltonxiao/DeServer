#pragma once

class DecodeEngine;

class DeLauncherIf
{
public:
	virtual ~DeLauncherIf() {}
	virtual DecodeEngine *LaunchDEngine(uint16_t *pport = 0) = 0;
};


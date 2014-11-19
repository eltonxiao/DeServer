#pragma once
#include <string>
#include <boost/thread/mutex.hpp>
#include <utility>
#include "ProcessUtility.h"

class DecodeEngine;

class DeLauncher
{
public:
	DeLauncher(uint16_t start,  uint16_t stop);
	~DeLauncher();
	DecodeEngine *LaunchDEngine();

private:
	uint16_t allocPort();
	void commitPort(uint16_t port, phandle handle);
	void freePort(uint16_t port);

	DecodeEngine *connect(uint16_t port);

	std::pair<uint16_t,uint16_t> portRange_;
	std::map<uint16_t,phandle> ppmap_; // port/process map
	boost::mutex mutex_;
	uint16_t lastPort_;
};


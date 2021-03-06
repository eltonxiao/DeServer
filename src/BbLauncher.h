#pragma once
#include <string>
#include <boost/thread/mutex.hpp>
#include <utility>
#include <stdint.h>
#include "ProcessUtility.h"
#include "./gen-cpp/BulletinBoard.h"

using namespace process_utility;
using namespace dengine;

class BbLauncher
{
public:
	BbLauncher(uint16_t start,  uint16_t stop, const char *image, uint16_t worker_start, uint16_t worker_stop);
	~BbLauncher();
	BulletinBoardIf *LaunchBulletin(uint16_t *pport = 0);

private:
	uint16_t allocPort();
	void commitPort(uint16_t port, phandle handle);
	void freePort(uint16_t port);

	static BulletinBoardIf *connect(uint16_t port);
	phandle createProcess(uint16_t port);

	const std::pair<uint16_t,uint16_t> portRange_;
	const std::string image_;
	uint16_t lastPort_;
	const uint16_t worker_start_;
	const uint16_t worker_stop_;
	std::map<uint16_t,phandle> ppmap_; // port/process map
	boost::mutex mutex_;
};


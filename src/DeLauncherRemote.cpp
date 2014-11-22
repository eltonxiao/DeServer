#include "DeLauncherRemote.h"
#include "DeLauncher.h"
#include "./gen-cpp/BulletinBoard.h"
using namespace dengine;

DecodeEngineIf *DeLauncherRemote::LaunchDEngine(uint16_t *pport)
{
	const uint32_t port = bboard_->allocWorker();
	if (!port)
	{
		std::cout << "ERROR: bulletin board fail to allocate one decode engine instance!" << std::endl;
		return 0;
	}

	DecodeEngineIf *instance = DeLauncher::connect(port);	

	if (!instance)
		std::cout << "ERROR: connect to point " << port << " for decode engine instance failed!" << std::endl;
	else if (pport)
		*pport = port;

	return instance;
}


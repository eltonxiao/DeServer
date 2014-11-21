#include "DeLauncherRemote.h"
#include "DeLauncher.h"

DecodeEngine *DeLauncherRemote::LaunchDEngine(uint16_t *pport)
{
	const uint32_t port = bboard_->allocPort();
	if (!port)
	{
		std::cout << "ERROR: bulletin board fail to allocate one decode engine instance!" << std::endl;
		return 0;
	}

	DecodeEngine *instance = connect(port);	

	if (!instance)
		std::cout << "ERROR: connect to point " << port << " for decode engine instance failed!" << std::endl;
	else if (pport)
		*pport = port;

	return instance;
}


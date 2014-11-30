
#include "stdafx.h"
#include <PreScanProtocol.h>
#include <EtherealCallInterface.h>

unsigned short FindCustomedAppIdFromPort(unsigned short portNumber)
{
	return CPreScanProtocol::FindAppPort(portNumber, false);
}

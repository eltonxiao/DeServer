#include "DeLauncher.h"
#include <boost/thread/thread.hpp>
#include <thrift/protocol/TBinaryProtocol.h>
#include <thrift/transport/TSocket.h>
#include <thrift/transport/TTransportUtils.h>

#include "./gen-cpp/DecodeEngine.h"

using namespace std;
using namespace apache::thrift;
using namespace apache::thrift::concurrency;
using namespace apache::thrift::protocol;
using namespace apache::thrift::transport;
using namespace apache::thrift::server;

using namespace dengine;



DeLauncher::DeLauncher()
	:portRange(1980, 2980),
	lastPort_(portRange.second)
{
}

DecodeEngin *DeLauncher::LaunchDEngine()
{
	const uint32_t port = allocPort();
	phandle handle = create_process(port);
	commitPort(port, handle);

	DecodeEngine *instance = 0;

	while (true)
	{
		instance = connect(port);	
		if (instance || !check_alive(handle))
			break;

		boost::thread::yield();	
	}

	if (!instance)
		freePort(port);

	return instance;
}

DecodeEngine *DeLauncher::connect(uint16_t port)
{
	boost::shared_ptr<TTransport> socket(new TSocket("localhost", port));
	boost::shared_ptr<TTransport> transport(new TBufferedTransport(socket));
	boost::shared_ptr<TProtocol> protocol(new TBinaryProtocol(transport));
	DecodeEngineClient *client = new DecodeEngineClient(protocol);

	try
	{
		transport->open();

	} catch (TException& tx) {
		cout << "ERROR: " << tx.what() << endl;
		delete client;
		client = 0;
	}

	return client;
}

uint16_t DeLauncher::allocPort()
{
	const uint16_t backup = lastPort_;
	uint16_t port = 0;
	while (!port)
	{
		if (++lastPort_ > portRange.second)
			lastPort_ = portRange.first;
	
		if (backup == lastPort_)
			break; // no free port

		const phandle handle = ppmap_[lastPort_]; // here, we have inserted one as allocated mark
		if (!handle) 
			port = lastPort_;
		else if (!check_alive(handle))
		{
			ppmap_[lastPort_] = (phandle)0;
			port = lastPort_;
		}
	}

	return port;
}


void DeLauncher::commitPort(uint16_t port, phandle, handle)
{
	ppmap_[port] = handle;
}

void DeLauncher::freePort(uint16_t port)
{
	ppmap_.erase(port);
}

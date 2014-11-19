#include "DeLauncher.h"
#include <algorithm>
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



DeLauncher::DeLauncher(uint16_t start,  uint16_t stop)
	:portRange(std::min(start,stop), std::max(start,stop)),
	lastPort_(portRange.second)
{
}

DecodeEngin *DeLauncher::LaunchDEngine()
{
	const uint32_t port = allocPort();
	const phandle handle = create_process(port);
	if (handle == INVALID_HANDLE)
	{
		cout << "ERROR: create process failed!" << endl;
		freePort(port);
		return 0;
	}
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
	boost::mutex::scoped_lock scoped_lock(mutex_);

	const phandle place_holder = (phandle)-1;
	const uint16_t backup = lastPort_;
	uint16_t port = 0;
	while (true)
	{
		if (++lastPort_ > portRange.second)
			lastPort_ = portRange.first;
	
		const phandle handle = ppmap_[lastPort_];
		if (!handle ||
			(handle != place_holder &&
			 !check_alive(handle)))
		{
			ppmap_[lastPort_] = place_holder;
			port = lastPort_;
		}

		if (port || backup == lastPort_)
			break; 
	}

	return port;
}


void DeLauncher::commitPort(uint16_t port, phandle, handle)
{
	boost::mutex::scoped_lock scoped_lock(mutex_);
	ppmap_[port] = handle;
}

void DeLauncher::freePort(uint16_t port)
{
	boost::mutex::scoped_lock scoped_lock(mutex_);
	ppmap_.erase(port);
}

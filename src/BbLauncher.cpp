#include "BbLauncher.h"
#include <algorithm>
#include <boost/thread/thread.hpp>
#include <thrift/protocol/TBinaryProtocol.h>
#include <thrift/transport/TSocket.h>
#include <thrift/transport/TTransportUtils.h>


using namespace std;
using namespace apache::thrift;
using namespace apache::thrift::concurrency;
using namespace apache::thrift::protocol;
using namespace apache::thrift::transport;
//using namespace apache::thrift::server;


class MyBulletinBoardClient : public BulletinBoardClient
{
public:
	MyBulletinBoardClient(boost::shared_ptr< ::apache::thrift::protocol::TProtocol> prot,
				boost::shared_ptr<TTransport> transport)
		: BulletinBoardClient(prot),
		  transport_(transport) {}

	~MyBulletinBoardClient()
	{
		transport_->close();
	}

private:
	boost::shared_ptr<TTransport> transport_;
};

BbLauncher::BbLauncher(uint16_t start,  uint16_t stop, const char *image, uint16_t worker_start, uint16_t worker_stop)
	:portRange_(std::min(start,stop), std::max(start,stop)),
	image_(image),
	lastPort_(portRange_.second),
	worker_start_(worker_start),
	worker_stop_(worker_stop)
{
}

BbLauncher::~BbLauncher()
{
}

BulletinBoardIf *BbLauncher::LaunchBulletin(uint16_t *pport)
{
	const uint32_t port = allocPort();
	const phandle handle = createProcess(port);
	if (handle == INVALID_HANDLE)
	{
		cout << "ERROR: create process failed!" << endl;
		freePort(port);
		return 0;
	}
	commitPort(port, handle);

	BulletinBoardIf *instance = 0;

	usleep(40 * 1000);
	while (true)
	{
		instance = connect(port);	
		if (instance || !check_alive(handle))
			break;

		boost::thread::yield();	
		
		cout << "INFO: try connect to (" << handle << ": " << port <<") again..." << endl;
	}

	if (!instance)
		freePort(port);
	else if (pport)
		*pport = port;

	return instance;
}

BulletinBoardIf *BbLauncher::connect(uint16_t port)
{
	boost::shared_ptr<TTransport> socket(new TSocket("localhost", port));
	boost::shared_ptr<TTransport> transport(new TBufferedTransport(socket));
	boost::shared_ptr<TProtocol> protocol(new TBinaryProtocol(transport));
	MyBulletinBoardClient *client = new MyBulletinBoardClient(protocol, transport);

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

uint16_t BbLauncher::allocPort()
{
	boost::mutex::scoped_lock scoped_lock(mutex_);

	const phandle place_holder = (phandle)-1;
	const uint16_t backup = lastPort_;
	uint16_t port = 0;
	while (true)
	{
		if (++lastPort_ > portRange_.second)
			lastPort_ = portRange_.first;
	
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

void BbLauncher::commitPort(uint16_t port, phandle handle)
{
	boost::mutex::scoped_lock scoped_lock(mutex_);
	ppmap_[port] = handle;
}

void BbLauncher::freePort(uint16_t port)
{
	boost::mutex::scoped_lock scoped_lock(mutex_);
	ppmap_.erase(port);
}


phandle BbLauncher::createProcess(uint16_t port)
{
	char bufferp[34];
	sprintf(bufferp, "%d", (int)port);

	char bufferw[68];
	sprintf(bufferw, "%d:%d", (int)worker_start_, (int)worker_stop_);
	
#pragma GCC diagnostic ignored "-Wwrite-strings"
	char *argv[] = {(char*)image_.data(), "-t", "slave", "-p", bufferp, "-wp", bufferw, (char *)0};
	
	return create_process(image_.data(), argv);
}


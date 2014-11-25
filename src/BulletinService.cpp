#include "BulletinService.h"
#include <thrift/protocol/TBinaryProtocol.h>
#include <thrift/server/TSimpleServer.h>
#include <thrift/server/TThreadPoolServer.h>
#include <thrift/server/TThreadedServer.h>
#include <thrift/transport/TServerSocket.h>
#include <thrift/transport/TTransportUtils.h>

#include <iostream>
#include <stdexcept>
#include <sstream>
#include <string>

#include "./gen-cpp/BulletinBoard.h"
#include "./gen-cpp/DecodeEngine.h"
#include "CommandLineParser.h"
#include "DeLauncher.h"

using namespace apache::thrift;
using namespace apache::thrift::concurrency;
using namespace apache::thrift::protocol;
using namespace apache::thrift::transport;
using namespace apache::thrift::server;

using namespace dengine;

class BulletinBoardHandler : public BulletinBoardIf {
public:
	BulletinBoardHandler(const boost::shared_ptr<DeLauncherIf> &launcher) : launcher_(launcher) {}
	~BulletinBoardHandler() {}

	int16_t allocWorker() 
	{
		uint16_t port = 0;
		try {
			delete launcher_->LaunchDEngine(&port);
		} catch (...) {
			std::cout << "ERROR: exception in allocWorker !" << std::endl;
		}
		return port;
	}

private:
	boost::shared_ptr<DeLauncherIf> launcher_;
};

int bulletin_service(int argc, char **argv)
{
	CommandLineParser parser;
	if (parser.parse(argc, argv))
		return -1;

	const uint16_t port = parser.get_my_port();
	const uint16_t start = parser.get_worker_port_start();
	const uint16_t stop = parser.get_worker_port_stop();

	
	std::cout << "INFO: bulletin board will serve on port:" << port << std::endl;
	std::cout << "INFO: decode engine instance port range [" << start << ", " << stop << "]" << std::endl;

	boost::shared_ptr<DeLauncherIf> launcher(new DeLauncher(start, stop, argv[0]));

	boost::shared_ptr<TProtocolFactory> protocolFactory(new TBinaryProtocolFactory());
	boost::shared_ptr<BulletinBoardHandler> handler(new BulletinBoardHandler(launcher));
	boost::shared_ptr<TProcessor> processor(new BulletinBoardProcessor(handler));
	boost::shared_ptr<TServerTransport> serverTransport(new TServerSocket(port));
	boost::shared_ptr<TTransportFactory> transportFactory(new TBufferedTransportFactory());
	TSimpleServer server(processor,
		       serverTransport,
		       transportFactory,
		       protocolFactory);

	std::cout << "INFO: Starting bulltein board..." << std::endl;
	server.serve();
	std::cout << "INFO: Bulletin board done." << std::endl;
	return 0;
}


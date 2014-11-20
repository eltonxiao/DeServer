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
	BulletinBoardHandler(boost::shared_ptr<DeLauncher> launcher) : launcher_(launcher) {}
	~BulletinBoardIf() {}

	int16_t allocWorker() 
	{
		return launcher->allocWorker();
	}

private:
	boost::shared_ptr<DeLauncher> launcher_;
};

int bulletin_service(int argc, char **argv)
{
	uint16_t port;
	ServerType_t type;
	if (parseCommandLine(argc, argv, type, port))
		return -1;
	
	std::cout << "INFO: bulletin board serve on port:" << port << std::endl;

	boost::shared_ptr<TProtocolFactory> protocolFactory(new TBinaryProtocolFactory());
	boost::shared_ptr<BulletinBoardHandler> handler(new BulletinBoardHandler());
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


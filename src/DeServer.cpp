#include <thrift/concurrency/ThreadManager.h>
#include <thrift/concurrency/PosixThreadFactory.h>
#include <thrift/protocol/TBinaryProtocol.h>
#include <thrift/server/TSimpleServer.h>
#include <thrift/server/TThreadPoolServer.h>
#include <thrift/server/TThreadedServer.h>
#include <thrift/transport/TServerSocket.h>
#include <thrift/transport/TTransportUtils.h>
//#include <thrift/TToString.h>

#include <iostream>
#include <stdexcept>
#include <sstream>
#include <string>

#include "./gen-cpp/DecodeEngine.h"

using namespace apache::thrift;
using namespace apache::thrift::concurrency;
using namespace apache::thrift::protocol;
using namespace apache::thrift::transport;
using namespace apache::thrift::server;

using namespace dengine;

class DecodeEngineProxyHandler : public DecodeEngineIf {
 public:
  DecodeEngineProxyHandler() {}

  void ping() {
    std::cout << "ping()" << std::endl;
  }

  int32_t add(const int32_t n1, const int32_t n2) {
    std::cout << "add(" << n1 << ", " << n2 << ")" << std::endl;
    return n1 + n2;
  }

};

int master_service(int argc, char **argv)
{
	uint16_t port, start, stop;
	ServerType_t type;
	if (parseCommandLine(argc, argv, type, port))
		return -1;
	
	std::cout << "INFO: decode engine master will serve on port:" << port << std::endl;

	boost::shared_ptr<BbLauncher> launcher 

	boost::shared_ptr<TProtocolFactory> protocolFactory(new TBinaryProtocolFactory());
	boost::shared_ptr<DecodeEngineProxyHandler> handler(new DecodeEngineProxyHandler());
	boost::shared_ptr<TProcessor> processor(new DecodeEngineProcessor(handler));
	boost::shared_ptr<TServerTransport> serverTransport(new TServerSocket(port));
	boost::shared_ptr<TTransportFactory> transportFactory(new TBufferedTransportFactory());
/*
  TSimpleServer server(processor,
                       serverTransport,
                       transportFactory,
                       protocolFactory);

*/
  
	const int workerCount = 4;

	boost::shared_ptr<ThreadManager> threadManager = ThreadManager::newSimpleThreadManager(workerCount);
	boost::shared_ptr<PosixThreadFactory> threadFactory = boost::shared_ptr<PosixThreadFactory>(new PosixThreadFactory());
	threadManager->threadFactory(threadFactory);
	threadManager->start();
	TThreadPoolServer server(processor, serverTransport, transportFactory, protocolFactory, threadManager);
/*
  TThreadedServer server(processor,
                         serverTransport,
                         transportFactory,
                         protocolFactory);

*/

	cout << "INFO: Starting the server..." << endl;
	server.serve();
	cout << "INFO: Done." << endl;

}

int main(int argc, char **argv)
{
	uint16_t port, start, stop;
	ServerType_t type;
	if (parseCommandLine(argc, argv, type, port))
		return -1;
	
	switch (type)
	{
	case ST_SLAVE:
		return bulletin_service(argc, argv);
	case ST_WORKER:
		return worker_service(argc, argv);
	default
		return master_service(argc, argv);
	}
}


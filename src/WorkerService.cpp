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

#include "./gen-cpp/DecodeEngine.h"
#include "CommandLineParser.h"
#include "DeLauncher.h"

using namespace apache::thrift;
using namespace apache::thrift::concurrency;
using namespace apache::thrift::protocol;
using namespace apache::thrift::transport;
using namespace apache::thrift::server;

using namespace dengine;

class DecodeEngineHandler : public DecodeEngineIf {
 public:
  DecodeEngineHandler() {}

  void ping() {
    std::cout << "ping()" << std::endl;
  }

  int32_t add(const int32_t n1, const int32_t n2) {
    std::cout << "add(" << n1 << ", " << n2 << ")" << std::endl;
    return n1 + n2;
  }

};


int worker_service(int argc, char **argv)
{
	uint16_t port;
	ServerType_t type;
	if (parseCommandLine(argc, argv, type, port))
		return -1;
	
	std::cout << "INFO: decode engine will serve on port:" << port << std::endl;


	boost::shared_ptr<TProtocolFactory> protocolFactory(new TBinaryProtocolFactory());
	boost::shared_ptr<DecodeEngineHandler> handler(new DecodeEngineHandler());
	boost::shared_ptr<TProcessor> processor(new DecodeEngineProcessor(handler));
	boost::shared_ptr<TServerTransport> serverTransport(new TServerSocket(port));
	boost::shared_ptr<TTransportFactory> transportFactory(new TBufferedTransportFactory());
	TSimpleServer server(processor,
		       serverTransport,
		       transportFactory,
		       protocolFactory);

	std::cout << "INFO: Starting decode engine..." << std::endl;
	server.serve();
	std::cout << "INFO: Decode engine done." << std::endl;
	return 0;
}


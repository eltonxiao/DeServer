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

	handle_t ctor() throw(DException)
	{
		std::cout << "DBG: worker's ctor, here we can intialize wireshark lib" << std::endl;
		return 0;	
	}
 
	void dtor(const handle_t)
	{
		std::cout << "DBG: worker's dtor" << std::endl;
	}

	void sample_decode_function_echo(std::string& _return, const handle_t, const std::string& msg) 
	{

		std::cout << "DBG: sample_decode_function_echo in worker. entry point for call to wireshark lib" << std::endl;
		std::cout << "DBG: msg from client is: " << msg << std::endl;

		_return = "This is echo msg from server, your message is:";
		_return += msg;
	}

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
	CommandLineParser parser;
	if (parser.parse(argc, argv))
		return -1;
	
	const uint16_t port = parser.get_my_port();

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


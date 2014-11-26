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
#include <time.h>

#include "./gen-cpp/DecodeEngine.h"
#include "DeLauncherIf.h"
#include "CommandLineParser.h"
#include "BbLauncher.h"
#include "DeLauncherRemote.h"
#include "BulletinService.h"
#include "WorkerService.h"

using namespace apache::thrift;
using namespace apache::thrift::concurrency;
using namespace apache::thrift::protocol;
using namespace apache::thrift::transport;
using namespace apache::thrift::server;

using namespace dengine;

class DecodeEngineProxyHandler : public DecodeEngineIf {
public:
	DecodeEngineProxyHandler(const boost::shared_ptr<DeLauncherIf> &launcher) : launcher_(launcher)
	{
		const int port_count = 0x10000;
		handlers_ = new HandleEntry[port_count];
		memset(handlers_, 0, port_count * sizeof(HandleEntry));
	}

	~DecodeEngineProxyHandler()
	{
		delete[] handlers_;
	}

	handle_t ctor() throw(DException)
	{
		uint16_t port = 0;
		DecodeEngineIf *engine = launcher_->LaunchDEngine(&port);
		if (!engine)
			throw DException();

		
		handlers_[port].handle = make_handle(port);
		handlers_[port].handler = engine;
		
		return handlers_[port].handle;
	}
 
	void dtor(const handle_t myself)
	{
		if (!get_handler(myself))
			throw DException();

		const uint16_t port = extrac_port(myself);
		delete handlers_[port].handler;
		handlers_[port].handler = 0;
		handlers_[port].handle = 0;
	}

	void sample_decode_function_echo(std::string& _return, const handle_t myself, const std::string& msg) 
	{
		if (!get_handler(myself))
			throw DException();


		std::cout << "DBG: sample_decode_function_echo in proxy" << std::endl;


		get_handler(myself)->sample_decode_function_echo(_return, myself, msg); 
	}

  void ping() {
    std::cout << "ping()" << std::endl;
  }

  int32_t add(const int32_t n1, const int32_t n2) {
    std::cout << "add(" << n1 << ", " << n2 << ")" << std::endl;
    return n1 + n2;
  }

private:
	static inline handle_t make_handle(uint16_t port)
	{
		time_t timer;
		time(&timer);
		return (handle_t)timer << 16 | port;	
	}
	
	static inline uint16_t extrac_port(handle_t handle)
	{
		return handle;
	}

	inline DecodeEngineIf *get_handler(handle_t handle)
	{
		const uint16_t port = extrac_port(handle);
		if (handlers_[port].handle == handle)
			return handlers_[port].handler;
		else
			return 0;
	}

	struct HandleEntry {
		DecodeEngineIf *handler;
		handle_t handle; 
	};


	boost::shared_ptr<DeLauncherIf> launcher_;
	HandleEntry *handlers_; // don't worry about false share, since most of time is read operation.
};

int master_service(int argc, char **argv)
{
	CommandLineParser parser;
	if (parser.parse(argc, argv))
		return -1;

	const uint16_t port = parser.get_my_port();
	
	const int count = kill_process(argv[0]);
	if (count > 0)
		std::cout << "INFO: total clean up " << count << " process." << std::endl;

	std::cout << "INFO: decode engine master will serve on port:" << port << std::endl;

	boost::shared_ptr<BbLauncher> bblauncher(new BbLauncher(parser.get_slave_port_start(),
								parser.get_slave_port_stop(),
								argv[0],
								parser.get_worker_port_start(),
								parser.get_worker_port_stop()));

	boost::shared_ptr<BulletinBoardIf> bbif(bblauncher->LaunchBulletin());
	if (!bbif.get())
	{
		std::cout << "ERROR: fail to launch bulletin board" << std::endl;
		return -1;
	}

	boost::shared_ptr<DeLauncherIf> delauncher(new DeLauncherRemote(bbif));
	

	boost::shared_ptr<TProtocolFactory> protocolFactory(new TBinaryProtocolFactory());
	boost::shared_ptr<DecodeEngineProxyHandler> handler(new DecodeEngineProxyHandler(delauncher));
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

	std::cout << "INFO: Starting the master server..." << std::endl;
	try
	{
		server.serve();
	} catch (TException& tx) {
		std::cout << "ERROR: " << tx.what() << std::endl;
	}

	std::cout << "INFO: Done." << std::endl;

	return 0;
}

int main(int argc, char **argv)
{
	CommandLineParser parser;
	if (parser.parse(argc, argv))
		return -1;
	
	switch (parser.get_type())
	{
	case ST_SLAVE:
		return bulletin_service(argc, argv);
	case ST_WORKER:
		return worker_service(argc, argv);
	default:
		return master_service(argc, argv);
	}
}


#include <stdint.h>
#include <thrift/protocol/TBinaryProtocol.h>
#include <thrift/transport/TSocket.h>
#include <thrift/transport/TTransportUtils.h>
#include <boost/shared_ptr.hpp>
#include <iostream>
#include "./gen-cpp/DecodeEngine.h"


using namespace std;
using namespace apache::thrift;
using namespace apache::thrift::concurrency;
using namespace apache::thrift::protocol;
using namespace apache::thrift::transport;


using namespace dengine;

class MyDecodeEngineClient : public DecodeEngineClient
{
public:
	MyDecodeEngineClient(const boost::shared_ptr< ::apache::thrift::protocol::TProtocol>& prot,
				const boost::shared_ptr<TTransport>& transport)
		: DecodeEngineClient(prot),
		  transport_(transport) {}

	~MyDecodeEngineClient()
	{
		transport_->close();
	}

private:
	boost::shared_ptr<TTransport> transport_;
};

DecodeEngineIf *connect(uint16_t port, const char *host = "localhost")
{
	boost::shared_ptr<TTransport> socket(new TSocket(host, port));
	boost::shared_ptr<TTransport> transport(new TBufferedTransport(socket));
	boost::shared_ptr<TProtocol> protocol(new TBinaryProtocol(transport));
	MyDecodeEngineClient *client = new MyDecodeEngineClient(protocol, transport);

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
int main(int argc, char **argv)
{	
	uint16_t port = 10000;

	if (argc > 1) 
		port = atoi(argv[1]);


	std::cout << "INFO: connect to port " << port << " ..." << std::endl;

	boost::shared_ptr<DecodeEngineIf> instance(connect(port)); 

	if (!instance.get())
	{
		std::cout << "ERROR: connect to port " << port << " for decode engine instance failed!" << std::endl;
		return -1;
	}

	std::cout << "INFO: connected" << std::endl;
	std::cout << "INFO: try making call" << std::endl;

	int sum = instance->add(5, 6);

	std::cout << "INFO: call result " << sum  << std::endl;

	return 0;
}



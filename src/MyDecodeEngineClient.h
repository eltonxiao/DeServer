#pragma once
#include <stdint.h>
#include <string>
#include <thrift/protocol/TBinaryProtocol.h>
#include <thrift/transport/TSocket.h>
#include <thrift/transport/TTransportUtils.h>
#include <boost/shared_ptr.hpp>
#include "./gen-cpp/DecodeEngine.h"


using namespace apache::thrift;
using namespace apache::thrift::concurrency;
using namespace apache::thrift::protocol;
using namespace apache::thrift::transport;


using namespace dengine;


class MyDecodeEngineClient
{
public:
	MyDecodeEngineClient();
	~MyDecodeEngineClient();

	void connect(uint16_t port, const char *host = "localhost") throw(TException);
	void disconnect() throw(TException);

	std::string sample_decode_function_echo(const std::string& msg);
private:
	boost::shared_ptr<TTransport> transport_;
	boost::shared_ptr<DecodeEngineClient> clientImp_;

	handle_t handle_;
};


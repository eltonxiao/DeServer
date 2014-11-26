#include "MyDecodeEngineClient.h"

MyDecodeEngineClient::MyDecodeEngineClient() : handle_(0)
{
}

MyDecodeEngineClient::~MyDecodeEngineClient()
{
	disconnect();
}

void MyDecodeEngineClient::connect(uint16_t port, const char *host) throw(TException)
{
	boost::shared_ptr<TTransport> socket(new TSocket(host, port));
	transport_.reset(new TBufferedTransport(socket));
	boost::shared_ptr<TProtocol> protocol(new TBinaryProtocol(transport_));
	clientImp_.reset(new DecodeEngineClient(protocol));

	transport_->open();
	handle_ = clientImp_->ctor();
}

void MyDecodeEngineClient::disconnect() throw(TException)
{
	if (!transport_.get())
		return;

	clientImp_->dtor(handle_);
	handle_ = 0;
	transport_->close();
	transport_.reset();
	clientImp_.reset();
}


std::string MyDecodeEngineClient::sample_decode_function_echo(const std::string& msg)
{
	std::string _return;
	clientImp_->sample_decode_function_echo(_return, handle_, msg);
	return _return;
}


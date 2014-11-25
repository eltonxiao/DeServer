#pragma once
#include <stdint.h>

typedef enum
{
	ST_MASTER,
	ST_SLAVE,
	ST_WORKER
} ServerType_t;

class CommandLineParser
{
public:
	CommandLineParser();
	~CommandLineParser();

	int parse(int argc, char **argv);

	ServerType_t get_type() { return type_; }
	uint16_t get_my_port() { return get_master_port(); }
	uint16_t get_master_port() { return master_port_; }
	uint16_t get_slave_port_start() { return slave_port_start_; }
	uint16_t get_slave_port_stop() { return slave_port_stop_; }
	uint16_t get_worker_port_start() { return worker_port_start_; }
	uint16_t get_worker_port_stop() { return worker_port_stop_; }

private:
	ServerType_t type_;
	uint16_t master_port_;
	uint16_t slave_port_start_;
	uint16_t slave_port_stop_;
	uint16_t worker_port_start_;
	uint16_t worker_port_stop_; 

};


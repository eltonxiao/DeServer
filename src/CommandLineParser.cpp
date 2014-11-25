#include "CommandLineParser.h"
#include <string.h>
#include <stdlib.h>
#include <iostream>
#include <algorithm>


CommandLineParser::CommandLineParser()
{
}

CommandLineParser::~CommandLineParser()
{
}

static inline int extract_port_range(const char *str, uint16_t &start, uint16_t &stop)
{
	char bak[255];
	strncpy(bak, str, sizeof(bak));

	char *pch = strtok(bak, ",.:-");
	const uint16_t _start = pch ? atoi(pch): 0;

	pch = strtok(0, ",.:-");
	const uint16_t _stop = pch ? atoi(pch): 0;

	start = std::min(_start, _stop);
	stop = std::max(_start, _stop);
	return 0;
}

int CommandLineParser::parse(int argc, char **argv)
{
	type_ = ST_MASTER;
	master_port_ = 1980;
	slave_port_start_ = 1981;
	slave_port_stop_ = 2000;
	worker_port_start_ = 2001;
	worker_port_stop_ = 10000; 

	int arg = 1;
	while (arg < argc)
	{
		if (!strcmp(argv[arg], "-p") && arg+1 < argc)
		{
			++arg;
			master_port_ = atoi(argv[arg]);
		}
		else if (!strcmp(argv[arg], "-t") && arg+1 < argc)
		{
			++arg;
			if (!strcmp(argv[arg], "master"))
				type_ = ST_MASTER;
			else if (!strcmp(argv[arg], "slave"))
				type_ = ST_SLAVE;
			else if (!strcmp(argv[arg], "worker"))
				type_ = ST_WORKER;
			else
				std::cout << "WARNING: unknown server type: " << argv[arg] << ". treat it as master." << std::endl;
		}
		else if (!strcmp(argv[arg], "-sp") && arg+1 < argc)
		{
			++arg;
			extract_port_range(argv[arg], slave_port_start_, slave_port_stop_);
		}
		else if (!strcmp(argv[arg], "-wp") && arg+1 < argc)
		{
			++arg;
			extract_port_range(argv[arg], worker_port_start_, worker_port_stop_);
			
		}
		else if (!strcmp(argv[arg], "-h") || !strcmp(argv[arg], "--help"))
		{
			std::cout << "command line example:" << std::endl;
			std::cout << argv[0] << " -t master -p 1980 -sp 1981:2000 -wp 2001:3001" << std::endl;
//			std::cout << "-t server type: master | slave | worker" << std::endl; 
			std::cout << "-p master socket port " << std::endl;
			std::cout << "-sp bulletin socket port range" << std::endl;
			std::cout << "-wp worker socket port range" << std::endl;
			exit(0);
		}
		else
		{
			std::cout << "WARNING: unrecognized command line option: " << argv[arg] << ". overlook it." << std::endl;
		}

		++arg;
	}

	return 0;

}



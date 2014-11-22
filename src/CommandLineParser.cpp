#include "CommandLineParser.h"
#include <string.h>
#include <stdlib.h>
#include <iostream>

int parseCommandLine(int argc, char **argv, ServerType_t &type, uint16_t &port)
{
	type = ST_MASTER;
	port = 0;

	int arg = 1;
	while (arg < argc)
	{
		if (!strcmp(argv[arg], "-p") && arg+1 < argc)
		{
			++arg;
			port = atoi(argv[arg]);
		}
		else if (!strcmp(argv[arg], "-t") && arg+1 < argc)
		{
			++arg;
			if (!strcmp(argv[arg], "master"))
				type = ST_MASTER;
			else if (!strcmp(argv[arg], "slave"))
				type = ST_SLAVE;
			else if (!strcmp(argv[arg], "worker"))
				type = ST_WORKER;
			else
				std::cout << "WARNING: unknown server type: " << argv[arg] << ". treat it as master." << std::endl;
		}
		else if (!strcmp(argv[arg], "-h") || !strcmp(argv[arg], "--help"))
		{
			std::cout << "command line example:" << std::endl;
			std::cout << argv[0] << " -p 1980 -t master" << std::endl;
			std::cout << "-p socket port number" << std::endl;
			std::cout << "-t server type: master | slave | worker" << std::endl; 
			exit(0);
		}
		else
		{
			std::cout << "WARNING: unrecognized command line option: " << argv[arg] << ". overlook it." << std::endl;
		}

		++arg;
	}

	
	if (!port)
	{
		std::cout << "ERROR: port is not valid: " << port << "." << std::endl;
		return -1;
	}

	return 0;
}


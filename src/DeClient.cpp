#include <stdint.h>
#include <iostream>
#include "MyDecodeEngineClient.h"


int main(int argc, char **argv)
{	
	uint16_t port = 1980;

	if (argc > 1) 
		port = atoi(argv[1]);


	std::cout << "INFO: connect to port " << port << " ..." << std::endl;

	MyDecodeEngineClient instance;
	instance.connect(port);


	std::cout << "INFO: connected" << std::endl;
	std::cout << "INFO: try making call" << std::endl;

	std::string msg("Hello server!");

	std::cout << "INFO: call result: " << instance.sample_decode_function_echo(msg)<< std::endl;

	return 0;
}



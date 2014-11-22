#pragma once
#include <stdint.h>

typedef enum
{
	ST_MASTER,
	ST_SLAVE,
	ST_WORKER
} ServerType_t;

int parseCommandLine(int argc, char **argv, ServerType_t &type, uint16_t &port);


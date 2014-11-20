#pragma once

namespace process_utility
{

#include <unistd.h>
typedef pid_t phandle;
#define INVALID_HANDLE ((phandle)-1)

phandle create_process(uint16_t port);
int kill_process(phandle p);
int wait_process(phandle p);
bool check_alive(phandle p);

};


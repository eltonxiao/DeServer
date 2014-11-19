#pragma once

namespace process_utility
{

#include <unistd.h>
typedef pid_t phandle;

phandle create_process(short port);
int kill_process(phandle p);
int wait_process(phandle p);
bool check_alive(phandle p);

};


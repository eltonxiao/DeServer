#pragma once
#include <stdint.h>
#include <unistd.h>

namespace process_utility
{

typedef pid_t phandle;
#define INVALID_HANDLE ((phandle)-1)

phandle create_process(const char *path, char *const argv[]);
int kill_process(phandle p);
int kill_process(const char *name);
int wait_process(phandle p);
bool check_alive(phandle p);

}


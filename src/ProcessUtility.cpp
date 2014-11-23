#include "ProcessUtility.h"
//#include <sys/types.h>
#include <unistd.h>
#include <spawn.h>
#include <errno.h>
#include <iostream>
#include <assert.h>
#include <string.h>
#include <sys/wait.h>
#include <signal.h>

namespace process_utility
{

phandle create_process(const char *path, char *const argv[])
{
	pid_t pid;
	int status;
	posix_spawnattr_t attr;
	posix_spawn_file_actions_t fact;
	posix_spawnattr_init(&attr);
	posix_spawn_file_actions_init(&fact);
	status = posix_spawn(&pid, path, &fact,&attr, argv, environ);
	if (status == 0)
	{
		return (phandle)pid;
	}
	else
	{
		std::cout << "ERROR: failed to spawn child process: " << strerror(status) << std::endl;
		return INVALID_HANDLE;
	}
}

int kill_process(phandle)
{
	assert(0); //TODO
	return 0;
}

int wait_process(phandle)
{
	assert(0); //TODO
	return 0;
}

bool check_alive(phandle p)
{
	int Stat;
        const pid_t wpid = waitpid(p, &Stat, WNOHANG); // avoid zombie
 
std::cout << "DBG: check alive: waitpid: wpid =" << wpid << "Stat" << Stat << std::endl;
std::cout << "DBG: check alive: waitpid: WIFEXITED(Stat) " << WIFEXITED(Stat) << std::endl;
std::cout << "DBG: check alive: waitpid: WIFSIGNALED(Stat) " << WIFSIGNALED(Stat) << std::endl;
std::cout << "DBG: check alive: waitpid: kill " << kill(p, 0) << std::endl;

	return !kill(p, 0);
}

}


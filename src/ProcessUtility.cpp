#include "ProcessUtility.h"
//#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <iostream>
#include <assert.h>
#include "ChildService.h"


phandle create_process(uint16_t port)
{
	pid_t p = fork();
	if (p == 0)
	{
		int status = child_service(port);
		exit(status);
	}
	else if (p < 0)
	{
		cout << "ERROR: failed to fork! errno = " << errno << endl;
		return INVALID_HANDLE;
	}
	else
	{
		return p;
	}
}

phandle create_process(const char *path, char *const argv[])
{
	pid_t pid;
	int status;
	posix_spawnattr_t attr;
	posix_spawn_file_actions_t fact;
	posix_spawnattr_init(&attr);
	posix_spawn_file_actions_init(&fact);
	posix_spawn(&pid, path, &fact,&attr, args, environ);
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

int kill_process(phandle p)
{
	return 0;
}

int wait_process(phandle p)
{
	return 0;
}

bool check_alive(phandle p)
{
	int Stat;
        const pid_t wpid = waitpid(p, &Stat, WNOHANG);
 
	if (wpid == -1 ||
	    WIFEXITED(Stat) ||
	    WIFSIGNALED(Stat))
		return false;

	return true;
}


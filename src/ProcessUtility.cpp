#include "ProcessUtility.h"
//#include <sys/types.h>
#include <unistd.h>
#include <spawn.h>
#include <errno.h>
#include <iostream>
#include <assert.h>
#include <string.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>

namespace process_utility
{

phandle create_process(const char *path, char *const argv[])
{
	signal(SIGCHLD, SIG_IGN); //ignore child fate, don't let it become zombie

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

static int read_cmdline(char *const dst, unsigned sz, unsigned pid){
    char name[32];
    int fd;
    unsigned n = 0;
    dst[0] = '\0';
    snprintf(name, sizeof name, "/proc/%u/cmdline", pid);
    fd = open(name, O_RDONLY);
    if(fd==-1) return 0;
    for(;;){
        ssize_t r = read(fd,dst+n,sz-n);
        if(r==-1){
            if(errno==EINTR) continue;
            break;
        }
        n += r;
        if(n==sz) break; // filled the buffer
        if(r==0) break;  // EOF
    }
    close(fd);
    if(n){
        int i;
        if(n==sz) n--;
        dst[n] = '\0';
        i=n;
        while(i--){
            int c = dst[i];
            if(c<' ' || c>'~') dst[i]=' ';
        }
    }
    return n;
}

int kill_process(const char *name)
{
	DIR *dp;
	struct dirent *ent;
	dp = opendir("/proc");
	if (!dp)
	{
		std::cout << "ERROR: opendir failed! " << strerror(errno) << std::endl;
		return -1;
	}

	int count = 0;

	const pid_t myself = getpid();
	for (;;) 
	{
		ent = readdir(dp);
		if(!ent || !ent->d_name) return 0;
		if((*ent->d_name > '0') && (*ent->d_name <= '9') )
		{
			char cmd[255];
			const pid_t pid = strtoul(ent->d_name, NULL, 10);	
			if (pid != myself && read_cmdline(cmd, sizeof(cmd), pid))
			{
				char cmdbk[255];
				strcpy(cmdbk, cmd);
				char *p = strstr(cmd, " ");
				if (p) *p = '\0';
				if (!strcmp(basename(cmd), basename(name)))
				{
					std::cout << "INFO: kill process " << pid << " command line:" << cmdbk << std::endl; 
					count++;
					kill(pid, SIGKILL);
				}
			}
		}
	}

	closedir(dp);
	return count;
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
 
	(void)wpid;
//std::cout << "DBG: check alive: waitpid: wpid =" << wpid << "Stat " << Stat << std::endl;
//std::cout << "DBG: check alive: waitpid: WIFEXITED(Stat) " << WIFEXITED(Stat) << std::endl;
//std::cout << "DBG: check alive: waitpid: WIFSIGNALED(Stat) " << WIFSIGNALED(Stat) << std::endl;
//std::cout << "DBG: check alive: waitpid: kill " << kill(p, 0) << std::endl;

	return !kill(p, 0);
}

}


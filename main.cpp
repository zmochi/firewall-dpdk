#include "ruletable.h"

#include <unistd.h>

/* shared memory: */
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "firewall.h"

#define RULETABLE_SHM_MODE 600

int main(void) {
	//int ruletable_fd = shm_open(RULETABLE_SHM_KEY, O_RDWR, RULETABLE_SHM_MODE);
	//struct ruletable* ruletable = mmap(NULL, RULETABLE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, ruletable_fd, 0);
	
	struct ruletable* ruletable = mmap(NULL, RULETABLE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	init_ruletable(ruletable);


	int logger_pid = fork();
	if(logger_pid == 0) {
		int log_pipe[2];
		if(pipe(log_pipe) < 0){
			ERROR("Couldn't create logging pipe");
		}

		int log_write_fd = log_pipe[1], log_read_fd = log_pipe[0];

		int fw_pid = fork();
		if(fw_pid == 0) {
			/* firewall process */
			close(log_read_fd);
			start_firewall(0, NULL, ruletable, log_write_fd);
		} else if (fw_pid < 0) {
			/* error in fork */
		}
		
		close(log_write_fd);
		start_logger();
	} else if (logger_pid < 0) {
		/* err on fork */
	}

	start_ruletable();
}

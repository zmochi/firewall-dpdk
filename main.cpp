#include "firewall.hpp"
#include "logger.hpp"
#include "ruletable.hpp"
#include "utils.h"

#include <new>
#include <unistd.h>

/* shared memory: */
#include <fcntl.h>
#include <mqueue.h>
#include <sys/mman.h>
#include <sys/stat.h>

int main(void) {
  ruletable *ruletable =
      new (mmap(NULL, RULETABLE_SIZE, PROT_READ | PROT_WRITE,
                MAP_SHARED | MAP_ANONYMOUS, -1, 0)) struct ruletable;

  int logger_pid = fork();
  if (logger_pid == 0) {
#define MAX_MQ_MSGS (1 << 14)
    mq_attr mqueue_attributes = {.mq_maxmsg = MAX_MQ_MSGS,
                                 .mq_msgsize = sizeof(log_row_t)};
    mqd_t mqueue = mq_open("/log_mqueue", O_CREAT | O_RDWR | O_EXCL, 600,
                           &mqueue_attributes);
	if(mqueue == -1) {
		ERROR("Error creating POSIX message queue");
	}

    int fw_pid = fork();
    if (fw_pid == 0) {
      /* third process, firewall process */
      start_firewall(0, NULL, ruletable, int_net_mac, ext_net_mac, mqueue);
    } else if (fw_pid < 0) {
      /* error in fork */
    }

	log_list logger = log_list(mqueue);

	/* second process handles logs */
    logger.start_logger();
  } else if (logger_pid < 0) {
    /* err on fork */
  }

  /* main process handles ruletable */
  /* create named Unix socket, backed by file somewhere in the file system to handle show_rules, load_rules and so on */
  start_ruletable();
}

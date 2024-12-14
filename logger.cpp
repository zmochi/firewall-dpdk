#include "packet.h"
#include <stdlib.h>
#include "logger.h"
#include "hash_set.h"

#define LOGS_PER_NODE 64

struct log_list {
	struct hash_set* storage;
	struct log_list* next;
};

int alloc_log(struct log_list* log_list) {
	log_list->storage = calloc(1, sizeof(*log_list->storage));
	if(log_list->storage == NULL)
		return -1;

	init_hashset(log_list->storage, sizeof(log_row_t), LOGS_PER_NODE);
	log_list->next = NULL;

	return 0;
}

int store_log(struct log_list* log, log_row_t log_row) {
	hash_log_row_t row_hash = hash_log_row(log_row, LOGS_PER_NODE);
	log->node[row_hash] = log_row;
}

int start_logger(int log_read_fd) {
	struct log_list log;
	int err = alloc_log(&log);
	if(err<0) {
		return -1;
	}

	log_row_t pkt_log;

	while(1) {
		/* this call blocks if there's nothing to read */
		pkt_log = read_log(log_read_fd);
		store_log(&log, pkt_log);
	}
}

int write_log(struct pkt_props pkt, pkt_dc action, reason_t reason, int log_write_fd) {
}

log_row_t read_log(int log_read_fd) {
}

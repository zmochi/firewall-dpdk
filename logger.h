#ifndef __LOGGER_H
#define __LOGGER_H

#include "endian.h"
#include "packet.h"
#include <time.h>

typedef uint64_t count_t;

typedef enum {
	REASON_XMAS_PKT,
	REASON_NO_RULE,
	REASON_RULE,
} reason_t;

typedef struct {
	time_t timestamp; 
	proto protocol;
	pkt_dc action;
	be32_t saddr;
	be32_t daddr;
	be16_t sport;
	be16_t dport;
	reason_t reason;
	count_t count;
} log_row_t;

struct log_list;

int start_logger(int log_read_fd);

int write_log(struct pkt_props pkt, pkt_dc action, reason_t reason, int log_write_fd);

log_row_t read_log(int log_read_fd);

#endif /* __LOGGER_H */

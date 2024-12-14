#ifndef __RULETABLE_H
#define __RULETABLE_H

#include <stdint.h>
#include <stddef.h>
#include "packet.h"
#include "endian.h"

#define MAX_NB_RULES 500
#define RULETABLE_SIZE 1024
#define RULETABLE_SHM_KEY "/ruletable"

typedef uint64_t table_entry;

typedef enum {
	MATCH,
	NO_MATCH,
} rule_match;

typedef rule_match(* cmp_rule_fn)(table_entry pkt_prop, table_entry rule_prop);

/* number of fields in `struct rule` */
#define NB_RULE_FIELDS 8
struct rule {
	union {
		table_entry direction_entry;
		direction direction;
	};
	union {
		table_entry saddr_entry;
		be32_t saddr;
	};
	union {
		table_entry daddr_entry;
		be32_t daddr;
	};
	union {
		table_entry proto_entry;
		be16_t proto;
	};
	union {
		table_entry sport_entry;
		be16_t sport;
	};
	union {
		table_entry dport_entry;
		be16_t dport;
	};
	union {
		table_entry ack_entry;
		uint64_t ack;
	};
	union {
		table_entry action_entry;
		pkt_dc action;
	};
};

#define RULE_NAME_MAXLEN 20

struct rule_entry {
	char name[RULE_NAME_MAXLEN];
	/* union for accessing fields by name and by index, to enable iterating over table columns by index AND by name */
	union {
		struct rule field;
		table_entry rule[NB_RULE_FIELDS];
	};
};

struct ruletable {
	struct rule_entry rule_entry[MAX_NB_RULES];
	size_t nb_rules;
};

int init_ruletable(struct ruletable*);

int add_rule(struct ruletable* table, struct rule_entry rule);

pkt_dc query_ruletable(struct ruletable* table, struct pkt_props* pkt);

#endif /* __RULETABLE_H */

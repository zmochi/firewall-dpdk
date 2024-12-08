#include "ruletable.h"

typedef enum {
	MATCH,
	NO_MATCH,
} rule_match;

typedef uint64_t table_entry;

typedef rule_match(* cmp_rule_fn)(table_entry pkt_prop, table_entry rule_prop);

#define MAX_NB_RULES 500

/* number of fields in `struct rule_fields` */
#define NB_RULE_FIELDS 7
struct rule_fields {
	union {
		table_entry direction_entry;
		uint64_t direction;
	};
	union {
		table_entry saddr_entry;
		uint64_t saddr;
	};
	union {
		table_entry daddr_entry;
		uint64_t daddr;
	};
	union {
		table_entry proto_entry;
		uint64_t proto;
	};
	union {
		table_entry sport_entry;
		uint64_t sport;
	};
	union {
		table_entry dport_entry;
		uint64_t dport;
	};
	union {
		table_entry ack_entry;
		uint64_t ack;
	};
};

struct rule {
	/* union for accessing fields by name and by index, to enable iterating over table columns by index AND by name */
	union {
		struct rule_fields field;
		table_entry rule[NB_RULE_FIELDS];
	};
};

struct ruletable {
	struct rule rule_entry[MAX_NB_RULES];
};

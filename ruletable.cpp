#include "ruletable.h"

int init_ruletable(struct ruletable* ruletable) {
	ruletable->nb_rules = 0;
	return 0;
}

int add_rule(struct ruletable* table, struct rule_entry rule) {
	table->rule_entry[table->nb_rules++] = rule;
	return 0;
}

pkt_dc query_ruletable(struct ruletable* table, struct pkt_props* pkt) {

}

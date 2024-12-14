#ifndef __RULETABLE_H
#define __RULETABLE_H

#include "endian.hpp"
#include "logger.hpp" /* for reason_t */
#include "packet.hpp"
#include <array>
#include <shared_mutex>
#include <stddef.h>
#include <stdint.h>

#define MAX_NB_RULES   500
#define RULETABLE_SIZE (MAX_NB_RULES * sizeof(rule_entry))

typedef uint64_t table_entry;

typedef enum {
    MATCH,
    NO_MATCH,
} rule_match;

typedef rule_match (*cmp_rule_fn)(table_entry pkt_prop, table_entry rule_prop);

#define RULE_NAME_MAXLEN 20

struct decision_info {
    int    rule_idx;
    pkt_dc decision;
    /* either REASON_NO_RULE or REASON_RULE */
    reason_t reason;
};

struct rule_entry {
    std::array<char, RULE_NAME_MAXLEN> name;

    direction direction;
    be32_t    saddr;
    be32_t    daddr;
    be16_t    proto;
    be16_t    sport;
    be16_t    dport;
    uint64_t  ack;
    pkt_dc    action;
};

struct ruletable {
    /* TODO: lock per rule_entry? */
    /* reader-writer lock - lock.lock_shared() is reader lock, lock.lock() is
     * writer lock */
    std::shared_mutex                    ruletable_rwlock;
    std::array<rule_entry, MAX_NB_RULES> rule_entry_arr;
    size_t                               nb_rules;

    ruletable() : nb_rules(0) {}
    int           add_rule(rule_entry rule);
    decision_info query(pkt_props *pkt);
};

int start_ruletable();

#endif /* __RULETABLE_H */

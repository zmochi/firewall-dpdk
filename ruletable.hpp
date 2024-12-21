#ifndef __RULETABLE_H
#define __RULETABLE_H

#include "endian.hpp"
#include "logger.hpp" /* for reason_t */
#include "packet.hpp"
#include <array>
#include <shared_mutex>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>

static constexpr auto RULE_NAME_MAXLEN = 20;

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

static constexpr auto MAX_NB_RULES = 500;
static constexpr auto RULETABLE_SIZE = (MAX_NB_RULES * sizeof(rule_entry));

typedef uint64_t table_entry;

typedef enum {
    MATCH,
    NO_MATCH,
} rule_match;

struct decision_info {
    int    rule_idx;
    pkt_dc decision;
    /* either REASON_NO_RULE or REASON_RULE */
    reason_t reason;
};

struct ruletable {
    /* TODO: lock per rule_entry? */
    /* reader-writer lock - lock.lock_shared() is reader lock, lock.lock() is
     * writer lock */
    std::shared_mutex                    ruletable_rwlock;
    std::array<rule_entry, MAX_NB_RULES> rule_entry_arr;
    atomic_size_t                               nb_rules;

    ruletable() : nb_rules(0) {}
    int           add_rule(rule_entry rule);
    decision_info query(pkt_props *pkt, pkt_dc dft_dc);
};

int start_ruletable(ruletable& ruletable);

#endif /* __RULETABLE_H */

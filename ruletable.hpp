#ifndef __RULETABLE_H
#define __RULETABLE_H

#include "endian.hpp"
#include "packet.hpp"

#include <array>
#include <shared_mutex>
#include <stdatomic.h>
#include <string>

static constexpr auto RULE_NAME_MAXLEN = 20;

typedef enum {
    ACK_NO = 0x01,
    ACK_YES = 0x02,
    ACK_ANY = ACK_NO | ACK_YES,
} ack_t;

/* how to compare a port number */
enum port_cmp : be16_t {
    PORT_LT = 0x01, /* less than */
    PORT_GT = 0x02, /* greater than */
    PORT_EQ = 0x04, /* equal only */
	PORT_ANY = 0x08, /* don't do comparison, allow all ports */
};

struct rule_entry {
    std::array<char, RULE_NAME_MAXLEN> name;

    direction direction;
    be32_t    saddr;
    be32_t    saddr_mask;
    be32_t    daddr;
    be32_t    daddr_mask;
    proto     proto;
    be16_t    sport;
    port_cmp  sport_mask;
    be16_t    dport;
    port_cmp  dport_mask;
    ack_t     ack;
    pkt_dc    action;

    rule_entry() : direction(NUL_DIRECTION), action(PKT_ERR) {}
};

static constexpr auto MAX_NB_RULES = 500;
static constexpr auto RULETABLE_SIZE = (MAX_NB_RULES * sizeof(rule_entry));

typedef enum {
    MATCH,
    NO_MATCH,
} rule_match;

typedef enum : int {
    REASON_XMAS_PKT,
    REASON_NO_RULE,
    REASON_RULE,
	REASON_NONIPV4,
} reason_t;

struct decision_info {
    int    rule_idx;
    pkt_dc decision;
    /* either REASON_NO_RULE or REASON_RULE */
    reason_t reason;

	decision_info() {}
	decision_info(int rule_idx, pkt_dc decision, reason_t reason) : rule_idx(rule_idx), decision(decision), reason(reason) {}
};

struct ruletable {
    /* TODO: lock per rule_entry in array? */
    /* reader-writer lock - lock.lock_shared() is reader lock, lock.lock() is
     * writer lock */
    std::shared_mutex                    ruletable_rwlock;
    std::array<rule_entry, MAX_NB_RULES> rule_entry_arr;
    atomic_size_t                        nb_rules;

    ruletable() : nb_rules(0) {}
    ruletable(std::array<rule_entry, MAX_NB_RULES> &rule_arr, size_t nb_rules);
    int           add_rule(rule_entry rule);
	int replace(ruletable &new_rt);
    decision_info query(const pkt_props *pkt, pkt_dc dft_dc);
};

int start_ruletable(struct ruletable &ruletable,
                    const std::string interface_path, int interface_perms);

#endif /* __RULETABLE_H */

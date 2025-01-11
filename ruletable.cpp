#include "ruletable.hpp"
#include "utils.h"

#include <cstdlib>
#include <fcntl.h>
#include <mutex> /* for unique_lock */
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

int ruletable::replace(ruletable &new_rt) {
    if ( new_rt.nb_rules > MAX_NB_RULES ) return -1;

    if ( rule_entry_arr.size() < new_rt.nb_rules ) {
        ERROR("Destination ruletable capacity too small, can't replace "
              "ruletable");
        return -1;
    }

    ruletable_rwlock.lock();

    for ( int i = 0; i < new_rt.nb_rules; i++ ) {
        rule_entry_arr.at(i) = new_rt.rule_entry_arr.at(i);
    }

    nb_rules = new_rt.nb_rules;

    ruletable_rwlock.unlock();

    return 0;
}

int ruletable::add_rule(rule_entry rule) {
    using namespace std;
    unique_lock<shared_mutex> ruletable_lock(ruletable_rwlock);
    rule_entry_arr.at(nb_rules++) = rule;
    ruletable_lock.unlock();
    return 0;
}

bool cmp_direction(direction rule_direction, direction pkt_direction) {
    if ( rule_direction == NUL_DIRECTION || pkt_direction == NUL_DIRECTION )
        return false;
    if ( rule_direction == UNSPEC ) return true;

    return rule_direction == pkt_direction;
}

bool cmp_ipaddr(be32_t ip1, be32_t ip2, be32_t mask) {
    return (ip1 & mask) == (ip2 & mask);
}

bool cmp_port(be16_t rule_port, be16_t pkt_port, be16_t port_mask) {
    if ( port_mask & PORT_LT )
        return pkt_port < rule_port;
    else if ( port_mask & PORT_GT )
        return pkt_port > rule_port;
    else if ( port_mask & PORT_EQ )
        return rule_port == pkt_port;
    else if ( port_mask & PORT_ANY )
        return true;
    else {
        ERROR("Unknown port mask");
        return false;
    }
}

bool cmp_ack(ack_t rule_ack, uint64_t pkt_tcp_flags) {
    switch ( rule_ack ) {
        case ACK_ANY:
            return true;
        case ACK_YES:
            return (pkt_tcp_flags & TCP_ACK_FLAG) != 0;
        case ACK_NO:
            return (pkt_tcp_flags & TCP_ACK_FLAG) == 0;
        default:
            ERROR("Unknown value from rule_ack");
            return false;
    }
}

bool cmp_proto(proto rule_proto, proto pkt_proto) {
    if ( rule_proto == PROTO_ANY ) return true;

    return rule_proto == pkt_proto;
}

decision_info ruletable::query(const struct pkt_props *pkt, pkt_dc dft_dc) {
    using namespace std;
    /* what to do with packet that has no matching rule */
    const pkt_dc  NO_MATCHING_RULE_DC = dft_dc;
    unsigned int  rule_idx;
    decision_info dc_info = {};

    shared_lock<shared_mutex> lock(ruletable_rwlock);
    for ( rule_idx = 0; rule_idx < nb_rules; rule_idx++ ) {
        rule_entry &rule = rule_entry_arr.at(rule_idx);
        if ( cmp_ack(rule.ack, pkt->tcp_flags) &&
             cmp_direction(rule.direction, pkt->direction) &&
             cmp_ipaddr(rule.saddr, pkt->saddr, rule.saddr_mask) &&
             cmp_ipaddr(rule.daddr, pkt->daddr, rule.daddr_mask) &&
             cmp_proto(rule.proto, pkt->proto) &&
             cmp_port(rule.sport, pkt->sport, rule.sport_mask) &&
             cmp_port(rule.dport, pkt->dport, rule.dport_mask) ) {
            dc_info.decision = rule.action;
            dc_info.rule_idx = rule_idx;
            dc_info.reason = REASON_RULE;
            break;
        }
    }
    lock.unlock();

    /* no matching rule found */
    if ( rule_idx == nb_rules ) {
        dc_info.decision = NO_MATCHING_RULE_DC;
        dc_info.rule_idx = -1;
        dc_info.reason = REASON_NO_RULE;
    }

    return dc_info;
}

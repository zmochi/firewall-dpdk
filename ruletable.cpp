#include "ruletable.hpp"
#include <mutex> /* for unique_lock */

int start_ruletable() {}

int ruletable::add_rule(rule_entry rule) {
	using namespace std;
    unique_lock<shared_mutex> ruletable_lock(ruletable_rwlock);
    rule_entry_arr[nb_rules++] = rule;
    ruletable_lock.unlock();
    return 0;
}

decision_info ruletable::query(struct pkt_props *pkt) {
    using namespace std;
    unsigned int  idx = 0;
    decision_info dc_info = {};

	shared_lock<shared_mutex> lock(ruletable_rwlock);
    for ( rule_entry rule : rule_entry_arr ) {
        if ( rule.ack == (pkt->tcp_flags & TCP_ACK_FLAG) &&
             rule.direction == pkt->direction && rule.saddr == pkt->saddr &&
             rule.daddr == pkt->daddr && rule.proto == pkt->proto &&
             rule.sport == pkt->sport && rule.dport == pkt->dport ) {
            dc_info.decision = rule.action;
            dc_info.rule_idx = idx;
            dc_info.reason = REASON_RULE;
            break;
        }
        idx++;
    }
	lock.unlock();

    /* no matching rule found */
    if ( idx == rule_entry_arr.size() ) {
        dc_info.decision = PKT_DROP;
        dc_info.rule_idx = -1;
        dc_info.reason = REASON_NO_RULE;
    }

    return dc_info;
}

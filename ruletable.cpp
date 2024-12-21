#include "ruletable.hpp"
#include "utils.h"
#include <mutex> /* for unique_lock */

#include <cstdlib>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "ruletable_interface.hpp"

int start_ruletable() {
    /* create named Unix socket, backed by file somewhere in the file system to
     * handle show_rules, load_rules and so on */
    if ( mkfifo(RULETABLE_INTERFACE_PATH,
                RULETABLE_INTERFACE_PIPE_PERMISSIONS) < 0 ) {
        ERROR("Couldn't create ruletable interface named pipe");
        return -1;
    }

    int ruletable_interface_fd = open(RULETABLE_INTERFACE_PATH, O_RDONLY);
    if ( ruletable_interface_fd < 0 ) {
        ERROR("Couldn't open ruletable interface named pipe");
        return -1;
    }

    ruletable_action action;
    char             new_ruletable_path[RULETABLE_PATH_MAXLEN];

    while ( 1 ) {
        read(ruletable_interface_fd, &action, sizeof(action));
        switch ( action ) {
        LOAD_RULETABLE:
			/* get path */
        SHOW_RULETABLE:
        RST_RULETABLE:
        default:
            printf("Unknown ruletable action\n");
            continue;
        }
    }
}

int ruletable::add_rule(rule_entry rule) {
    using namespace std;
    unique_lock<shared_mutex> ruletable_lock(ruletable_rwlock);
    rule_entry_arr.at(nb_rules++) = rule;
    ruletable_lock.unlock();
    return 0;
}

decision_info ruletable::query(struct pkt_props *pkt, pkt_dc dft_dc) {
    using namespace std;
    /* what to do with packet that has no matching rule */
    const pkt_dc  NO_MATCHING_RULE_DC = dft_dc;
    unsigned int  rule_idx;
    decision_info dc_info = {};

    shared_lock<shared_mutex> lock(ruletable_rwlock);
    for ( rule_idx = 0; rule_idx < nb_rules; rule_idx++ ) {
        rule_entry &rule = rule_entry_arr.at(rule_idx);
        if ( rule.ack == (pkt->tcp_flags & TCP_ACK_FLAG) &&
             rule.direction == pkt->direction && rule.saddr == pkt->saddr &&
             rule.daddr == pkt->daddr && rule.proto == pkt->proto &&
             rule.sport == pkt->sport && rule.dport == pkt->dport ) {
            dc_info.decision = rule.action;
            dc_info.rule_idx = rule_idx;
            dc_info.reason = REASON_RULE;
            break;
        }
        rule_idx++;
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

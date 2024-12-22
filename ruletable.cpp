#include "ruletable.hpp"
#include "simple_ipc.hpp"
#include "utils.h"
#include <mutex> /* for unique_lock */

#include <cstdlib>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include "ruletable_interface.hpp"

static constexpr auto RULETABLE_INTERFACE_BACKLOG = 10;

int replace_ruletable(ruletable        &ruletable,
                      const std::string new_ruletable_path) {
    char* new_ruletable = load_file(&ruletable.rule_entry_arr, sizeof(rule_entry_arr),
                   new_ruletable_path); 
	if(
        ERROR("Couldn't load file from %s", new_ruletable_path.data());
        return -1;
    }
}

void ruletable_msg_callback(IPC_Server<ruletable_action> &inst,
                            ruletable_action action, int msg_sockfd,
                            void *arg) {
    ruletable &ruletable = *static_cast<struct ruletable *>(arg);
    char       new_ruletable_path[RULETABLE_PATH_MAXLEN];

    switch ( action ) {
        case LOAD_RULETABLE:
            /* get RULETABLE_PATH_MAXLEN bytes, path padded with null bytes
             * return DONE, 4 bytes when finished */
            if ( inst.recv_size(msg_sockfd, new_ruletable_path,
                                RULETABLE_PATH_MAXLEN) < 0 ) {
                ERROR("Couldn't receive new path from ruletable interface "
                      "socket");
                return -1;
            }

            replace_ruletable(new_ruletable_path, RULETABLE_PATH_MAXLEN);
            break;

        case SHOW_RULETABLE:
            /* send sizeof(struct ruletable) bytes containing the entire
             * ruletable struct? */
            ruletable.ruletable_rwlock.lock_shared();
            inst.send_size(msg_sockfd, &ruletable, sizeof(ruletable));
            ruletable.ruletable_rwlock.unlock();
            break;

        default:
            printf("Unknown ruletable action\n");
            return;
    }
}

int start_ruletable(struct ruletable &ruletable) {
    /* named Unix socket, backed by file somewhere in the file system to
     * handle show_rules and load_rules */
    IPC_Server<ruletable_action> server(
        RULETABLE_INTERFACE_PATH, RULETABLE_INTERFACE_PIPE_PERMISSIONS,
        RULETABLE_INTERFACE_BACKLOG, ruletable_msg_callback);

    server.start_server(&ruletable);
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

#include "ruletable.hpp"
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

int recv_size(int fd, void *buf, size_t len) {
    size_t bytes_recv = 0;
    while ( bytes_recv < len )
        if ( recv(fd, (char *)buf + bytes_recv, len - bytes_recv, 0) < 0 )
            return -1;

    return 0;
}

int send_size(int fd, void *buf, size_t len) {
    size_t bytes_sent = 0;
    while ( bytes_sent < len ) {
        if ( send(fd, buf, len, 0) < 0 ) return -1;
    }

    return 0;
}

int start_ruletable(struct ruletable &ruletable) {
    /* create named Unix socket, backed by file somewhere in the file system to
     * handle show_rules, load_rules and so on */
    struct sockaddr_un unix_sock_opts = {.sun_family = AF_UNIX};
    strcpy(unix_sock_opts.sun_path, RULETABLE_INTERFACE_PATH);

    int ruletable_interface_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if ( ruletable_interface_fd < 0 ) {
        ERROR("Couldn't open ruletable interface socket");
        return -1;
    }

    int err = bind(ruletable_interface_fd, (struct sockaddr *)&unix_sock_opts,
                   strlen(RULETABLE_INTERFACE_PATH) +
                       sizeof(unix_sock_opts.sun_family));
    if ( err < 0 ) {
        ERROR("Couldn't bind ruletable interface socket");
        return -1;
    }

    if(listen(ruletable_interface_fd, RULETABLE_INTERFACE_BACKLOG) < 0) {
		ERROR("Couldn't listen on ruletable interface socket");
		return -1;
	}

    int              new_sockfd;
    int              bytes_recv, bytes_sent;
    ruletable_action action;
    char             new_ruletable_path[RULETABLE_PATH_MAXLEN];

    while ( 1 ) {
        int new_sockfd = accept(ruletable_interface_fd, nullptr, nullptr);
        if ( new_sockfd < 0 ) {
            ERROR("Couldn't accept ruletable interface connection on socket");
            return -1;
        }

        if ( recv_size(new_sockfd, &action, sizeof(action)) < 0 )
            ERROR("Couldn't receive action from ruletable interface socket");

        bytes_recv = 0;
        bytes_sent = 0;
        switch ( action ) {
            case LOAD_RULETABLE:
                /* get RULETABLE_PATH_MAXLEN bytes, path padded with null bytes
                 * return DONE, 4 bytes when finished */
                if ( recv_size(new_sockfd, new_ruletable_path,
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
                send_size(new_sockfd, &ruletable, sizeof(ruletable));
                ruletable.ruletable_rwlock.unlock();
                break;

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

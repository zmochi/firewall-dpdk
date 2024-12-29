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

int replace_ruletable(ruletable &rt, ruletable &new_rt) {
    if ( new_rt.nb_rules > MAX_NB_RULES ) return -1;

    if ( rt.rule_entry_arr.size() < new_rt.nb_rules ) {
        ERROR("Destination ruletable capacity too small, can't replace "
              "ruletable");
        return -1;
    }

    rt.ruletable_rwlock.lock();

    for ( int i = 0; i < new_rt.nb_rules; i++ ) {
        rt.rule_entry_arr.at(i) = rt.rule_entry_arr.at(i);
    }

    rt.nb_rules = new_rt.nb_rules;

    rt.ruletable_rwlock.unlock();

    return 0;
}

int ruletable_msg_callback(IPC_Server<ruletable_action> &server,
                           ruletable_action action, size_t msg_size,
                           int msg_sockfd, void *user_arg) {
    ruletable       &ruletable = *static_cast<struct ruletable *>(user_arg);
    char             new_ruletable_path[RULETABLE_PATH_MAXLEN];
    struct ruletable new_rt;
    size_t           new_nb_rules;
    ruletable_action server_response;

    switch ( action ) {
        case LOAD_RULETABLE:
            /* get RULETABLE_PATH_MAXLEN bytes, path padded with null bytes */
            if ( server.recv_size(msg_sockfd, &new_nb_rules,
                                  sizeof(new_nb_rules)) < 0 ) {
                ERROR("Couldn't receive number of rules in new ruletable");
                return -1;
            }

            /* rule_entry_arr is a static array, so its size is also its
             * capacity */
            if ( new_nb_rules > new_rt.rule_entry_arr.size() ) {
                ERROR("Client sent ruletable with too many rules.");
                server_response = BAD_MSG;
                if ( server.send_size(msg_sockfd, &server_response,
                                      sizeof(server_response)) < 0 ) {
                    ERROR("Couldn't send BAD_MSG back to client");
                    return -1;
                }
                break;
            }

            server_response = OK;
            if ( server.send_size(msg_sockfd, &server_response,
                                  sizeof(server_response)) < 0 ) {
                ERROR("Couldn't send OK message to client after receiving "
                      "number of rules");
                return -1;
            }

            if ( server.recv_size(msg_sockfd, &new_rt.rule_entry_arr,
                                  new_rt.rule_entry_arr.size() *
                                      sizeof(new_rt.rule_entry_arr[0])) < 0 ) {
                ERROR("Couldn't receive new ruletable, on ruletable interface "
                      "socket");
                return -1;
            }

            replace_ruletable(ruletable, new_rt);
            break;

        case SHOW_RULETABLE:
            ruletable.ruletable_rwlock.lock_shared();

            server.send_size(msg_sockfd, &ruletable.nb_rules,
                             sizeof(ruletable.nb_rules));
            server.send_size(msg_sockfd, &ruletable.rule_entry_arr,
                             ruletable.nb_rules *
                                 sizeof(ruletable.rule_entry_arr[0]));

            ruletable.ruletable_rwlock.unlock();
            break;

        default:
            printf("Unknown ruletable action\n");
            return 0;
    }

    return 0;
}

int start_ruletable(struct ruletable &ruletable,
                    const std::string interface_path, int interface_perms) {
    /* named Unix socket, backed by file somewhere in the file system to
     * handle show_rules and load_rules. this is a server object that listens on
     * that socket. */
    IPC_Server<ruletable_action> server(interface_path, interface_perms,
                                        RULETABLE_INTERFACE_BACKLOG,
                                        ruletable_msg_callback);

    /* starts server that handles show_rules, load_rules */
    return server.start_server(&ruletable);
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

bool cmp_port(be16_t port1, be16_t port2, be16_t port_mask) {
    if ( port_mask & PORT_LT )
        return port2 < port1;
    else if ( port_mask & PORT_GT )
        return port2 > port1;
    else if ( port_mask & PORT_EQ )
        return port1 == port2;
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

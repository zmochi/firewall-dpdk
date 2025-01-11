#include "../ruletable.hpp"
#include "ruletable_interface.hpp"
#include "simple_ipc.hpp"
#include "../utils.h"

/* how many simultaneous clients can be waiting for server to accept their connection */
static constexpr auto RULETABLE_INTERFACE_BACKLOG = 10;

/* @brief callback for IPC_Server implementation - whenever IPC_Client implementation uses send_action() on the interface, this callback is triggered
 * @param server the IPC_Server class instance this was called from
 * @param action the action IPC_Client sent
 * @param msg_size size of message
 * @param msg_sockfd socket file descriptor to receive message on
 * @param user_arg argument defined at instantiation of IPC_Server instance
 */
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

            new_rt.nb_rules = new_nb_rules;

            if ( server.recv_size(msg_sockfd, new_rt.rule_entry_arr.data(),
                                  new_rt.rule_entry_arr.size() *
                                      sizeof(new_rt.rule_entry_arr[0])) < 0 ) {
                ERROR("Couldn't receive new ruletable, on ruletable interface "
                      "socket");
                return -1;
            }

            ruletable.replace(new_rt);
            break;

        case SHOW_RULETABLE:
            ruletable.ruletable_rwlock.lock_shared();

            server.send_size(msg_sockfd, &ruletable.nb_rules,
                             sizeof(ruletable.nb_rules));
            server.send_size(msg_sockfd, ruletable.rule_entry_arr.data(),
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

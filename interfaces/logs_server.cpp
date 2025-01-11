#include "../logger.hpp"
#include "logs_interface.hpp"
#include "simple_ipc.hpp"

int log_server_cb(IPC_Server<log_actions> &server, log_actions action,
                  size_t msg_size, int sockfd, void *logger_arg) {
    log_list        &logger = *static_cast<log_list *>(logger_arg);
    nb_logs_t        num_logs = 0;
    log_row_t       *logs_arr;
    int              i = 0;
    enum log_actions client_resp = CLIENT_ERR;

    switch ( action ) {
        case SHOW_LOGS:
            logger.log_hashmap_lock.lock();

            num_logs = logger.log_hashmap.size();
            logs_arr = new log_row_t[num_logs];
            i = 0;
            for ( auto log_row : logger.log_hashmap ) {
                logs_arr[i++] = log_row.second;
            }

            server.send_size(sockfd, &num_logs, sizeof(num_logs));

            server.recv_size(sockfd, &client_resp, sizeof(client_resp));
            if ( client_resp != CLIENT_OK ) {
                ERROR("Client couldn't receive %zu logs", num_logs);
                return 0;
            }

            server.send_size(sockfd, logs_arr, num_logs * sizeof(logs_arr[0]));

            logger.log_hashmap_lock.unlock();
            break;

        case RST_LOGS:
            logger.log_hashmap_lock.lock();
            logger.log_hashmap.clear();
            logger.log_hashmap_lock.unlock();
            break;

        default:
            ERROR("Unknown action from client");
            break;
    }

    return 0;
}

int start_log_server(log_list &logger, const std::string log_interface_path,
                     int log_interface_perms) {
    IPC_Server<log_actions> server(log_interface_path, log_interface_perms, 10,
                                   log_server_cb);

    return server.start_server(&logger);
}

#include "../logger.hpp"
#include "logs_interface.hpp"
#include "simple_ipc.hpp"

int show_logs(IPC_Client<log_actions> &client,
              std::vector<log_row_t>  &logs_dest) {
    nb_logs_t        num_logs = 0;
    enum log_actions resp = CLIENT_ERR;

    if ( client.send_action(SHOW_LOGS) < 0 ) {
        ERROR("Couldn't send SHOW_LOGS action");
        return -1;
    }

    if ( client.recv_size(&num_logs, sizeof(num_logs)) < 0 ) {
        ERROR("Couldn't receive number of logs from server");
        return -1;
    }

    if ( num_logs > MAX_NB_LOGS ) {
        ERROR("Server wants to send too many logs");
        return -1;
    }

    resp = CLIENT_OK;
    if ( client.send_size(&resp, sizeof(resp)) < 0 ) {
        ERROR("Couldn't send CLIENT_OK response");
        return -1;
    }

    logs_dest.resize(num_logs);
    if ( client.recv_size(logs_dest.data(),
                          logs_dest.capacity() * sizeof(log_row_t)) < 0 ) {
        ERROR("Couldn't receive logs array");
        return -1;
    }

    return 0;
}

int reset_logs(IPC_Client<log_actions> &client) {
    if ( client.send_action(RST_LOGS) < 0 ) {
        ERROR("Couldn't send RST_LOGS action to server");
        return -1;
    }

    return 0;
}

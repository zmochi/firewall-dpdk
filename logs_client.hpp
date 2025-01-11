#ifndef __LOGS_CLIENT_H
#define __LOGS_CLIENT_H

#include "logger.hpp"
#include "logs_interface.hpp"
#include "simple_ipc.hpp"

#define LOG_TXT_TITLE                                                          \
    "timestamp\t\tsrc_ip\t\tdst_ip\t\tsrc_port\t\tdst_"                        \
    "port\t\tprotocol\t\taction\t\treason\t\tcount";

int         show_logs(IPC_Client<log_actions> &ipc_client,
                      std::vector<log_row_t>  &logs_dest);
int         reset_logs(IPC_Client<log_actions> &client);
std::string fmt_log(log_row_t log);

#endif /* __LOGS_CLIENT_H */

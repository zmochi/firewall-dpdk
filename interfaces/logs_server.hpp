#ifndef __LOGS_SERVER_H
#define __LOGS_SERVER_H

#include "../logger.hpp"
#include <string>

/* server that listens on AF_UNIX socket for show_logs, reset_logs... see start_ruletable() documentation */
int start_log_server(log_list& logger, const std::string log_interface_path, int log_interface_perms);

#endif /* __LOGS_SERVER_H */

#ifndef __LOGS_SERVER_H
#define __LOGS_SERVER_H

#include "logger.hpp"
#include <string>

int start_log_server(log_list& logger, const std::string log_interface_path, int log_interface_perms);

#endif /* __LOGS_SERVER_H */

#include "logger.hpp" /* for log_row_t */

#define LOG_INTERFACE_PATH "/dev/log_interface"
constexpr auto MAX_NB_LOGS = 1 << 18;
constexpr auto LOG_INTERFACE_PERMS = 0600;

enum log_actions {
    SHOW_LOGS,
    RST_LOGS,
    CLIENT_OK,
    CLIENT_ERR,
};

/* type that stores number of logs, first thing that is sent to the client
 * receiving the logs */
using nb_logs_t = size_t;

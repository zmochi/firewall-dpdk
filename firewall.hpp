#include <cstring>
#include "macaddr.hpp"
#include "logger.hpp"

int start_firewall(int argc, char **argv, struct ruletable &ruletable,
                   MAC_addr in_mac, MAC_addr out_mac, log_list &logger);

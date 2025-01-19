#include "logger.hpp"
#include "macaddr.hpp"
#include "ruletable.hpp"
#include <cstring>

int start_firewall(int argc, char **argv, ruletable &rt, MAC_addr in_mac,
                   MAC_addr out_mac, log_list &logger);

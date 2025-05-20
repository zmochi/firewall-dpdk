#include "logger.hpp"
#include "macaddr.hpp"
#include "ruletable.hpp"
#include <cstring>

int start_firewall(int argc, char **argv, ruletable &rt, MAC_addr in_mac,
                   uint32_t in_netmask, MAC_addr out_mac, uint32_t out_netmask,
                   log_list &logger);

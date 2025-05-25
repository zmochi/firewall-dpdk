#ifndef __FIREWALL_H
#define __FIREWALL_H

#include "logger.hpp"
#include "macaddr.hpp"
#include "ruletable.hpp"
#include <cstring>

int start_firewall(int argc, char **argv, ruletable &rt, MAC_addr in_mac,
                   be32_t in_routingprefix, be32_t in_netmask, MAC_addr out_mac, be32_t out_routingprefix, be32_t out_netmask,
                   log_list &logger);

#endif /* __FIREWALL_H */

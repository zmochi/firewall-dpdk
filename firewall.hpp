#include <cstring>
#include "macaddr.hpp"

int start_firewall(int argc, char **argv, struct ruletable *ruletable,
                   MAC_addr in_mac, MAC_addr out_mac);

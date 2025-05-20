#include "firewall.hpp"
#include "interfaces/logs_interface.hpp"
#include "interfaces/logs_server.hpp"
#include "interfaces/ruletable_interface.hpp"
#include "interfaces/ruletable_server.hpp"
#include "logger.hpp"
#include "macaddr.hpp"
#include "parsers/net_parsers.hpp"
#include "ruletable.hpp"
#include "utils.h"

#include <cstdlib>
#include <iostream>
#include <thread>
#include <unistd.h>

void firewall_thread(int argc, char **argv, ruletable &rt, MAC_addr in_mac,
                     uint32_t in_netmask, MAC_addr out_mac,
                     uint32_t out_netmask, log_list &logger) {
    start_firewall(argc, argv, rt, in_mac, in_netmask, out_mac, out_netmask, logger);
}

void ruletable_thread(ruletable &rt, const std::string &interface_file_path,
                      int interface_file_permissions) {
    start_ruletable(rt, interface_file_path, interface_file_permissions);
}

void logger_thread(log_list &logger, const std::string &interface_file_path,
                   int interface_file_permissions) {
    start_log_server(logger, interface_file_path, interface_file_permissions);
}

int main(int argc, char *argv[]) {
    if ( argc != 5 ) {
        std::cout << "Usage: " << argv[0]
                  << " <internal NIC MAC address> <external NIC MAC address>"
                  << " <internal network IP and mask xx.xx.xx.xx/xx>"
                  << " <external network IP and mask xx.xx.xx.xx/xx>"
                  << std::endl;
        return 1;
    }

    /* TODO: move tests to a normal location */
    // test_parse_mac_addr();
    MAC_addr int_net_mac, ext_net_mac;
    uint32_t int_netmask, ext_netmask;
    /* unused */
    uint32_t int_gw, ext_gw;
    if ( parse_mac_addr(argv[1], int_net_mac) < 0 ) {
        ERROR_EXIT("Error parsing internal network mac address");
    }
    if ( parse_mac_addr(argv[2], ext_net_mac) < 0 ) {
        ERROR_EXIT("Error parsing external network mac address");
    }
    if ( parse_ipaddr(argv[3], &int_gw, &int_netmask) != 0 ) {
        ERROR_EXIT("Error parsing internal network IP and subnet");
    }
    if ( parse_ipaddr(argv[4], &ext_gw, &ext_netmask) != 0 ) {
        ERROR_EXIT("Error parsing external network IP and subnet");
    }
	// from subnet and IP into netmask
	int_netmask &= int_gw;
	ext_netmask &= ext_gw;

    log_list  *logger = new struct log_list;
    ruletable *rt = new struct ruletable;

    std::thread log_thread(logger_thread, std::ref(*logger), LOG_INTERFACE_PATH,
                           LOG_INTERFACE_PERMS);
    std::thread rt_thread(ruletable_thread, std::ref(*rt),
                          RULETABLE_INTERFACE_PATH, RULETABLE_INTERFACE_PERMS);
    std::thread fw_thread(firewall_thread, argc - 2, argv, std::ref(*rt),
                          int_net_mac, int_netmask, ext_net_mac, ext_netmask, std::ref(*logger));

    fw_thread.join();
    /* quick and dirty solution to exit other threads when returning... */
    rt_thread.detach();
    log_thread.detach();
    return 0;
}

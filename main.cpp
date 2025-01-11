#include "firewall.hpp"
#include "logger.hpp"
#include "logs_interface.hpp"
#include "ruletable_interface.hpp"
#include "logs_server.hpp"
#include "macaddr.hpp"
#include "ruletable.hpp"
#include "utils.h"

#include <cstdlib>
#include <iostream>
#include <thread>
#include <unistd.h>

void firewall_thread(int argc, char **argv, ruletable &rt, MAC_addr in_mac,
                     MAC_addr out_mac, log_list &logger) {
    start_firewall(argc, argv, rt, in_mac, out_mac, logger);
}

void ruletable_thread(ruletable &rt, const std::string &interface_file_path,
                      int interface_file_permissions) {
    start_ruletable(rt, interface_file_path, interface_file_permissions);
}

void logger_thread(log_list &logger, const std::string &interface_file_path, int interface_file_permissions) {
    start_log_server(logger, interface_file_path, interface_file_permissions);
}

int main(int argc, char *argv[]) {
    if ( argc != 3 ) {
        std::cout << "Usage: " << argv[0]
                  << " <internal NIC MAC address> <external NIC MAC address>"
                  << std::endl;
		return 1;
    }

    /* TODO: move tests to a normal location */
	//test_parse_mac_addr();
    MAC_addr int_net_mac, ext_net_mac;
    if ( parse_mac_addr(argv[1], int_net_mac) < 0 ) {
        ERROR_EXIT("Error parsing internal network mac address");
    }
    if ( parse_mac_addr(argv[2], ext_net_mac) < 0 ) {
        ERROR_EXIT("Error parsing external network mac address");
    }

    log_list  *logger = new struct log_list;
    ruletable *rt = new struct ruletable;

    std::thread log_thread(logger_thread, std::ref(*logger), LOG_INTERFACE_PATH, LOG_INTERFACE_PERMS);
    std::thread rt_thread(ruletable_thread, std::ref(*rt), RULETABLE_INTERFACE_PATH,
                          RULETABLE_INTERFACE_PERMS);
    std::thread fw_thread(firewall_thread, argc - 2, argv, std::ref(*rt), int_net_mac,
                          ext_net_mac, std::ref(*logger));

    log_thread.join();
    rt_thread.join();
    fw_thread.join();
}

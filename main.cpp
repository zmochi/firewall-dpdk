#include "firewall.hpp"
#include "logger.hpp"
#include "macaddr.hpp"
#include "ruletable.hpp"
#include "utils.h"

#include <cstdlib>
#include <new>
#include <unistd.h>
#include <threads.h>

/* shared memory: */
#include <fcntl.h>
#include <mqueue.h>
#include <string>
#include <sys/mman.h>
#include <sys/stat.h>

struct firewall_thread_args {
    int               dpdk_eal_argc;
    char            **dpdk_eal_argv;
    struct ruletable &ruletable;
    MAC_addr          int_mac_addr, ext_mac_addr;

	firewall_thread_args(int dpdk_eal_argc, char** dpdk_eal_argv, struct ruletable& ruletable, MAC_addr int_mac_addr, MAC_addr ext_mac_addr) : dpdk_eal_argc(dpdk_eal_argc), dpdk_eal_argv(dpdk_eal_argv), ruletable(ruletable), int_mac_addr(int_mac_addr), ext_mac_addr(ext_mac_addr) {}
};

void *logger_thread(void *arg) {}

void *firewall_thread(void *arg) {}

void *ruletable_thread(void *arg) {}

int main(int argc, char *argv[]) {
    if ( argc != 2 ) {
        PRINT_USAGE();
    }

    /* TODO: move tests to a normal location */
    test_parse_mac_addr();
    std::string int_mac = std::string(argv[0]), ext_mac = std::string(argv[1]);
    MAC_addr    int_net_mac, ext_net_mac;
    if ( parse_mac_addr(int_mac, int_net_mac) < 0 ) {
        ERROR_EXIT("Error parsing internal network mac address");
    }
    if ( parse_mac_addr(ext_mac, ext_net_mac) < 0 ) {
        ERROR_EXIT("Error parsing external network mac address");
    }

    ruletable *ruletable = new struct ruletable;
    if ( ruletable == nullptr ) {
        ERROR_EXIT("Error creating ruletable memory");
    }

    int logger_pid = fork();
    if ( logger_pid == 0 ) {
        /* second process handles logs */
        start_logger();
    } else if ( logger_pid < 0 ) {
        /* err on fork */
        ERROR_EXIT("Logger fork failed");
    }

    int fw_pid = fork();
    if ( fw_pid == 0 ) {
        /* third process, firewall process */
		firewall_thread_args args(0, nullptr, *ruletable, int_net_mac, ext_net_mac);
        if ( start_firewall(0, NULL, ruletable, int_net_mac, ext_net_mac) <
             0 ) {
            ERROR_EXIT("Couldn't start firewall");
        }
    } else if ( fw_pid < 0 ) {
        /* error in fork */
        ERROR_EXIT("Firewall fork failed");
    }

    /* main process handles ruletable */
    start_ruletable();
}

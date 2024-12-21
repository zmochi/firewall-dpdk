#include "firewall.hpp"
#include "logger.hpp"
#include "macaddr.hpp"
#include "ruletable.hpp"
#include "utils.h"

#include <cstdlib>
#include <new>
#include <unistd.h>

/* shared memory: */
#include <fcntl.h>
#include <mqueue.h>
#include <string>
#include <sys/mman.h>
#include <sys/stat.h>

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

    ruletable *ruletable =
        new (mmap(NULL, RULETABLE_SIZE, PROT_READ | PROT_WRITE,
                  MAP_SHARED | MAP_ANONYMOUS, -1, 0)) struct ruletable;
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

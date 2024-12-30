#include "firewall.hpp"
#include "logger.hpp"
#include "macaddr.hpp"
#include "ruletable.hpp"
#include "utils.h"

#include <cstdlib>
#include <iostream>
#include <new>
#include <thread>
#include <unistd.h>

/* shared memory: */
#include <fcntl.h>
#include <mqueue.h>
#include <string>
#include <sys/mman.h>
#include <sys/stat.h>

void logger_thread(log_list &logger) {

}

void log_filewriter(log_list &logger, const std::string_view log_writepath) {
}

int main(int argc, char *argv[]) {
    if ( argc != 2 ) {
		std::cout << "Usage:" << argv[0] << "<internal NIC MAC address> <external NIC MAC address>" << std::endl;
    }

    /* TODO: move tests to a normal location */
    test_parse_mac_addr();
    MAC_addr    int_net_mac, ext_net_mac;
    if ( parse_mac_addr(argv[0], int_net_mac) < 0 ) {
        ERROR_EXIT("Error parsing internal network mac address");
    }
    if ( parse_mac_addr(argv[1], ext_net_mac) < 0 ) {
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
		log_list logger;
		/* writes logs to hashmap */
		std::thread log_recorder(logger_thread, logger);
		/* writes logs to file on demand etc */
		std::thread log_writer(log_filewriter, logger);
        logger.start_logger();
    } else if ( logger_pid < 0 ) {
        /* err on fork */
        ERROR_EXIT("Logger fork failed");
    }

    int fw_pid = fork();
    if ( fw_pid == 0 ) {
        /* third process, firewall process */
        if ( start_firewall(0, NULL, ruletable, int_net_mac, ext_net_mac, logger) <
             0 ) {
            ERROR_EXIT("Couldn't start firewall");
        }
    } else if ( fw_pid < 0 ) {
        /* error in fork */
        ERROR_EXIT("Firewall fork failed");
    }

    /* main process handles ruletable */
    if(start_ruletable(*ruletable) < 0) {
		ERROR("Couldn't start ruletable process");
		return -1;
	}
}


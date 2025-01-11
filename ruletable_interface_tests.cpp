#include "ruletable_client.hpp"
#include "ruletable.hpp"
#include <iostream>
#include <unistd.h>

constexpr auto NEW_RT_PATH = "/home/fw/DPDK/ruletable.txt";
constexpr auto RT_MSG_PATH = "/dev/ruletable_iface_test";

int main() {
    if ( fork() == 0 ) {
        usleep(90);
		std::cout << "Hello from client" << std::endl;
        auto new_rt = load_ruletable_from_file(NEW_RT_PATH);
        if ( new_rt == nullptr ) {
            std::cout << "Couldn't load ruletable from file" << std::endl;
			return 1;
        }

		std::cout << "Read ruletable file" << std::endl;

        if ( load_ruletable(*new_rt, RT_MSG_PATH) < 0 ) {
            std::cout << "Couldn't send ruletable to server" << std::endl;
        }

		std::cout << "Loaded ruletable file to server process" << std::endl;
		std::cout << "Number of rules = " << new_rt->nb_rules << std::endl;

        return 0;
    }
    ruletable rt;
    if ( start_ruletable(rt, RT_MSG_PATH, 0600) < 0 ) {
        std::cout << "Can't start ruletable server" << std::endl;
        return 1;
    }
}

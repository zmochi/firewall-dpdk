#include "ruletable.hpp"
#include "ruletable_client.hpp"
#include <iostream>
#include <unistd.h>

constexpr auto NEW_RT_PATH = "/home/fw/DPDK/ruletable.txt";
constexpr auto RT_MSG_PATH = "/dev/ruletable_iface_test";

int main() {
    if ( fork() == 0 ) {
        usleep(50);
        auto new_rt = load_ruletable_from_file(NEW_RT_PATH);

        if ( load_ruletable(new_rt, RT_MSG_PATH) < 0 ) {
            std::cout << "Couldn't send ruletable to server" << std::endl;
        }

        return 0;
    } else {
        ruletable rt;
        if ( start_ruletable(rt, RT_MSG_PATH, 0600) < 0 ) {
            std::cout << "Can't server ruletable server" << std::endl;
            return 1;
        }
    }
}

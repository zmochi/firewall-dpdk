#include "ruletable_client.hpp"

#include "parsers/ruletable_parser.hpp"
#include "ruletable.hpp"
#include "ruletable_interface.hpp"
#include "simple_ipc.hpp"
#include "utils.h"

#include <cassert>
#include <climits>

int load_ruletable(ruletable &rt, const std::string rt_interface_path) {
    /* ruletable_action is an enum containing actions the client can send to the
     * server */
    IPC_Client<ruletable_action> client(rt_interface_path);

    if ( client.send_action(LOAD_RULETABLE) < 0 ) {
        ERROR("Couldn't send client action to server");
        return -1;
    }

    /* send number of rules in new ruletable */
    if ( client.send_size(&rt.nb_rules, sizeof(rt.nb_rules)) < 0 ) {
        ERROR("Couldn't send number of rules to ruletable server");
        return -1;
    }

    ruletable_action server_response;

    if ( client.recv_size(&server_response, sizeof(server_response)) < 0 ||
         server_response != OK ) {
        ERROR(
            "Couldn't/didn't receive server OK after sending number of rules");
        return -1;
    }

    if ( client.send_size(rt.rule_entry_arr.data(),
                          rt.rule_entry_arr.size() *
                              sizeof(rt.rule_entry_arr[0])) < 0 ) {
        ERROR("Couldn't send ruletable to server");
        return -1;
    }

    return 0;
}

int show_ruletable(ruletable &rt, const std::string rt_interface_path) {
    IPC_Client<ruletable_action> client(rt_interface_path);

    if ( client.send_action(SHOW_RULETABLE) < 0 ) {
        ERROR("Couldn't send SHOW_RULETABLE action to server");
        return -1;
    }

    if ( client.recv_size(&rt.nb_rules, sizeof(rt.nb_rules)) < 0 ) {
        ERROR("Couldn't receive number of rules in ruletable from server");
        return -1;
    }

    if ( client.recv_size(rt.rule_entry_arr.data(),
                          sizeof(rt.rule_entry_arr[0]) * rt.nb_rules) < 0 ) {
        ERROR("Couldn't receive ruletable data");
        return -1;
    }

    return 0;
}

#include <memory>

#include "packet.hpp"
#include "ruletable.hpp"
#include "parsers/ruletable_parser.hpp"
#include "ruletable_client.hpp"
#include "simple_ipc.hpp"
#include "ruletable_interface.hpp"
#include "utils.h"

#include <cassert>
#include <climits>
#include <fstream>

std::unique_ptr<ruletable>
load_ruletable_from_file(const std::string &filepath) {
    using namespace std;
    unique_ptr<ruletable> rt = make_unique<ruletable>();

    constexpr auto                 MAX_RULE_LINE_LEN = 1 << 9;
    array<char, MAX_RULE_LINE_LEN> rule_line;

    size_t   rule_line_len;
    size_t   line_idx = 0;
    ifstream ruletable_file(filepath, ios_base::in);
    while ( ruletable_file.getline(&rule_line[0], rule_line.size()) ) {
        rule_entry rule;
        line_idx++;
        if ( parse_rule(rule_line.data(), rule) < 0 ) {
            ERROR("Couldn't parse rule at line %zu", line_idx);
            return nullptr;
        }
        rt.get()->add_rule(rule);
    }

    return rt;
}

int load_ruletable(ruletable &rt, const std::string rt_interface_path) {
	  /* ruletable_action is an enum containing actions the client can send to the
     * server */
    IPC_Client<ruletable_action> client(ruletable_send_path);

    if ( client.send_action(LOAD_RULETABLE) < 0 ) {
        ERROR("Couldn't send client action to server");
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
}


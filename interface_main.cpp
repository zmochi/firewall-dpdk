#include "parsers/ruletable_parser.hpp"

#include "ruletable_client.hpp"
#include "logger.hpp"
#include "logs_client.hpp"
#include "logs_interface.hpp"
#include "ruletable_interface.hpp"
#include "simple_ipc.hpp"
#include <string>
#include <vector>

const std::string show_logs_user_arg = "show_log";
const std::string reset_logs_user_arg = "clear_log";
const std::string show_rules_user_arg = "show_rules";
const std::string load_rules_user_arg = "load_rules";

void print_usage(const char *progname) {
    printf("\
Usage:\n\
	%s <[%s | %s | %s | %s <path_to_rules_file>]>\n",
           progname, show_logs_user_arg.data(), reset_logs_user_arg.data(),
           show_rules_user_arg.data(), load_rules_user_arg.data());
}

int main(int argc, char *argv[]) {
	if(argc < 2) {
		print_usage(argv[0]);
		return 1;
	}

    const std::string arg = std::string(argv[1]);

    if ( arg == show_logs_user_arg ) {
        IPC_Client<log_actions> client(LOG_INTERFACE_PATH);
        std::vector<log_row_t>  logs;
        show_logs(client, logs);
        const char *log_output_title = LOG_TXT_TITLE;
        std::cout << log_output_title << std::endl;
        for ( log_row_t log : logs ) {
            std::string log_txt = fmt_log(log);
            std::cout << log_txt << std::endl;
        }
    } else if ( arg == reset_logs_user_arg ) {
        IPC_Client<log_actions> client(LOG_INTERFACE_PATH);
        reset_logs(client);
        std::cout << "Reset logs successfully" << std::endl;
    } else if ( arg == show_rules_user_arg ) {
        ruletable rt;
        show_ruletable(rt, RULETABLE_INTERFACE_PATH);
        for (int i = 0; i < rt.nb_rules; i++) {
            std::string rule_txt;
            fmt_rule(rt.rule_entry_arr.at(i), rule_txt);
            std::cout << rule_txt << std::endl;
        }
    } else if ( arg == load_rules_user_arg ) {
        if ( argc != 3 ) {
            print_usage(argv[0]);
            return 1;
        }

        std::unique_ptr<ruletable> rt = load_ruletable_from_file(argv[2]);
        if ( rt == nullptr ) {
            ERROR("Couldn't load ruletable from file %s", argv[2]);
            return 1;
        }

        if ( load_ruletable(*rt, RULETABLE_INTERFACE_PATH) < 0 ) {
            ERROR("Couldn't load ruletable to server");
            return 1;
        }
    } else {
        print_usage(argv[0]);
    }

    return 0;
}

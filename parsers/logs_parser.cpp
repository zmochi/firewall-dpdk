#include "ruletable_parser.hpp"

#include "../endian.hpp"
#include "../logger.hpp"
#include "../packet.hpp"
#include "../ruletable.hpp"

#include <stdexcept>
#include <string>
#include <vector>

using field_pairings_t = std::vector<std::pair<const char *, int>>;
static field_pairings_t proto_converter = {
    {"tcp", TCP}, {"udp", UDP}, {"icmp", ICMP}, {"Unknown protocol", NUL_PROTO}};
static field_pairings_t action_converter = {{"accept", PKT_PASS},
                                            {"drop", PKT_DROP}};
static field_pairings_t reason_converter = {
    {"REASON_NO_MATCHING_RULE", REASON_NO_RULE},
    {"REASON_XMAS_PKT", REASON_XMAS_PKT},
    {"REASON_NONIPV4", REASON_NONIPV4},
    {"fmt_log error!!", REASON_RULE}, /* reason should be the rule idx */
    {"REASON_STATEFUL_INVALID", REASON_STATEFUL_INVALID},
    {"REASON_STATEFUL_CONN_EXISTS", REASON_STATEFUL_CONN_EXISTS},
	{"REASON_STATEFUL_RST", REASON_STATEFUL_RST},
};

const char *LOG_TXT_TITLE = "timestamp\t\tsrc_ip\t\tdst_ip\t\tsrc_port\t\tdst_"
                            "port\t\tprotocol\t\taction\t\treason\t\tcount";

std::string fmt_log(log_row_t log) {
    std::string log_txt;
    const char *DELIM = "\t\t";

    char     datetime[128];
    std::tm *time = std::localtime(&log.timestamp);
    std::strftime(datetime, sizeof(datetime), "%d/%m/%y %H:%M:%S", time);

    auto append_field = [DELIM](std::string &str, std::string field) {
        str.append(field);
        str.append(DELIM);
    };

    auto convert_field = [DELIM](field_pairings_t field_values, int entry) {
        for ( auto pair : field_values ) {
            if ( pair.second == entry ) {
                return pair.first;
            }
        }
        throw std::runtime_error(
            "No matching value found in field pairings list");
    };

    /* in order of the fields as appears in LOG_TXT_TITLE in header file */
    append_field(log_txt, datetime);
    append_field(log_txt, fmt_ipaddr(log.saddr, 0, false));
    append_field(log_txt, fmt_ipaddr(log.daddr, 0, false));
    append_field(log_txt, fmt_port(log.sport));
    append_field(log_txt, fmt_port(log.dport));
    append_field(log_txt, convert_field(proto_converter, log.protocol));
    append_field(log_txt, convert_field(action_converter, log.action));
    if ( log.reason == REASON_RULE ) {
        append_field(log_txt, std::to_string(log.reason_idx));
    } else {
        append_field(log_txt, convert_field(reason_converter, log.reason));
    }
    append_field(log_txt, std::to_string(log.count));
    /* remove trailing delimiter */
    for ( int i = 0; i < strlen(DELIM); i++ )
        log_txt.pop_back();

    return log_txt;
}

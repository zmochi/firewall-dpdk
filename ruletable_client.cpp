#include <memory>

#include "packet.hpp"
#include "ruletable.hpp"
#include "ruletable_client.hpp"
#include "ruletable_interface.hpp"
#include "simple_ipc.hpp"
#include "utils.h"

#include <cassert>
#include <climits>
#include <fstream>

constexpr auto   RULE_FIELD_DELIM = ' ';
constexpr auto   RULE_NB_FIELDS = 9;
constexpr be32_t IPADDR_ANY_MASK = 0x0000'0000;
constexpr be16_t PORT_ANY_MASK = 0x0000;

std::vector<std::pair<int, int>> parse_line(const char *rule, char field_delim,
                                            char field_end_char) {
    std::vector<std::pair<int, int>> field_indices;

    char cur_char;

    /* which field in rule we're looking at */
    int field_idx = 0;
    /* which char we're looking at */
    int ch_idx = 0;

    do {
        field_indices.at(field_idx).first = ch_idx;
        do {
            cur_char = rule[ch_idx++];
        } while ( cur_char != field_delim && cur_char != field_end_char );
        field_indices.at(field_idx).second = ch_idx;
        /* move to next field */
        field_idx++;
        /* move to first char of next field */
        ch_idx++;
    } while ( cur_char != field_end_char );

    return field_indices;
}

int parse_ipaddr(const std::string &ipaddr_str, be32_t *ipaddr_dest,
                 be32_t *ipaddr_dest_mask) {
    constexpr auto IP_NB_FIELDS = 4;
    be32_t         ipaddr_val = 0;
    /* variable to hold the intermediate values in range [0,255] */
    int ip_field_val;

    /* parse ip addr, until the / part */
    std::vector<std::pair<int, int>> field_indices =
        parse_line(ipaddr_str.data(), '.', '/');

    assert(field_indices.size() == IP_NB_FIELDS);
    for ( int i = 0; i < IP_NB_FIELDS; i++ ) {
        auto idx_pair = field_indices.at(i);

        ip_field_val = std::stoi(ipaddr_str.substr(
            idx_pair.first, idx_pair.second - idx_pair.first - 1));

        if ( !(0 <= ip_field_val && ip_field_val <= 255) ) {
            ERROR("IP address field is not in the range [0,255]");
            return -1;
        }

        /* big endian calculation */
        ipaddr_val += ip_field_val * (1 << i);
    }

    /* set ip address value, big endian */
    *ipaddr_dest = ipaddr_val;

    /* parse mask */
    std::pair<int, int> mask_idx_pair = {
        field_indices.at(field_indices.size() - 1).second + 1,
        ipaddr_str.size() - 1};

    assert(ipaddr_str.at(mask_idx_pair.first - 1) == '/');

    int mask_val =
        std::stoi(ipaddr_str.substr(mask_idx_pair.first, mask_idx_pair.second));

    if ( !(0 <= mask_val && mask_val <= 32) ) {
        ERROR("IP address mask not in range [0,32]");
        return -1;
    }

    if ( mask_val == 0 )
        *ipaddr_dest_mask = 0;
    else
        *ipaddr_dest_mask =
            (1 << (sizeof(be32_t) - 1) * CHAR_BIT) >> (mask_val - 1);

    return 0;
}
int parse_port(const std::string &port_str, be16_t *port_dest,
               be16_t *port_mask) {
    *port_mask = PORT_ANY_MASK;
    return std::stoi(port_str);
}

int parse_rule(const char *rule /* delimited by null byte */,
               rule_entry &rule_entry) {
    /* array holding start and end index of each field in rule array, end index
     * points at the delimiting space character */
    std::vector<std::pair<int, int>> field_indices =
        parse_line(rule, ' ', '\0');
    /* value for parse_field to return on "any" string when parsing */
    constexpr int ANY = 0x1;

    int name_field_idx = 1, direction_field_idx = 2, saddr_field_idx = 3,
        daddr_field_idx = 4, proto_field_idx = 5, sport_field_idx = 6,
        dport_field_idx = 7, ack_field_idx = 8, action_field_idx = 9;

    /* calculates len of a field, given a pair of start and end indices */
    auto field_len = [](std::pair<int, int> idx_pair) {
        return idx_pair.second - idx_pair.first - 1;
    };

    /* `list` is a list of pairs <expected string, value to return on string
     * match> */
    auto match_field =
        [&field_indices, field_len,
         &rule](int                                                 field_idx,
                std::initializer_list<std::pair<const char *, int>> list,
                int no_match_code) {
            std::pair idx = field_indices[field_idx];
            int       len = field_len(idx);
            for ( auto opt : list ) {
                if ( memcmp(&rule[idx.first], opt.first, strlen(opt.first)) ==
                     0 ) {
                    return opt.second;
                }
            }

            return no_match_code;
        };

    /* parse name */
    std::pair name_indices = field_indices[name_field_idx];
    int       name_len = field_len(name_indices);
    if ( name_len > rule_entry.name.size() ) {
        ERROR("Rule name `%.*s`... too long, maximum length is %d characters",
              RULE_NAME_MAXLEN, &rule[name_indices.first], RULE_NAME_MAXLEN);
        return -1;
    }
    memcpy(&rule_entry.name[name_field_idx], &rule[name_indices.first],
           name_len);

    std::string rule_name(&rule[name_indices.first], name_len);

    /* uninitialized field must have this value */
    assert(rule_entry.direction == NUL_DIRECTION);

    switch ( match_field(direction_field_idx,
                         {{"any", UNSPEC}, {"in", IN}, {"out", OUT}}, -1) ) {
        case IN:
            rule_entry.direction = IN;
            break;
        case OUT:
            rule_entry.direction = OUT;
            break;
        case UNSPEC:
            rule_entry.direction = UNSPEC;
            break;
        default:
            ERROR("In rule %s, field %*.s is unrecognized", rule_name.data(),
                  field_len(field_indices[direction_field_idx]),
                  &rule[field_indices[direction_field_idx].first]);
            return -1;
    }

    switch ( match_field(saddr_field_idx, {{"any", ANY}}, -1) ) {
        case ANY:
            rule_entry.saddr_mask = IPADDR_ANY_MASK;
            break;

        case -1:
            if ( parse_ipaddr(
                     std::string(&rule[field_indices[saddr_field_idx].first],
                                 field_len(field_indices[saddr_field_idx])),
                     &rule_entry.saddr, &rule_entry.saddr_mask) < 0 ) {
                ERROR("Couldn't parse destination port for rule %s",
                      rule_name.data());
                return -1;
            }
            break;
        default:
            ERROR("Source address field can't be recognized for rule %s",
                  rule_name.data());
            return -1;
    }

    switch ( match_field(daddr_field_idx, {{"any", ANY}}, -1) ) {
        case ANY:
            rule_entry.daddr_mask = IPADDR_ANY_MASK;
            break;

        case -1:
            if ( parse_ipaddr(
                     std::string(&rule[field_indices[daddr_field_idx].first],
                                 field_len(field_indices[daddr_field_idx])),
                     &rule_entry.daddr, &rule_entry.daddr_mask) < 0 ) {
                ERROR("Couldn't parse destination port for rule %s",
                      rule_name.data());
                return -1;
            }
            break;

        default:
            ERROR("Source address field can't be recognized for rule %s",
                  rule_name.data());
            return -1;
    }

    switch ( match_field(sport_field_idx, {{"any", ANY}}, -1) ) {
        case ANY:
            rule_entry.sport_mask = PORT_ANY_MASK;
            break;
        case -1:
            if ( parse_port(
                     std::string(&rule[field_indices[sport_field_idx].first],
                                 field_len(field_indices[sport_field_idx])),
                     &rule_entry.sport, &rule_entry.sport_mask) < 0 ) {
                ERROR("Couldn't parse destination port for rule %s",
                      rule_name.data());
                return -1;
            }
            break;
        default:
            ERROR("Source port field can't be recognized for rule %s",
                  rule_name.data());
            return -1;
    }

    switch ( match_field(dport_field_idx, {{"any", ANY}}, -1) ) {
        case ANY:
            rule_entry.dport_mask = PORT_ANY_MASK;
            break;
        case -1:
            if ( parse_port(
                     std::string(&rule[field_indices[dport_field_idx].first],
                                 field_len(field_indices[dport_field_idx])),
                     &rule_entry.dport, &rule_entry.dport_mask) < 0 ) {
                ERROR("Couldn't parse destination port for rule %s",
                      rule_name.data());
                return -1;
            }
            break;
        default:
            ERROR("Destination port field can't be recognized for rule %s",
                  rule_name.data());
            return -1;
    }

    switch ( match_field(ack_field_idx,
                         {{"any", ACK_ANY}, {"yes", ACK_YES}, {"no", ACK_NO}},
                         -1) ) {
        case ACK_ANY:
            rule_entry.ack = ACK_ANY;
            break;
        case ACK_YES:
            rule_entry.ack = ACK_YES;
            break;
        case ACK_NO:
            rule_entry.ack = ACK_NO;
            break;
        default:
            ERROR("Ack field can't be recognized for rule %s",
                  rule_name.data());
            return -1;
    }

    switch ( match_field(action_field_idx,
                         {{"accept", PKT_PASS}, {"drop", PKT_DROP}}, -1) ) {
        case PKT_PASS:
            rule_entry.action = PKT_PASS;
            break;
        case PKT_DROP:
            rule_entry.action = PKT_DROP;
            break;
        default:
            ERROR("Action field can't be recognized for rule %s",
                  rule_name.data());
            return -1;
    }

    return 0;
}

std::unique_ptr<ruletable>
load_ruletable_from_file(const std::string &filepath) {
    using namespace std;
    unique_ptr<ruletable> rt = make_unique<ruletable>();

    constexpr auto                 MAX_RULE_LINE_LEN = 1 << 9;
    array<char, MAX_RULE_LINE_LEN> rule_line;

    size_t   rule_line_len;
    size_t   line_idx = 0;
    ifstream ruletable_file(filepath, ios_base::in);
    while ( ruletable_file.getline(&rule_line[0], MAX_RULE_LINE_LEN) ) {
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

int load_ruletable(ruletable &rt, const std::string& ruletable_send_path) {

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

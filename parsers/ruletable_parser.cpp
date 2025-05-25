#include <memory>

#include <netinet/in.h>
#include "../endian.hpp"
#include "../packet.hpp"
#include "../ruletable.hpp"
#include "../utils.h"

#include <cassert>
#include <climits>
#include <cstring>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

constexpr auto   RULE_FIELD_DELIM = ' ';
constexpr auto   RULE_NB_FIELDS = 9;
constexpr be32_t IPADDR_ANY_MASK = 0x0000'0000;

/* helper function
 * calculates len of a field, given a pair of start and end indices */
static int field_len(std::pair<int, int> field_idx) {
    return field_idx.second - field_idx.first;
}

/* @brief parses a line according to a char that delimits each field (for
 * example space or tab) and a 'line end char' for example null byte or new
 * line.
 *
 * @return a list of pairs <start index, end index> where start index is the
 * index of the first char of the field, and end index is the index of the
 * field_delim right after that field */
static std::vector<std::pair<int, int>>
parse_line(const char *rule, char field_delim, char field_end_char) {
    std::vector<std::pair<int, int>> field_indices;

    char cur_char;

    /* which field in rule we're looking at */
    int field_idx = 0;
    /* which char we're looking at */
    int ch_idx = 0;

    do {
        field_indices.push_back({ch_idx, 0});
        do {
            cur_char = rule[ch_idx++];
        } while ( cur_char != field_delim && cur_char != field_end_char );
        field_indices.back().second = ch_idx - 1;
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
            idx_pair.first, idx_pair.second - idx_pair.first));

        if ( !(0 <= ip_field_val && ip_field_val <= 255) ) {
            ERROR("IP address field is not in the range [0,255]");
            return -1;
        }

        /* big endian calculation */
        ipaddr_val += ip_field_val * (1 << (i * 8)); /* =ip_field_val*(256^i) */
    }

    /* set ip address value, big endian */
    *ipaddr_dest = ipaddr_val;

    /* parse mask */
    std::pair<int, int> mask_idx_pair = {field_indices.back().second + 1,
                                         ipaddr_str.size()};

    assert(ipaddr_str.at(mask_idx_pair.first - 1) == '/');

    int mask_val = std::stoi(
        ipaddr_str.substr(mask_idx_pair.first, field_len(mask_idx_pair)));

    if ( !(0 <= mask_val && mask_val <= 32) ) {
        ERROR("IP address mask not in range [0,32]");
        return -1;
    }

    /* cast to uint64_t is needed, since the shift size could be 32, and
     * shifting by width of a type is UB */
    *ipaddr_dest_mask =
        htonl((be32_t)((~(uint64_t)0) << (sizeof(be32_t) * CHAR_BIT - mask_val)));

    return 0;
}
static int parse_port(const std::string &port_str, be16_t *port_dest,
                      be16_t *port_mask) {
    std::string str_to_parse;
    switch ( port_str.at(0) ) {
        case '<':
            *port_mask = PORT_LT;
            str_to_parse = port_str.substr(1, port_str.size() - 1);
            break;
        case '>':
            *port_mask = PORT_GT;
            str_to_parse = port_str.substr(1, port_str.size() - 1);
            break;
        case '0':
            [[fallthrough]];
        case '1':
            [[fallthrough]];
        case '2':
            [[fallthrough]];
        case '3':
            [[fallthrough]];
        case '4':
            [[fallthrough]];
        case '5':
            [[fallthrough]];
        case '6':
            [[fallthrough]];
        case '7':
            [[fallthrough]];
        case '8':
            [[fallthrough]];
        case '9':
            *port_mask = PORT_EQ;
            str_to_parse = port_str;
            break;
        default:
            ERROR("Unknown port format");
            return -1;
    }

    int    port_val = std::stoi(str_to_parse);
    be16_t PORT_MAX = 0xFFFFU;
    if ( port_val > PORT_MAX || port_val < 0 ) {
        ERROR("Port value too big or negative");
        return -1;
    }

    *port_dest = htons(port_val);
    return 0;
}

std::string fmt_ipaddr(be32_t ipaddr, uint32_t ipaddr_mask, bool add_mask) {
    const std::string DELIM = ".";
    std::string       ip_str;
    uint8_t          *ip_bytes = reinterpret_cast<uint8_t *>(&ipaddr);

    for ( int i = 0; i < 4; i++ ) {
        ip_str.append(std::to_string(ip_bytes[i]));
        ip_str.append(DELIM);
    }
    /* remove trailing delim */
    ip_str.pop_back();

    if ( !add_mask ) return ip_str;

    /* determine mask size based on ipaddr_mask, assuming mask is some sequence
     * of 1's followed by 0's only */
    int ipaddr_mask_val = -1;
    for ( int i = 0; i <= sizeof(ipaddr_mask) * CHAR_BIT; i++ ) {
        if ( (ipaddr_mask << i) == 0 || i == 32 ) {
            ipaddr_mask_val = i;
            break;
        }
    }

    if ( ipaddr_mask_val == -1 ) {
        ERROR("Couldn't determine mask of ipaddr %s", ip_str.data());
    }

    ip_str.append("/");
    ip_str.append(std::to_string(ipaddr_mask_val));

    return ip_str;
}

std::string fmt_port(be16_t port) {
    uint16_t port_le = ntohs(port);
    return std::to_string(port_le);
}

using field_pairings_t = std::initializer_list<std::pair<const char *, int>>;

static constexpr int    ANY = 0x1;
static field_pairings_t direction_converter = {
    {"any", UNSPEC}, {"in", IN}, {"out", OUT}};
static field_pairings_t saddr_converter = {{"any", ANY}};
static field_pairings_t sport_converter = {{"any", ANY}};
static field_pairings_t daddr_converter = {{"any", ANY}};
static field_pairings_t proto_converter = {
    {"any", PROTO_ANY}, {"TCP", TCP}, {"UDP", UDP}, {"ICMP", ICMP}};
static field_pairings_t dport_converter = {{"any", ANY}};
static field_pairings_t ack_converter = {
    {"any", ACK_ANY}, {"yes", ACK_YES}, {"no", ACK_NO}};
static field_pairings_t action_converter = {{"accept", PKT_PASS},
                                            {"drop", PKT_DROP}};

int fmt_rule(rule_entry rule, std::string &rule_txt) {
    // rule_txt.clear();
    const auto DELIM = " ";
    /* all rules have value widths < int, so `entry` is of type int */
    auto convert_field = [&rule_txt, DELIM](field_pairings_t field_values,
                                            int              entry) {
        for ( auto pair : field_values ) {
            if ( pair.second == entry ) {
                rule_txt.append(pair.first);
                rule_txt.append(DELIM);
                return;
            }
        }
    };

    auto append_ipaddr = [&rule_txt, convert_field, DELIM](be32_t ipaddr,
                                                           be32_t ipaddr_mask) {
        if ( ipaddr_mask == IPADDR_ANY_MASK )
            convert_field(saddr_converter, ANY);
        else {
            rule_txt.append(fmt_ipaddr(ipaddr, ipaddr_mask, true));
            rule_txt.append(DELIM);
        }
    };

    auto append_port = [&rule_txt, convert_field, DELIM](be16_t port,
                                                         be16_t port_mask) {
        std::string port_str = fmt_port(port);
        switch ( port_mask ) {
            case PORT_ANY:
                convert_field(sport_converter, ANY);
                break;
            case PORT_LT:
                rule_txt.append("<");
                rule_txt.append(port_str);
                rule_txt.append(DELIM);
                break;
            case PORT_GT:
                rule_txt.append(">");
                rule_txt.append(port_str);
                rule_txt.append(DELIM);
                break;
            case PORT_EQ:
                rule_txt.append(port_str);
                rule_txt.append(DELIM);
                break;
            default:
                ERROR("Unknown value for port_mask");
        }
    };

    /* must be ordered according to order of rules in rule string */
    rule_txt.append(static_cast<const char *>(rule.name.data()));
    rule_txt.append(DELIM);
    convert_field(direction_converter, rule.direction);
    append_ipaddr(rule.saddr, rule.saddr_mask);
    append_ipaddr(rule.daddr, rule.daddr_mask);
    convert_field(proto_converter, rule.proto);
    append_port(rule.sport, rule.sport_mask);
    append_port(rule.dport, rule.dport_mask);
    convert_field(ack_converter, rule.ack);
    convert_field(action_converter, rule.action);
    /* replace last ' ' with a newline */
    rule_txt.pop_back();

    return 0;
}

int parse_rule(const char *rule /* delimited by null byte */,
               rule_entry &rule_entry) {
    /* array holding start and end index of each field in rule array, end index
     * points at the delimiting space character */
    std::vector<std::pair<int, int>> field_indices =
        parse_line(rule, ' ', '\0');
    /* value for parse_field to return on "any" string when parsing */

    int name_field_idx = 0, direction_field_idx = 1, saddr_field_idx = 2,
        daddr_field_idx = 3, proto_field_idx = 4, sport_field_idx = 5,
        dport_field_idx = 6, ack_field_idx = 7, action_field_idx = 8;

    /* `list` is a list of pairs <expected string, value to return on string
     * match> */
    auto match_field =
        [&field_indices,
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
    if ( name_len >
         rule_entry.name.size() - 1 /* -1 save space for nul byte*/ ) {
        ERROR("Rule name `%.*s`... too long, maximum length is %d characters",
              RULE_NAME_MAXLEN, &rule[name_indices.first], RULE_NAME_MAXLEN);
        return -1;
    }
    memcpy(rule_entry.name.data(), &rule[name_indices.first], name_len);
    rule_entry.name[name_indices.second] = '\0';

    std::string rule_name(&rule[name_indices.first], name_len);

    /* uninitialized field must have this value */
    assert(rule_entry.direction == NUL_DIRECTION);

    switch ( match_field(direction_field_idx, direction_converter, -1) ) {
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

    switch ( match_field(saddr_field_idx, saddr_converter, -1) ) {
        case ANY:
            rule_entry.saddr_mask = IPADDR_ANY_MASK;
            break;

        case -1:
            if ( parse_ipaddr(
                     std::string(&rule[field_indices[saddr_field_idx].first],
                                 field_len(field_indices[saddr_field_idx])),
                     &rule_entry.saddr, &rule_entry.saddr_mask) < 0 ) {
                ERROR("Couldn't parse source IP address for rule %s",
                      rule_name.data());
                return -1;
            }
            break;
        default:
            ERROR("Source address field can't be recognized for rule %s",
                  rule_name.data());
            return -1;
    }

    switch ( match_field(daddr_field_idx, daddr_converter, -1) ) {
        case ANY:
            rule_entry.daddr_mask = IPADDR_ANY_MASK;
            break;

        case -1:
            if ( parse_ipaddr(
                     std::string(&rule[field_indices[daddr_field_idx].first],
                                 field_len(field_indices[daddr_field_idx])),
                     &rule_entry.daddr, &rule_entry.daddr_mask) < 0 ) {
                ERROR("Couldn't parse destination IP address for rule %s",
                      rule_name.data());
                return -1;
            }
            break;

        default:
            ERROR("Destination address field can't be recognized for rule %s",
                  rule_name.data());
            return -1;
    }

    switch ( match_field(proto_field_idx, proto_converter, -1) ) {
        case PROTO_ANY:
            rule_entry.proto = PROTO_ANY;
            break;
        case TCP:
            rule_entry.proto = TCP;
            break;
        case UDP:
            rule_entry.proto = UDP;
            break;
        case ICMP:
            rule_entry.proto = ICMP;
            break;
        default:
            ERROR("Protocol field can't be recognized for rule %s",
                  rule_name.data());
            return -1;
    }

    switch ( match_field(sport_field_idx, sport_converter, -1) ) {
        case ANY:
            rule_entry.sport_mask = PORT_ANY;
            break;
        case -1:
            static_assert(sizeof(rule_entry.sport_mask) == sizeof(be16_t));
            if ( parse_port(
                     std::string(&rule[field_indices[sport_field_idx].first],
                                 field_len(field_indices[sport_field_idx])),
                     &rule_entry.sport,
                     (be16_t *)&rule_entry.sport_mask) < 0 ) {
                ERROR("Couldn't parse source port for rule %s",
                      rule_name.data());
                return -1;
            }
            break;
        default:
            ERROR("Source port field can't be recognized for rule %s",
                  rule_name.data());
            return -1;
    }

    switch ( match_field(dport_field_idx, dport_converter, -1) ) {
        case ANY:
            rule_entry.dport_mask = PORT_ANY;
            break;
        case -1:
            static_assert(sizeof(rule_entry.dport_mask) == sizeof(be16_t));
            if ( parse_port(
                     std::string(&rule[field_indices[dport_field_idx].first],
                                 field_len(field_indices[dport_field_idx])),
                     &rule_entry.dport,
                     (be16_t *)&rule_entry.dport_mask) < 0 ) {
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

    switch ( match_field(ack_field_idx, ack_converter, -1) ) {
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

    switch ( match_field(action_field_idx, action_converter, -1) ) {
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

static int parse_line_test() {
    const std::string line1 = "one two three/ff";

    auto line_indices = parse_line(line1.c_str(), ' ', '/');
    assert(line_indices.size() == 3);
    assert(line1.substr(line_indices.at(0).first,
                        field_len(line_indices.at(0))) == "one");
    assert(line1.substr(line_indices.at(1).first,
                        field_len(line_indices.at(1))) == "two");
    assert(line1.substr(line_indices.at(2).first,
                        field_len(line_indices.at(2))) == "three");

    std::cout << "Line parsing test successful" << std::endl;
    return 0;
}

static int parse_ipaddr_test() {
    const std::string ipaddr_1 = "1.2.3.4/32";
    const std::string ipaddr_2 = "1.2.3.4/0";

    be32_t ipaddr_dest, ipaddr_mask;
    if ( parse_ipaddr(ipaddr_1, &ipaddr_dest, &ipaddr_mask) < 0 ) {
        ERROR("Couldn't parse IP address");
        return -1;
    }
    assert(ipaddr_dest == 1 + 2 * 256 + 3 * 256 * 256 + 4 * 256 * 256 * 256);
    assert(ipaddr_mask == 0xFFFF'FFFFU);

    if ( parse_ipaddr(ipaddr_2, &ipaddr_dest, &ipaddr_mask) < 0 ) {
        ERROR("Couldn't parse IP address");
        return -1;
    }

    assert(ipaddr_dest == 1 + 2 * 256 + 3 * 256 * 256 + 4 * 256 * 256 * 256);
    assert(ipaddr_mask == 0);

    std::cout << "IP address parse test successful" << std::endl;
    return 0;
}

static int parse_rule_test() {
    const std::string rule1_input =
        "loopback any 127.0.0.1/8 127.255.2.1/32 any any any any accept";
    const std::string rule2_input =
        "telnet2 in 0.0.0.0/0 10.0.1.1/24 TCP 23 >1023 yes accept";
    rule_entry rule1_output;
    rule_entry rule2_output;

    if ( parse_rule(rule1_input.c_str(), rule1_output) < 0 ) {
        ERROR("Error parsing rule 1");
        return -1;
    }

    if ( parse_rule(rule2_input.c_str(), rule2_output) < 0 ) {
        ERROR("Error parsing rule 2");
        return -1;
    }

    assert(std::string(rule1_output.name.data()) == std::string("loopback"));
    assert(rule1_output.direction == UNSPEC);
    assert(rule1_output.saddr ==
           127 + 0 * 256 + 0 * 256 * 256 + 1 * 256 * 256 * 256);
    assert(rule1_output.saddr_mask == 0b11111111000000000000000000000000);
    assert(rule1_output.daddr ==
           127 + 255 * 256 + 2 * 256 * 256 + 1 * 256 * 256 * 256);
    assert(rule1_output.daddr_mask == 0xFFFF'FFFFU);
    assert(rule1_output.proto == PROTO_ANY);
    /* when port is `any`, sport/dport fields isn't assigned */
    assert(rule1_output.sport_mask == PORT_ANY);
    assert(rule1_output.dport_mask == PORT_ANY);
    assert(rule1_output.action == PKT_PASS);

    assert(std::string(rule2_output.name.data()) == std::string("telnet2"));
    assert(rule2_output.direction == IN);
    assert(rule2_output.saddr_mask == 0);
    assert(rule2_output.daddr_mask == 0b11111111111111111111111100000000);
    assert(rule2_output.proto == TCP);
    assert(rule2_output.sport_mask == PORT_EQ);
    assert(rule2_output.dport_mask == PORT_GT);
    assert(rule2_output.action == PKT_PASS);

    std::cout << "Rule parse test successful" << std::endl;
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

#include <memory>

#include "../ruletable.hpp"

std::string fmt_ipaddr(be32_t ipaddr, uint32_t ipaddr_mask, bool add_mask);
std::string fmt_port(be16_t port);
std::unique_ptr<ruletable>
    load_ruletable_from_file(const std::string &filepath);
int parse_rule(const char *rule /* delimited by null byte */,
               rule_entry &rule_entry);
int fmt_rule(rule_entry rule, std::string &rule_txt);

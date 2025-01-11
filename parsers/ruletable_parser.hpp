#include "../ruletable.hpp"

int parse_rule(const char *rule /* delimited by null byte */,
                      rule_entry &rule_entry);
int fmt_rule(rule_entry rule, std::string &rule_txt);

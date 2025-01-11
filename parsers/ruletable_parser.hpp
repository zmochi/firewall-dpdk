#include <memory>

#include "../ruletable.hpp"

std::unique_ptr<ruletable>
load_ruletable_from_file(const std::string &filepath);
int parse_rule(const char *rule /* delimited by null byte */,
                      rule_entry &rule_entry);
int fmt_rule(rule_entry rule, std::string &rule_txt);

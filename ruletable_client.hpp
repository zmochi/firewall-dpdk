#ifndef __RULETABLE_CLIENT_H
#define __RULETABLE_CLIENT_H

#include <memory>
#include "ruletable.hpp"

int load_ruletable(ruletable &rt, const std::string rt_interface_path);
int show_ruletable(ruletable &rt, const std::string rt_interface_path);
std::unique_ptr<ruletable>
load_ruletable_from_file(const std::string &filepath);
int fmt_rule(rule_entry rule, std::string &rule_txt);

#endif /* __RULETABLE_CLIENT_H */

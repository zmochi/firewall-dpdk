#ifndef __RULETABLE_CLIENT_H
#define __RULETABLE_CLIENT_H

#include <memory>
#include "ruletable.hpp"

std::unique_ptr<ruletable>
load_ruletable_from_file(const std::string& filepath);
int load_ruletable(ruletable &rt, const std::string& ruletable_send_path);

#endif /* __RULETABLE_CLIENT_H */

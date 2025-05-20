#include "endian.hpp"
#include <string>

// impl in ruletable_parser.cpp
int         parse_ipaddr(const std::string &ipaddr_str, be32_t *ipaddr_dest,
                         be32_t *ipaddr_dest_mask);

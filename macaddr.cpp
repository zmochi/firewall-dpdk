#include "macaddr.hpp"
#include "utils.h"
#include <cstring>
#include <string>
#include <string_view>

bool MAC_addr::operator==(const MAC_addr &other) {
    for ( int i = 0; i < MAC_ADDR_LEN; i++ )
        if ( addr_bytes.at(i) != other.addr_bytes.at(i) ) return false;

    return true;
}

int parse_mac_addr(std::string_view mac_addr, MAC_addr &maddr) {
    const auto MAC_ADDR_FMT_LEN = strlen("01:23:45:67:89:AB");
    if ( mac_addr.size() != MAC_ADDR_FMT_LEN ) return -1;
    int maddr_byte_idx = 0;

    for ( int i = 0; i < MAC_ADDR_FMT_LEN; i += 3 /* skips separator : */ ) {
        uint8_t &maddr_byte = maddr.addr_bytes.at(maddr_byte_idx++);
        for ( int j = i; j < i + 2; j++ ) {
            if ( '0' <= mac_addr.at(j) && mac_addr.at(j) <= '9' )
                maddr_byte += mac_addr.at(j) - '0';

            else if ( 'A' <= mac_addr.at(j) && 'F' <= mac_addr.at(j) )
                maddr_byte += mac_addr.at(j) - 'A' + 10;

            else if ( 'a' <= mac_addr.at(j) && 'f' <= mac_addr.at(j) )
                maddr_byte += mac_addr.at(j) - 'a' + 10;

            else {
                ERROR("Bad MAC addr character at index %d", j);
                return -1;
            }
        }
    }

    return 0;
}

#include <cassert>

void test_parse_mac_addr() {
    std::array<std::pair<std::string, MAC_addr>, 3> testcases{{
        {"01:23:45:67:89:AB", MAC_addr(0x01, 0x23, 0x45, 0x67, 0x89, 0xAB)},
        {"01:23:45:67:89:ab", MAC_addr(0x01, 0x23, 0x45, 0x67, 0x89, 0xAB)},
        {"AB:CD:EF:AB:01:99", MAC_addr(0xAB, 0xCD, 0xEF, 0xAB, 0x01, 0x99)},
    }};

    MAC_addr maddr;
    for ( auto pair : testcases ) {
        parse_mac_addr(pair.first, maddr);
        assert(maddr == pair.second);
    }
}

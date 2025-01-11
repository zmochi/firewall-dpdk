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
    if ( mac_addr.size() != MAC_ADDR_FMT_LEN ) {
        ERROR("Passed mac address with length %zu, expected length %zu",
              mac_addr.size(), MAC_ADDR_FMT_LEN);
        return -1;
    }
    int maddr_byte_idx = 0;

    /* example: given "AB", the value of A is value('A')=`'A' - 'A' + 10` where
     * 'A' is the value of the char `A`. similarly B has value value('B')=`'B' -
     * 'A' + 10`. A has order 1 and 'B' has order 0, so multiply A by 16 to get
     * its value and multiply B by 1 to get its value. */
    auto calc_digit_val = [](char digit, char base, char offset, int order,
                             int digit_base) {
        char value = digit - base + offset;
        /* value = value*(digit_base^order). */
        for ( int i = 0; i < order; i++ )
            value *= digit_base;

        return value;
    };

    for ( int i = 0; i < MAC_ADDR_FMT_LEN; i += 3 /* skips separator : */ ) {
        uint8_t &maddr_byte = maddr.addr_bytes.at(maddr_byte_idx++);
        maddr_byte = 0;

        for ( int j = i; j < i + 2; j++ ) {
            char str_byte = mac_addr.at(j);

            if ( '0' <= str_byte && str_byte <= '9' )
                maddr_byte += calc_digit_val(str_byte, '0', 0, i + 1 - j, 16);

            else if ( 'A' <= str_byte && str_byte <= 'F' )
                maddr_byte += calc_digit_val(str_byte, 'A', 10, i + 1 - j, 16);

            else if ( 'a' <= str_byte && str_byte <= 'f' )
                maddr_byte += calc_digit_val(str_byte, 'a', 10, i + 1 - j, 16);

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
    std::array<std::pair<std::string, MAC_addr>, 4> testcases{{
        {"01:23:45:67:89:AB", MAC_addr(0x01, 0x23, 0x45, 0x67, 0x89, 0xAB)},
        {"01:23:45:67:89:ab", MAC_addr(0x01, 0x23, 0x45, 0x67, 0x89, 0xAB)},
        {"AB:CD:EF:AB:01:99", MAC_addr(0xAB, 0xCD, 0xEF, 0xAB, 0x01, 0x99)},
		{"7a:db:a5:08:d3:9c", MAC_addr(0x7a, 0xdb, 0xa5, 0x08, 0xd3, 0x9c)},
    }};

    MAC_addr maddr;
    for ( auto pair : testcases ) {
        parse_mac_addr(pair.first, maddr);
        assert(maddr == pair.second);
    }
}

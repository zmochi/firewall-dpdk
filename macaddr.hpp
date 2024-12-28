#ifndef __MACADDR_H
#define __MACADDR_H

#include <array>
#include <cstdint>
#include <string_view>

#define MAC_ADDR_LEN 6

struct MAC_addr {
	std::array<uint8_t, MAC_ADDR_LEN> addr_bytes;

	MAC_addr() {}

	MAC_addr(uint8_t byte1, uint8_t byte2, uint8_t byte3, uint8_t byte4, uint8_t byte5, uint8_t byte6) : addr_bytes{byte1, byte2, byte3, byte4, byte5, byte6} {}

	bool operator==(const MAC_addr& other);
};

int parse_mac_addr(std::string_view mac_addr, MAC_addr &maddr);
void test_parse_mac_addr();

#endif /* __MACADDR_H */

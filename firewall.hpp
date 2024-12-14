extern "C" {

#include <stdint.h>

#define MAC_ADDR_LEN 6

struct MAC_addr {
  uint8_t addr_bytes[MAC_ADDR_LEN];
};

int start_firewall(int argc, char **argv, struct ruletable *ruletable,
                   MAC_addr in_mac, MAC_addr out_mac, int log_write_fd);

} /* extern C */

#include <stdint.h>

typedef enum {
	PKT_PASS,
	PKT_DROP,
	PKT_ERR,
} pkt_dc;

typedef enum : uint8_t {
	TCP,
	UDP,
	ICMP,
} proto;

typedef enum : uint8_t {
	IN,
	OUT,
	ANY,
} direction;

struct pkt_props {
	direction direction;
	uint32_t saddr;
	uint32_t daddr;
	proto proto;
	uint16_t sport;
	uint16_t dport;
	uint8_t ack;
};


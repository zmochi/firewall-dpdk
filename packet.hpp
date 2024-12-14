#ifndef __PKT_H
#define __PKT_H

#include <netinet/in.h>
#include <stdint.h>

typedef enum : uint8_t {
	TCP = IPPROTO_TCP,
	UDP = IPPROTO_UDP,
	ICMP = IPPROTO_ICMP,
} proto;

typedef enum : uint8_t {
	IN,
	OUT,
	ANY,
} direction;

typedef enum {
	PKT_PASS,
	PKT_DROP,
	PKT_ERR,
} pkt_dc;

enum tcp_flags : uint64_t {
	/* copied from DPDK's rte_tcp.h */
	TCP_CWR_FLAG = 0x80, /**< Congestion Window Reduced */
	TCP_ECE_FLAG = 0x40, /**< ECN-Echo */
	TCP_URG_FLAG = 0x20, /**< Urgent Pointer field significant */
	TCP_ACK_FLAG = 0x10, /**< Acknowledgment field significant */
	TCP_PSH_FLAG = 0x08, /**< Push Function */
	TCP_RST_FLAG = 0x04, /**< Reset the connection */
	TCP_SYN_FLAG = 0x02, /**< Synchronize sequence numbers */
	TCP_FIN_FLAG = 0x01, /**< No more data from sender */
};

struct pkt_props {
	uint32_t saddr;
	uint32_t daddr;
	proto proto;
	uint16_t sport;
	uint16_t dport;
	enum tcp_flags tcp_flags;
};

#endif /* __PKT_H */

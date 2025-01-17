#ifndef __PKT_H
#define __PKT_H

#include <netinet/in.h>
#include <stdint.h>

#include "endian.hpp"

enum proto : uint8_t {
    TCP = IPPROTO_TCP,
    UDP = IPPROTO_UDP,
    ICMP = IPPROTO_ICMP,
    PROTO_ANY = 0x02,
    NUL_PROTO = 0xFF,
};

static_assert(__BYTE_ORDER == __LITTLE_ENDIAN);
enum eth_proto : be16_t {
    ETHTYPE_IPV4 = 0x0008, /* 0x0800 in big endian */
    ETHTYPE_IPV6 = 0x0608, /* 0x0806 in big endian */
    ETHTYPE_ARP = 0xDD86,  /* 0x86DD in big endian */
};

enum direction : uint8_t {
    IN = 0x01,
    OUT = 0x02,
    UNSPEC = 0x04,
    NUL_DIRECTION = 0x08,
};

enum pkt_dc {
    PKT_PASS = 0x01,
    PKT_DROP = 0x02,
    PKT_ERR = 0x04,
};

enum tcp_flags : uint8_t {
    /* copied from DPDK's rte_tcp.h */
    TCP_CWR_FLAG = 0x80, /**< Congestion Window Reduced */
    TCP_ECE_FLAG = 0x40, /**< ECN-Echo */
    TCP_URG_FLAG = 0x20, /**< Urgent Pointer field significant */
    TCP_ACK_FLAG = 0x10, /**< Acknowledgment field significant */
    TCP_PSH_FLAG = 0x08, /**< Push Function */
    TCP_RST_FLAG = 0x04, /**< Reset the connection */
    TCP_SYN_FLAG = 0x02, /**< Synchronize sequence numbers */
    TCP_FIN_FLAG = 0x01, /**< No more data from sender */
    TCP_NUL_FLAG = 0x00,
};

struct pkt_props {
    direction direction;
    be32_t  saddr;
    be32_t  daddr;
    proto     proto;
    eth_proto eth_proto;
    be16_t  sport;
    be16_t  dport;
    tcp_flags tcp_flags;

    pkt_props()
        : tcp_flags(TCP_NUL_FLAG), direction(NUL_DIRECTION), proto(NUL_PROTO) {}

    pkt_props(::proto proto, be32_t saddr, be32_t daddr, be16_t sport,
              be16_t dport, enum tcp_flags tcp_flags)
        : proto(proto), saddr(saddr), daddr(daddr), sport(sport), dport(dport),
          tcp_flags(tcp_flags) {}
};

#endif /* __PKT_H */

#include <lwip/api.h>
#include <lwip/netif.h>
#include <lwip/pbuf.h>
#include <lwip/prot/tcp.h>
#include <lwip/sockets.h>
#include <lwip/tcp.h>
#include <lwip/tcpip.h>

#include <stdexcept>
#include <string.h>

#include "lwip/etharp.h"
#include "lwip/inet_chksum.h"
#include "lwip/prot/etharp.h"
#include "lwip/prot/ethernet.h"
#include "setup.hpp"

#ifdef CONN_TABLE_LOGGING
#define LOG(fmt, ...)                                                          \
    do {                                                                       \
        printf("LOG: %s: " fmt "\n", __func__, ##__VA_ARGS__);                 \
    } while ( 0 )
#define ERROR(fmt, ...)                                                        \
    do {                                                                       \
        fprintf(stderr, "ERROR: %s: " fmt "\n", __func__, ##__VA_ARGS__);      \
    } while ( 0 )
#else
#define LOG(x, ...)   (void)0
#define ERROR(x, ...) (void)0
#endif

int MITM::socket() { return lwip_socket(AF_INET, SOCK_STREAM, 0); }

int MITM::make_socket_nonblocking(int sock) {
    auto opt = lwip_fcntl(sock, F_GETFL, 0);
    if ( opt & O_NONBLOCK ) {
        return 0;
    }
    return lwip_fcntl(sock, F_SETFL, opt | O_NONBLOCK);
}

int MITM::getsockopt_SOLSOCKET_SOERROR(int s, int level, int optname,
                                       void *optval, socklen_t *optlen) {
    return lwip_getsockopt(s, SOL_SOCKET, SO_ERROR, optval, optlen);
}

int MITM::setsockopt_SOLSOCKET_SOLINGER(int s, int level, int optname,
                                        const void  *optval,
                                        unsigned int optlen) {
    return lwip_setsockopt(s, SOL_SOCKET, SO_LINGER, optval, optlen);
}

int MITM::getsockname(int socket, struct sockaddr *addr,
                      unsigned int *addr_len) {
    return lwip_getsockname(socket, addr, addr_len);
}

#include <iostream>
int MITM::bind(int socket, uint16_t port) {
    err_t              err;
    int                yes = 1;
    struct sockaddr_in local = {.sin_family = AF_INET,
                                .sin_port = PP_HTONS(port),
                                .sin_addr = {.s_addr = PP_HTONL(INADDR_ANY)}};
    if ( lwip_setsockopt(socket, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) <
         0 )
        throw std::runtime_error("lwip_setsockopt()");

    return lwip_bind(socket, (struct sockaddr *)&local, sizeof(local));
}

int MITM::listen(int socket, uint8_t backlog) {
    auto ret = lwip_listen(socket, backlog);
    std::cout << "listen returned err = " << (int)ret << std::endl;
    return ret;
}

int MITM::accept(int listen_socket, struct sockaddr *addr,
                 socklen_t *addrsize) {
    return lwip_accept(listen_socket, addr, addrsize);
}

int MITM::close(int socket) { return lwip_close(socket); }

int MITM::shutdown(int socket, bool ingress, bool egress) {
    int how = 0;
    if ( ingress ) how = SHUT_RD;
    if ( egress ) how = SHUT_WR;
    if ( ingress && egress ) how = SHUT_RDWR;
    return lwip_shutdown(socket, how);
}

// buffer points to where data should be copied, buf_cap holds buffer capacity
ssize_t MITM::recv(int socket, char *buffer, size_t buf_cap) {
    return lwip_recv(socket, buffer, buf_cap, 0);
}

int MITM::poll(struct pollfd *fds, nfds_t nfds, int timeout) {
    return lwip_poll(fds, nfds, timeout);
}

int MITM::connect(int socket, struct sockaddr *name, socklen_t name_len) {
    return lwip_connect(socket, name, name_len);
}

ssize_t MITM::send(int socket, char *src, size_t len) {
    return lwip_send(socket, src, len, 0);
}

static uint8_t get_ipv4hdr_size(ip_hdr *iphdr) {
    return (iphdr->_v_hl & 0x0F) * 4;
}

static void *get_ipv4hdr_data(ip_hdr *iphdr) {
    uint8_t ipv4hdr_size = get_ipv4hdr_size(iphdr);
    if ( ipv4hdr_size < 20 || ipv4hdr_size > 60 ) {
        return nullptr;
    }

    return (char *)iphdr + ipv4hdr_size;
}

/* outdated - needs to be fixed. inet_chksum_pseudo calculates over a chain of
 * pbufs pointing to IP header apparently? */
static void fix_tcp_checksum(struct pbuf *p, ip_hdr *iphdr) {
    struct pbuf tcp_pbuf = *p;
    pbuf_remove_header(&tcp_pbuf, sizeof(eth_hdr));
    if ( tcp_pbuf.payload != iphdr )
        throw std::runtime_error("p->payload != iphdr, assumption broken");

    pbuf_remove_header(&tcp_pbuf, sizeof(ip_hdr));
    const ip4_addr_t src = {.addr = iphdr->src.addr};
    const ip4_addr_t dest = {.addr = iphdr->dest.addr};

    tcp_hdr *tcphdr = static_cast<tcp_hdr *>(get_ipv4hdr_data(iphdr));
    tcphdr->chksum = 0;
    tcphdr->chksum = inet_chksum_pseudo(&tcp_pbuf, IPPROTO_TCP,
                                        tcp_pbuf.tot_len, &src, &dest);
}

static uint16_t calc_ipv4_checksum(ip_hdr *iphdr) {
    return inet_chksum(iphdr, IPH_HL_BYTES(iphdr));
}

static void fix_ipv4_checksum(ip_hdr *iphdr) {
    IPH_CHKSUM_SET(iphdr, 0);
    IPH_CHKSUM_SET(iphdr, calc_ipv4_checksum(iphdr));
}

err_t outgoing_hook(netif *netif, pbuf *p, const ip4_addr_t *ip_dest) {
    if ( netif == nullptr ) throw std::runtime_error("netif is null");
    if ( p == nullptr ) throw std::runtime_error("pbuf is null");
    MITM    &instance = *((MITM *)netif->state);
    eth_hdr *eth_frame = (eth_hdr *)p->payload;

    LOG("%s: dest:%" X8_F ":%" X8_F ":%" X8_F ":%" X8_F ":%" X8_F ":%" X8_F
        ", src:%" X8_F ":%" X8_F ":%" X8_F ":%" X8_F ":%" X8_F ":%" X8_F
        ", type:%" X16_F "\n",
        __func__, (unsigned char)eth_frame->dest.addr[0],
        (unsigned char)eth_frame->dest.addr[1],
        (unsigned char)eth_frame->dest.addr[2],
        (unsigned char)eth_frame->dest.addr[3],
        (unsigned char)eth_frame->dest.addr[4],
        (unsigned char)eth_frame->dest.addr[5],
        (unsigned char)eth_frame->src.addr[0],
        (unsigned char)eth_frame->src.addr[1],
        (unsigned char)eth_frame->src.addr[2],
        (unsigned char)eth_frame->src.addr[3],
        (unsigned char)eth_frame->src.addr[4],
        (unsigned char)eth_frame->src.addr[5], lwip_htons(eth_frame->type));
    if ( eth_frame->type != PP_HTONS(ETHTYPE_ARP) ) {
        ip_hdr *iphdr = (ip_hdr *)((char *)eth_frame + sizeof(*eth_frame));

        if ( IPH_V(iphdr) != 4 ) {
            throw std::runtime_error("passed non IPv4 pbuf?");
        }

        if ( IPH_PROTO(iphdr) != 6 ) {
            throw std::runtime_error("passed non TCP datagram?");
        }

        const ip4_addr_t src = {.addr = iphdr->src.addr};
        const ip4_addr_t dest = {.addr = iphdr->dest.addr};

        tcp_hdr *pbuf_tcphdr = static_cast<tcp_hdr *>(get_ipv4hdr_data(iphdr));
        auto    *conn =
            instance.lookup_conn(iphdr->dest.addr, 0, pbuf_tcphdr->dest, 0);
        if ( conn == nullptr ) {
            throw std::runtime_error("conn is nullptr");
        }
        // case for traffic to internal side, tuple (mitm_ip, dest_port, src_ip,
        // src_port)
        if ( conn->src_ip == iphdr->dest.addr &&
             conn->src_port == pbuf_tcphdr->dest ) {
            iphdr->src.addr = conn->dest_ip;
        }
        // case for traffic to external side, tuple (mitm_ip, mitm_ext_port,
        // dest_ip, dest_port)
        else if ( conn->dest_ip == iphdr->dest.addr &&
                  conn->dest_port == pbuf_tcphdr->dest ) {
            conn->MITM_ext_port = pbuf_tcphdr->src;
            iphdr->src.addr = conn->src_ip;
            pbuf_tcphdr->src = conn->src_port;
        }
        fix_tcp_checksum(p, iphdr);
        fix_ipv4_checksum(iphdr);
    }

    // copy p->payload to new buffer and enqueue to send
    instance.outgoing_queue.emplace((char *)p->payload, p->len);

    return ERR_OK;
}

err_t linkoutput(netif *netif, pbuf *p) {
    return outgoing_hook(netif, p, nullptr);
}

// note: network byte order
#define IP4(a, b, c, d) PP_HTONL(LWIP_MAKEU32(a, b, c, d))

err_t netif_init_func(struct netif *netif) { return ERR_OK; }

MITM::MITM()
    : netif(new struct netif), netif_ip(IP4(8, 8, 8, 8)),
      netif_netmask(IP4(0, 0, 0, 0)) {
    // MITM is singleton since (currently) 127.0.0.1 is assigned statically, but
    // we can't have 2 netif's with the same IP address. also possible issue
    // with xxxx_init() being called multiple times.
    tcpip_init(nullptr, nullptr);
    pbuf_init();
    netif_init();

    LOCK_TCPIP_CORE();
    if ( netif_add(netif.get(), (ip4_addr *)&netif_ip,
                   (ip4_addr *)&netif_netmask, nullptr, this, netif_init_func,
                   tcpip_input) == nullptr ) {
        throw std::runtime_error("main: netif_add error");
    }

    netif->output = etharp_output;
    netif->linkoutput = linkoutput;
    netif->flags |= NETIF_FLAG_ETHARP;
    netif->hwaddr_len = ETHARP_HWADDR_LEN;
    netif->hwaddr[0] = 0xFE;
    netif->hwaddr[1] = 0x45;
    netif->hwaddr[2] = 0x4F;
    netif->hwaddr[3] = 0x3D;
    netif->hwaddr[4] = 0xB5;
    netif->hwaddr[5] = 0x3C;
    netif->mtu = 1500;
    netif_set_default(netif.get());
    netif_set_link_up(netif.get());
    netif_set_up(netif.get());
    UNLOCK_TCPIP_CORE();
}

MITM::~MITM() {
    netif_set_down(netif.get());
    netif_remove(netif.get());
    delete netif.release();
}

/*
 * each connection has 3 conntable entries, with tuples:
 * (src_ip, src_port, 0, 0) - lookup with src ip and src port only
 * (outgoing packet from MITM tcp stack, directed in to firewall).
 * (dest_ip, dest_port, 0, 0) - lookup with dest ip and dest port only
 * (outgoing packet from MITM tcp stack, directed out of firewall).
 * (src_ip, src_port, dest_ip, dest_port) - for lookup of MITM ingress packets.
 *
 * connection table entries are symmetric, i.e
 * lookup(src_ip, src_port, dest_ip, dest_port) = lookup(dest_ip, dest_port,
 * src_ip, src_port) so ingress packets from both internal and external sides of
 * firewall will be equivalent on lookup
 */
void MITM::new_conn(uint32_t src_ip, uint32_t dest_ip, uint16_t src_port,
                    uint16_t dest_port) {
    LOG("adding entry: src_ip = %u, dest_ip = %u, src_port = %d, dest_port = "
        "%d",
        src_ip, dest_ip, src_port, dest_port);
    auto entry1 = conn_table_entry(src_ip, 0, src_port, 0);
    auto entry2 = conn_table_entry(dest_ip, 0, dest_port, 0);
    auto entry3 = conn_table_entry(src_ip, dest_ip, src_port, dest_port);
    conntable.add_entry(entry3);
    assert(conntable.lookup_entry(entry3) != nullptr);
    conntable.lookup_entry(entry3)->user_arg =
        new MITM_conn_data{.src_ip = src_ip,
                           .dest_ip = dest_ip,
                           .src_port = src_port,
                           .dest_port = dest_port};
    // worst code i've written in my life.
    entry2.user_arg = nullptr;
    entry2.user_arg = nullptr;
    conntable.add_entry(entry1);
    conntable.add_entry(entry2);
    assert(conntable.lookup_entry(entry1)->ref == nullptr &&
           conntable.lookup_entry(entry2)->ref == nullptr);
    conntable.lookup_entry(entry1)->ref = new conn_table_entry(entry3);
    conntable.lookup_entry(entry2)->ref = new conn_table_entry(entry3);
}

/*
 * "smart" universal MITM connection lookup, returns the relevant MITM_conn_data
 * when looking up any of the 3 tuples created in new_conn()
 */
MITM_conn_data *MITM::lookup_conn(be32_t src_ip, be32_t dest_ip,
                                  be16_t src_port, be16_t dest_port) {
    auto entry = conn_table_entry(src_ip, dest_ip, src_port, dest_port);
    // entry that is inserted with full original connection tuple (src_ip,
    // src_port, dest_ip, dest_port), no zero fillers
    LOG("looking up: src_ip = %u, dest_ip = %u, src_port = %d, dest_port = %d",
        src_ip, dest_ip, src_port, dest_port);
    auto *full_conntable_entry = conntable.lookup_entry(entry);

    if ( full_conntable_entry == nullptr ) {
        LOG("not found");
        return nullptr;
    }

    if ( !(src_ip && dest_ip && src_port && dest_port) )
        full_conntable_entry =
            conntable.lookup_entry(*full_conntable_entry->ref);

    if ( full_conntable_entry == nullptr ) {
        throw std::runtime_error(
            "partial entry exists but full entry is missing");
    }

    if ( full_conntable_entry->user_arg == nullptr ) {
        throw std::runtime_error("user_arg is null");
    }

    return static_cast<MITM_conn_data *>(full_conntable_entry->user_arg);
}

void MITM::test() {
    conntable.test();
    new_conn(16843018, 33685770, 43671, 2048);
    new_conn(33685770, 16843018, 2048, 43671);
    new_conn(16843018, 33685770, 2048, 43671);
    new_conn(33685770, 16843018, 43671, 2048);
    assert(lookup_conn(16843018, 33685770, 43671, 2048) != nullptr);
    assert(lookup_conn(33685770, 16843018, 2048, 43671) != nullptr);
    assert(lookup_conn(33685770, 0, 2048, 0) != nullptr);
    assert(lookup_conn(0, 16843018, 0, 43671) != nullptr);
    assert(lookup_conn(16843018, 0, 43671, 0) != nullptr);
    assert(lookup_conn(0, 33685770, 0, 2048) != nullptr);
}

pbuf *MITM::mitm_buf_alloc(size_t len) {
    return pbuf_alloc(PBUF_RAW, len, PBUF_POOL);
}

pbuf *MITM::buf_alloc_copy(char *data, size_t len) {
    auto *pbuf = mitm_buf_alloc(len);
    if ( pbuf == nullptr ) {
        return nullptr;
    }
    memcpy(pbuf->payload, data, len);

    return pbuf;
}

void MITM::buf_chain(pbuf *buf, pbuf *new_tail) {
    if ( new_tail == nullptr ) return;
    pbuf_chain(buf, new_tail);
}

void MITM::tx_eth_frame(pbuf *pbuf) {
    if ( pbuf->len < sizeof(eth_hdr) )
        throw std::runtime_error("pbuf too small to contain ethernet header");
    eth_hdr *eth_frame = (eth_hdr *)pbuf->payload;
    // size checked in else if condition
    ip_hdr *pbuf_iphdr = (ip_hdr *)((char *)eth_frame + sizeof(eth_hdr));

    if ( eth_frame->type == PP_HTONS(ETHTYPE_ARP) ) {
        // exit if and send
    } else if ( (pbuf->len >=
                 sizeof(eth_hdr) + sizeof(ip_hdr) + sizeof(tcp_hdr)) &&
                IPH_V(pbuf_iphdr) == 4 &&
                IPH_PROTO(pbuf_iphdr) == IPPROTO_TCP ) {
        tcp_hdr *pbuf_tcphdr = nullptr;

        pbuf_tcphdr = static_cast<tcp_hdr *>(get_ipv4hdr_data(pbuf_iphdr));
        auto *conn = lookup_conn(pbuf_iphdr->src.addr, pbuf_iphdr->dest.addr,
                                 pbuf_tcphdr->src, pbuf_tcphdr->dest);
        if ( conn == nullptr ) {
            new_conn(pbuf_iphdr->src.addr, pbuf_iphdr->dest.addr,
                     pbuf_tcphdr->src, pbuf_tcphdr->dest);
        } else {
            LOG("found conn path...");
            if ( conn->dest_ip == pbuf_iphdr->src.addr &&
                 conn->dest_port == pbuf_tcphdr->src &&
                 conn->src_ip == pbuf_iphdr->dest.addr &&
                 conn->src_port == pbuf_tcphdr->dest ) {
                // packet from external to internal side
                if ( conn->MITM_ext_port == 0 ) {
                    throw std::runtime_error("MITM_ext_port unset");
                }
                pbuf_tcphdr->dest = conn->MITM_ext_port;
            } else if ( conn->dest_ip == pbuf_iphdr->dest.addr &&
                        conn->dest_port == pbuf_tcphdr->dest &&
                        conn->src_ip == pbuf_iphdr->src.addr &&
                        conn->src_port == pbuf_tcphdr->src ) {
                // packet from internal to external side
                // nothing to do here (destination IP is changed universally
                // outside of if clause)
            } else {
                throw std::runtime_error("unexpected tuple");
            }
        }

        // before modifying IP header, make sure checksum is currently
        // correct
        if ( calc_ipv4_checksum(pbuf_iphdr) != 0 ) {
            LOG("%s: ipv4 checksum check failed", __func__);
            return;
        }

        // netif_ip should be in network byte order!
        pbuf_iphdr->dest.addr = netif_ip;

        fix_tcp_checksum(pbuf, pbuf_iphdr);
        fix_ipv4_checksum(pbuf_iphdr);

        LOG("transmitting packet:R=%d\n"
            "ip src %u.%u.%u.%u\n"
            "ip dest %u.%u.%u.%u\n"
            "port src %u\n"
            "port dest %u",
            ((pbuf_tcphdr->_hdrlen_rsvd_flags & 0xFF) & TCP_RST) != 0,
            (pbuf_iphdr->src.addr >> 24) & 0xFF,
            (pbuf_iphdr->src.addr >> 16) & 0xFF,
            (pbuf_iphdr->src.addr >> 8) & 0xFF, (pbuf_iphdr->src.addr) & 0xFF,
            (pbuf_iphdr->dest.addr >> 24) & 0xFF,
            (pbuf_iphdr->dest.addr >> 16) & 0xFF,
            (pbuf_iphdr->dest.addr >> 8) & 0xFF, (pbuf_iphdr->dest.addr) & 0xFF,
            lwip_ntohs(pbuf_tcphdr->src), lwip_ntohs(pbuf_tcphdr->dest));
        /*
if ( pbuf_tcphdr->_hdrlen_rsvd_flags & TCP_ACK ) {
    printf("transmitting:\n");
    printf("strlen = %zu\n",
           strlen((char *)pbuf_tcphdr + sizeof(*pbuf_tcphdr)));
    printf("real len = %zu\n",
           len - ((char *)pbuf_tcphdr + sizeof(*pbuf_tcphdr) -
                  (char *)eth_frame));
    printf("%s\n", (char *)pbuf_tcphdr + sizeof(*pbuf_tcphdr));
}
        */
        pbuf_tcphdr = nullptr;
    }

    netif.get()->input(pbuf, netif.get());
    pbuf_iphdr = nullptr;
}

std::unique_ptr<char[]> MITM::rx_eth_frame(size_t *len) {
    if ( len == nullptr ) throw std::runtime_error("len argument is null");
    if ( outgoing_queue.empty() ) return nullptr;
    auto buf = std::move(outgoing_queue.front());
    outgoing_queue.pop();
    *len = buf.len;
    return std::move(buf.data);
}

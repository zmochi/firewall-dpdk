#include <lwip/netif.h>
#include <lwip/pbuf.h>
#include <lwip/prot/tcp.h>
#include <lwip/tcp.h>
#include <lwip/tcpip.h>

#include <stdexcept>
#include <string.h>

#include "lwip/api.h"
#include "lwip/inet_chksum.h"
#include "setup.hpp"

#define LOG(fmt, ...)     printf(fmt "\n", ##__VA_ARGS__)
#define LOG_ERR(fmt, ...) LOG("ERR: " fmt, ...)

struct MITM_conn_data {
    // entry with tuple (dest_ip, 0, dest_port, 0)
    conn_table_entry *entry1 = nullptr;
    // entry with tuple (src_ip, 0, src_port, 0)
    conn_table_entry *entry2 = nullptr;
    be32_t            src_ip = 0;
    be32_t            dest_ip = 0;
    be16_t            src_port = 0;
    be16_t            dest_port = 0;
    be16_t            MITM_ext_port = 0;
};

struct netconn *MITM::socket() { return netconn_new(NETCONN_TCP); }

int MITM::make_socket_nonblocking(struct netconn *sock) {
    netconn_set_nonblocking(sock, 1);
    return OK;
}

#include <iostream>
int MITM::bind(struct netconn *socket, uint16_t port) {
    err_t err;
	const ip_addr_t addr = {.addr = netif_ip};
    if ( (err = netconn_bind(socket, &addr, port)) != ERR_OK ) {
        std::cout << "err: " << (int)err << std::endl;
        return ERR;
    }
    return OK;
}

int MITM::listen(struct netconn *socket, uint8_t backlog) {
	err_t err;
    if ( (err = netconn_listen_with_backlog(socket, backlog)) != ERR_OK ){std::cout<<"err " << __func__ << ":" << (int)err << std::endl; return ERR; }
    return OK;
}

int MITM::accept(struct netconn *listen_socket, struct netconn **new_sock) {
    auto err = netconn_accept(listen_socket, new_sock);
    if ( err != ERR_OK && err != ERR_WOULDBLOCK ){std::cout<<"err " << __func__ << ":" << (int)err << std::endl; return ERR; }
    return OK;
}

int MITM::close(struct netconn *socket) {
    if ( netconn_close(socket) != ERR_OK ) return ERR;
    return OK;
}

int MITM::shutdown(struct netconn *socket, bool ingress, bool egress) {
    if ( netconn_shutdown(socket, ingress, egress) != ERR_OK ) return ERR;
    return OK;
}

// buffer points to where data should be copied, buf_cap holds buffer capacity
ssize_t MITM::recv(struct netconn *socket, char *buffer, size_t buf_cap) {
    size_t         nb_bytes_copied;
    struct netbuf *buf;

    // allocates a netbuf buffer with received data
    if ( netconn_recv(socket, &buf) != ERR_OK ) return ERR;
    // copy buf contents into user buffer
    if ( (nb_bytes_copied = netbuf_copy(buf, buffer, buf_cap)) == 0 )
        return ERR;

    return nb_bytes_copied;
}

ssize_t MITM::send(struct netconn *socket, char *src, size_t len) {
    size_t bytes_written;
    if ( netconn_write_partly(socket, src, len, 0, &bytes_written) != ERR_OK )
        return ERR;
    if ( bytes_written > SSIZE_MAX ) return ERR;
    return bytes_written;
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

static void fix_tcp_checksum(struct pbuf *p, ip_hdr *iphdr) {
    struct pbuf tcp_pbuf = *p;
    if ( p->payload != iphdr )
        throw std::runtime_error("p->payload != iphdr, assumption broken");

    tcp_pbuf.payload = iphdr;
    tcp_pbuf.tot_len -= get_ipv4hdr_size(iphdr);
    tcp_pbuf.len -= get_ipv4hdr_size(iphdr);
    const ip4_addr_t src = {.addr = iphdr->src.addr};
    const ip4_addr_t dest = {.addr = iphdr->dest.addr};

    if ( IPH_V(iphdr) != 4 ) {
        throw std::runtime_error("passed non IPv4 pbuf?");
    }
    if ( IPH_PROTO(iphdr) != 6 ) {
        throw std::runtime_error("passed non TCP datagram?");
    }

    tcp_hdr *tcphdr = static_cast<tcp_hdr *>(get_ipv4hdr_data(iphdr));
    tcphdr->chksum = inet_chksum_pseudo(
        &tcp_pbuf, IPPROTO_TCP, ntohs(iphdr->_len) - (iphdr->_v_hl << 2), &src,
        &dest);
}

static void fix_ipv4_checksum(ip_hdr *iphdr) {
    IPH_CHKSUM_SET(iphdr, 0);
    IPH_CHKSUM_SET(iphdr, inet_chksum(iphdr, lwip_ntohs(IPH_LEN(iphdr))));
}

err_t outgoing_hook(netif *netif, pbuf *p, const ip4_addr_t *ip_dest) {
    MITM            &instance = *((MITM *)netif->state);
    ip_hdr          *pbuf_iphdr = (ip_hdr *)p->payload;
    const ip4_addr_t src = {.addr = pbuf_iphdr->src.addr};
    const ip4_addr_t dest = {.addr = pbuf_iphdr->dest.addr};

    if ( IPH_V(pbuf_iphdr) != 4 ) {
        throw std::runtime_error("passed non IPv4 pbuf?");
    }
    if ( IPH_PROTO(pbuf_iphdr) != 6 ) {
        throw std::runtime_error("passed non TCP datagram?");
    }

    tcp_hdr *pbuf_tcphdr = static_cast<tcp_hdr *>(get_ipv4hdr_data(pbuf_iphdr));
    auto    *conn =
        instance.lookup_conn(pbuf_iphdr->dest.addr, 0, pbuf_tcphdr->dest, 0);
    // case for traffic to internal side, tuple (mitm_ip, dest_port, src_ip,
    // src_port)
    if ( conn->src_ip == pbuf_iphdr->dest.addr &&
         conn->src_port == pbuf_tcphdr->dest ) {
        pbuf_iphdr->src.addr = conn->dest_ip;
    }
    // case for traffic to external side, tuple (mitm_ip, mitm_ext_port,
    // dest_ip, dest_port)
    else if ( conn->dest_ip == pbuf_iphdr->dest.addr &&
              conn->dest_port == pbuf_tcphdr->dest ) {
        conn->MITM_ext_port = pbuf_tcphdr->src;
        pbuf_iphdr->src.addr = conn->src_ip;
        pbuf_tcphdr->src = conn->src_port;
    }
    fix_tcp_checksum(p, pbuf_iphdr);
    fix_ipv4_checksum(pbuf_iphdr);

    // copy p->payload to new buffer and enqueue to send
    instance.outgoing_queue.emplace((char *)p->payload, p->len);

    return ERR_OK;
}

// note: network byte order
#define IP4(a, b, c, d) PP_HTONL(LWIP_MAKEU32(a, b, c, d))

err_t netif_init_func(struct netif *netif) {
    return ERR_OK;
}

MITM::MITM()
    : netif(new struct netif), netif_ip(IP4(8, 8, 8, 8)),
      netif_netmask(IP4(255, 255, 255, 255)) {
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

    netif.get()->output = outgoing_hook;
    netif_set_default(netif.get());
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
    auto entry1 = conn_table_entry(src_ip, 0, src_port, 0);
    auto entry2 = conn_table_entry(dest_ip, 0, dest_port, 0);
    auto entry3 = conn_table_entry(src_ip, src_port, dest_ip, dest_port);
    entry3.user_arg = new MITM_conn_data{.src_ip = src_ip,
                                         .dest_ip = dest_ip,
                                         .src_port = src_port,
                                         .dest_port = dest_port};
    conntable.add_entry(entry3);
    entry1.user_arg = conntable.lookup_entry(entry3);
    entry2.user_arg = conntable.lookup_entry(entry3);
    conntable.add_entry(entry1);
    conntable.add_entry(entry2);
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
    auto *full_conntable_entry = conntable.lookup_entry(entry);

    if ( !(src_ip && dest_ip && src_port && dest_port) )
        full_conntable_entry =
            static_cast<conn_table_entry *>(full_conntable_entry->user_arg);

    if ( full_conntable_entry == nullptr ) {
        throw std::runtime_error("nullptr dereference");
    }

    return static_cast<MITM_conn_data *>(full_conntable_entry->user_arg);
}

void MITM::tx_ip_datagram(char *datagram, size_t len) {
    std::unique_ptr<pbuf> pbuf(pbuf_alloc(PBUF_RAW, len, PBUF_POOL));
    ip_hdr               *datagram_iphdr = (ip_hdr *)datagram;
    ip_hdr               *pbuf_iphdr = (ip_hdr *)pbuf->payload;
    tcp_hdr              *pbuf_tcphdr;

    if ( IPH_V(datagram_iphdr) != 4 ) {
        throw std::runtime_error("passed non IPv4 datagram?");
    }
    if ( IPH_PROTO(datagram_iphdr) != 6 ) {
        throw std::runtime_error("passed non TCP datagram?");
    }

    memcpy(pbuf->payload, datagram, len);

    pbuf_tcphdr = static_cast<tcp_hdr *>(get_ipv4hdr_data(pbuf_iphdr));
    auto *conn = lookup_conn(pbuf_iphdr->src.addr, pbuf_iphdr->dest.addr,
                             pbuf_tcphdr->src, pbuf_tcphdr->dest);
    if ( conn == nullptr ) {
        new_conn(pbuf_iphdr->src.addr, pbuf_iphdr->dest.addr, pbuf_tcphdr->src,
                 pbuf_tcphdr->dest);
    } else {
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
            // nothing to do here (destination IP is changed universally outside
            // of if clause)
        } else {
            throw std::runtime_error("unexpected tuple");
        }
    }

    // netif_ip should be in network byte order!
    pbuf_iphdr->dest.addr = netif_ip;

    fix_tcp_checksum(pbuf.get(), pbuf_iphdr);
    fix_ipv4_checksum(pbuf_iphdr);

    netif.get()->input(pbuf.release(), netif.get());
    pbuf_iphdr = nullptr;
    pbuf_tcphdr = nullptr;
}

std::unique_ptr<char[]> MITM::rx_ip_datagram(size_t *len) {
    if ( len == nullptr ) throw std::runtime_error("len argument is null");
    if ( outgoing_queue.empty() ) return nullptr;
    auto buf = std::move(outgoing_queue.front());
    outgoing_queue.pop();
    *len = buf.len;
    return std::move(buf.data);
}

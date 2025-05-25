#include <cstring>
#include <list>
#include <poll.h>
#include <rte_ethdev.h>
#include <rte_ip_frag.h>
#include <rte_mbuf.h>
#include <rte_memory.h>
#include <signal.h>
#include <stdexcept>

#include <iostream>

#include "MITM/setup.hpp"
#include "macaddr.hpp"
#include "utils.h"

#ifndef DEBUG
#undef LOG
#define LOG(x, ...) (void)0
#endif

/* eth, ip, and tcp header structs: */
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_tcp.h>

#include "DLP/filter.hpp"
#include "DLP/http_parser.hpp"
#include "conn_table.hpp"
#include "firewall.hpp"
#include "logger.hpp"
#include "packet.hpp"
#include "ruletable.hpp"

static constexpr size_t ethhdr_size = sizeof(struct rte_ether_hdr),
                        udphdr_size = sizeof(struct rte_udp_hdr),
                        icmphdr_size = sizeof(struct rte_icmp_hdr);

struct rte_ether_hdr *get_eth_hdr(struct rte_mbuf *pkt) {
    return rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
}

char *get_ethhdr_data(struct rte_mbuf *pkt) {
    return (char *)get_eth_hdr(pkt) + ethhdr_size;
}

char *get_ipv4hdr_data(struct rte_mbuf *pkt) {
    auto  *iphdr = (struct rte_ipv4_hdr *)get_ethhdr_data(pkt);
    size_t ipv4hdr_size = (iphdr->ihl & 0x0F) * 4;
    if ( ipv4hdr_size < 20 || ipv4hdr_size > 60 ) {
        std::cout << "Bad ipv4hdr_size" << std::endl;
    }

    return (char *)iphdr + ipv4hdr_size;
}

char *get_tcphdr_data(struct rte_mbuf *pkt) {
    auto  *tcp_hdr = (struct rte_tcp_hdr *)get_ipv4hdr_data(pkt);
    size_t tcphdr_size = ((tcp_hdr->data_off & 0xF0) >> 4) * 4;
    if ( tcphdr_size < 20 || tcphdr_size > 60 ) {
        std::cout << "Bad tcphdr_size" << std::endl;
    }

    return (char *)tcp_hdr + tcphdr_size;
}

static const uint16_t nb_rx_rings = 1, nb_tx_rings = 1;
const int             MBUF_POOL_ELMS_PER_RING = 1024;
volatile bool         force_quit = false;
struct port_data {
  private:
    /* value choices inspired by example packet reassembly app
     * https://github.com/DPDK/dpdk/blob/main/examples/ip_reassembly/main.c
     * https://doc.dpdk.org/guides/sample_app_ug/ip_reassembly.html
     */
    static constexpr uint32_t f_tbl_nb_buckets = UINT16_MAX / 16;
    static constexpr uint32_t f_tbl_associativity = 16;
    static constexpr uint32_t f_tbl_max_entries = f_tbl_nb_buckets;
    static constexpr uint64_t f_tbl_max_cycles = UINT64_MAX;

  public:
    uint16_t port;
    // port represents a network in the firewall, so this is the subnet of the
    // network
    be32_t                       netmask;
    be32_t                       routingprefix;
    MAC_addr                     mac;
    struct rte_mempool          *mempool = nullptr;
    struct rte_ip_frag_tbl      *ip_frag_tbl = nullptr;
    struct rte_ip_frag_death_row dr;

    port_data() : port(-1), mempool(nullptr), ip_frag_tbl(nullptr) {}

    port_data(uint16_t port, be32_t routingprefix, be32_t netmask, MAC_addr mac,
              struct rte_mempool *mempool)
        : port(port), routingprefix(routingprefix), netmask(netmask), mac(mac),
          mempool(mempool) {
        /* put this in init */
        /*
ip_frag_tbl = rte_ip_frag_table_create(
f_tbl_nb_buckets, f_tbl_associativity, f_tbl_max_entries,
f_tbl_max_cycles, SOCKET_ID_ANY);
if ( ip_frag_tbl == nullptr ) {
throw std::runtime_error(
"Couldn't initialize ip fragmentation table");
}
*/
    }

    void cleanup() {
        if ( ip_frag_tbl != nullptr ) rte_ip_frag_table_destroy(ip_frag_tbl);
    }
};

struct rte_mbuf *ipv4_reassemble(port_data &pdata, struct rte_mbuf *mbuf,
                                 struct rte_ipv4_hdr *ip_hdr,
                                 uint64_t             timestamp) {
    if ( mbuf == nullptr || ip_hdr == nullptr ) {
        ERROR("mbuf or ip_hdr are null");
        return nullptr;
    }

    mbuf->l2_len = ethhdr_size;
    /* ignoring the fact that ip header size is actually variable, since this is
     * how its done in the example application and they know better than me. */
    mbuf->l3_len = sizeof(rte_ipv4_hdr);

    if ( ip_hdr->ihl * 4 != sizeof(rte_ipv4_hdr) ) {
        ERROR("ihl field in ip header is not standard. possible issues?");
    }

    auto reass_mbuf = rte_ipv4_frag_reassemble_packet(
        pdata.ip_frag_tbl, &pdata.dr, mbuf, timestamp, ip_hdr);

    if ( reass_mbuf == nullptr ) {
        // error or not all fragments collected yet
        return nullptr;
    }

    if ( rte_pktmbuf_mtod(reass_mbuf, struct rte_ether_hdr *)->ether_type !=
         rte_be_to_cpu_16(RTE_ETHER_TYPE_IPV4) ) {
        ERROR("Ether type is not IPv4");
        rte_pktmbuf_mtod(reass_mbuf, struct rte_ether_hdr *)->ether_type =
            rte_be_to_cpu_16(RTE_ETHER_TYPE_IPV4);
    }

    return reass_mbuf;
}

/*
 * @brief configure and start a port (NIC), set up rx/tx rings and queues. this
 * function also set promiscuous mode.
 */
int port_init(port_data &pdata) {
    /* the basic steps are:
     * check if the given port is valid, with rte_eth_dev_is_valid_port()
     *
     * configure the port with number of rx/tx rings and port_conf struct, with
     * rte_eth_dev_configure()
     *
     * set up each rx/tx ring with rte_eth_tx_queue_setup()
     *
     * set rx/tx callbacks for NIC
     */
    uint16_t                port = pdata.port;
    struct rte_mempool     *mbuf_pool = pdata.mempool;
    int                     ret;
    struct rte_eth_conf     port_conf = {};
    struct rte_eth_dev_info dev_info;
    struct rte_eth_txconf   txconf;
    struct rte_eth_rxconf   rxconf;
    uint16_t                nb_rx_dsc = MBUF_POOL_ELMS_PER_RING;
    uint16_t                nb_tx_dsc = MBUF_POOL_ELMS_PER_RING;

    std::memset(&port_conf, 0, sizeof(port_conf));

    if ( !rte_eth_dev_is_valid_port(port) ) return -1;

    ret = rte_eth_dev_info_get(port, &dev_info);
    if ( ret != 0 ) {
        ERROR("Couldn't get device info for port %d: %s", port, strerror(-ret));
        return -1;
    }

    /* use default rx/tx configuration given by driver in
     * rte_eth_dev_info_get()
     *
     * portconf is used to configure the NIC, rxconf and txconf are used to
     * configure each ring on the NIC */
    txconf = dev_info.default_txconf;
    rxconf = dev_info.default_rxconf;

    /* configure NIC
     * must adjust port settings on port_conf before this */
    ret = rte_eth_dev_configure(port, nb_rx_rings, nb_tx_rings, &port_conf);
    if ( ret != 0 ) {
        ERROR("Couldn't configure port %d", port);
        return -1;
    }

    /* if nb_rx/tx_dsc are above maximum number of rx/tx descriptors driver can
     * handle, this adjusts them to a valid value (rx/tx descriptors are slots
     * in the rx/tx rings that hold packets) */
    ret = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rx_dsc, &nb_tx_dsc);
    if ( ret != 0 ) {
        ERROR("Couldn't adjust rx/tx descriptors for port %d", port);
        return -1;
    }

    /* for each ring, set number of tx descriptors */
    for ( int i = 0; i < nb_tx_rings; i++ ) {
        ret = rte_eth_tx_queue_setup(port, i, nb_tx_dsc,
                                     rte_eth_dev_socket_id(port), &txconf);
        if ( ret < 0 ) {
            ERROR("Couldn't setup tx queue on port %d", port);
            return -1;
        }
    }

    /* for each ring, set number of rx descriptors */
    for ( int i = 0; i < nb_rx_rings; i++ ) {
        ret = rte_eth_rx_queue_setup(port, i, nb_rx_dsc,
                                     rte_eth_dev_socket_id(port), nullptr,
                                     mbuf_pool);
        if ( ret < 0 ) {
            ERROR("Couldn't setup rx queue on port %d", port);
            return -1;
        }
    }

    ret = rte_eth_dev_start(port);
    if ( ret != 0 ) {
        ERROR("Couldn't start port %d", port);
        return -1;
    }

    /* enable promiscuous mode so packet forwarding works correctly */
    ret = rte_eth_promiscuous_enable(port);
    if ( ret != 0 ) {
        ERROR("Couldn't set port %d in promiscuous mode", port);
        return -1;
    }

    return 0;
}

#include <signal.h>
struct sigaction old_act;

void sigint_handler(int sig) {
    /* this flag is read on every iteration in firewall_loop() (main loop that
     * handles rx/tx) */
    force_quit = true;

    printf("Stopping gracefully...\n");
}

int init_sigint_handler() {
    struct sigaction act = {};
    sigemptyset(&act.sa_mask);
    act.sa_handler = sigint_handler;

    if ( sigaction(SIGINT, &act, &old_act) != 0 ) {
        ERROR("Couldn't assign handler to SIGINT");
        return 1;
    }

    return 0;
}

/* @brief fills pkt_props struct with data from packet.
 * if packet is not long enough to contain all fields in the pkt_props struct,
 * the struct instance is returned partially filled (unfilled fields get their
 * respective NUL/INVALID special values) with all available info.
 *
 * @return the pkt_props struct instance.
 */
pkt_props extract_pkt_props(struct rte_mbuf &pkt, direction pkt_direction) {
    struct pkt_props pkt_props;
    pkt_props.direction = pkt_direction;

    struct rte_tcp_hdr *tcp_hdr = {};

    size_t tcphdr_size = 0;
    size_t ipv4hdr_size = 0;

    /* struct rte_mbuf of the packet is stored right behind it in memory.
     * rte_pktmbuf_mtod() returns a pointer to the data (the packet itself)
     * of a struct rte_mbuf. for details:
     * https://doc.dpdk.org/guides/prog_guide/mbuf_lib.html
     */
    struct rte_ether_hdr *eth_hdr = get_eth_hdr(&pkt);
    size_t                eff_pktlen = rte_pktmbuf_pkt_len(&pkt);

    if ( eff_pktlen < ethhdr_size ) {
        ERROR("Packet too small to contain ethernet header");
        pkt_props.eth_proto = FW_ETHTYPE_NUL;
        goto ret;
    }
    /*
     * there might be a better way to check packet types (ipv4, tcp, ...),
     * using https://doc.dpdk.org/api/rte__mbuf__ptype_8h.html
     * and the `packet_type` field in struct rte_mbuf
     */
    pkt_props.eth_proto = static_cast<eth_proto>(eth_hdr->ether_type);

    eff_pktlen -= ethhdr_size;

    if ( pkt_props.eth_proto == FW_ETHTYPE_IPV4 ) {
        ipv4hdr_size = get_ipv4hdr_data(&pkt) - get_ethhdr_data(&pkt);
        if ( eff_pktlen < ipv4hdr_size ) {
            pkt_props.eth_proto = FW_ETHTYPE_NUL;
            goto ret;
        }
        auto *ipv4_hdr = (struct rte_ipv4_hdr *)get_ethhdr_data(&pkt);

        /* store in network order */
        pkt_props.saddr = ipv4_hdr->src_addr;
        pkt_props.daddr = ipv4_hdr->dst_addr;

        eff_pktlen -= ipv4hdr_size;

        if ( ipv4_hdr->next_proto_id == IPPROTO_TCP ) {
            tcphdr_size = get_tcphdr_data(&pkt) - get_ipv4hdr_data(&pkt);
            if ( eff_pktlen < tcphdr_size ) {
                pkt_props.proto = NUL_PROTO;
                goto ret;
            }
            pkt_props.proto = TCP;
            tcp_hdr = (struct rte_tcp_hdr *)get_ipv4hdr_data(&pkt);
            pkt_props.sport = tcp_hdr->src_port;
            pkt_props.dport = tcp_hdr->dst_port;
            pkt_props.tcp_flags =
                static_cast<enum tcp_flags>(tcp_hdr->tcp_flags);
            pkt_props.seq_nb = tcp_hdr->sent_seq;
            pkt_props.ack_nb = tcp_hdr->recv_ack;
        } else if ( ipv4_hdr->next_proto_id == IPPROTO_UDP ) {
            if ( eff_pktlen < udphdr_size ) {
                pkt_props.proto = NUL_PROTO;
                goto ret;
            }
            pkt_props.proto = UDP;
            auto *udp_hdr = (struct rte_udp_hdr *)get_ipv4hdr_data(&pkt);
            pkt_props.sport = udp_hdr->src_port;
            pkt_props.dport = udp_hdr->dst_port;
        } else if ( ipv4_hdr->next_proto_id == IPPROTO_ICMP ) {
            pkt_props.proto = ICMP;
        }
    }

ret:
    return pkt_props;
}

uint16_t pre_query_hook(port_data &pdata, struct rte_mbuf *pkt,
                        struct rte_mbuf **outgoing_pkts,
                        const uint16_t    outoging_pkts_cap,
                        const uint64_t    timestamp) {
    uint16_t pkt_cnt = 0;
    if ( get_eth_hdr(pkt)->ether_type == FW_ETHTYPE_IPV4 &&
         rte_ipv4_frag_pkt_is_fragmented(
             (struct rte_ipv4_hdr *)get_ethhdr_data(pkt)) ) {
        printf("got fragmented packet\n");
        // ipv4_reassemble either returns null (and "saves" the passed packet
        // for later) or returns the reassembled packet.
        outgoing_pkts[0] = ipv4_reassemble(
            pdata, pkt, (struct rte_ipv4_hdr *)get_ethhdr_data(pkt), timestamp);
        if ( outgoing_pkts[0] != nullptr ) {
            pkt_cnt++;
            printf("reassembled packet!\n");
        }
    } else {
        outgoing_pkts[0] = pkt;
        pkt_cnt++;
    }

    return pkt_cnt;
}

// HTTP port 80 in big endian
constexpr be32_t http_port_be = 0x5000;
// SMTP port 25 in big endian
constexpr be32_t smtp_port_be = 0x1900;

// having this in global variable is very bad design :D
MITM mitm;

// this should be in MITM files
struct MITM_conn {
    MITM_conn &peer;
    int        socket;
    // socket field in adjacent element from MITM_conn_pair
    bool finished_receiving = false;
    bool finished_sending = false;
    // to parse HTTP requests, need to know which side is sending requests
    // (client) and which is responding (server)
    bool is_http_client = false;
    // finished both sending and receiving
    std::vector<char>     data;
    size_t                http_content_start = 0;
    size_t                http_content_len = 0;
    size_t                http_data_parsed = 0;
    size_t                data_recvd = 0;
    size_t                data_sent = 0;
    constexpr static auto data_init_size = 1 << 11;

    MITM_conn(int socket, MITM_conn &peer) : socket(socket), peer(peer) {
        data.resize(data_init_size);
    }

    ~MITM_conn() { mark_done(); }

    /*
     * copy another MITM_conn and set a new peer, to make copy constructor in
     * MITM_conn_pair easier
     */
    MITM_conn(MITM_conn &other, MITM_conn &peer) noexcept : peer(peer) {
        socket = other.socket;
        finished_receiving = other.finished_receiving;
        finished_sending = other.finished_sending;
        done = other.done;
        data_sent = other.data_sent;
        data = std::move(other.data);
    }

    /* closes this connection. may be called multiple times */
    void mark_done() noexcept {
        if ( done ) return;
        int err = mitm.close(socket);
        data_recvd = data_sent = 0;
        finished_receiving = finished_sending = done = true;
        if ( err < 0 ) {
            ERROR("mitm.close() error");
        }
    }

    bool is_done() noexcept { return done; }

  private:
    bool done = false;
};

/* client and server connection pair */
struct MITM_conn_pair {
    std::array<struct MITM_conn, 2> peers;
    MITM_conn_pair(int conn, int peer)
        : peers{MITM_conn(conn, peers.at(1)), MITM_conn(peer, peers.at(0))} {
        peers.at(0).is_http_client = true;
    }

    MITM_conn_pair(MITM_conn_pair &&other) noexcept
        : peers{MITM_conn(other.peers.at(0), peers.at(1)),
                MITM_conn(other.peers.at(1), peers.at(0))} {}
};

#include <fstream>
class MITM_client {
  public:
    uint16_t  port;
    int       listen_socket;
    filter_fn filter_cb;

    std::list<MITM_conn_pair> connections;

    MITM_client(uint16_t port, filter_fn fn) : port(port), filter_cb(fn) {
        listen_socket = mitm.socket();
        if ( listen_socket < 0 ) {
            std::cout << "mitm.socket() failed" << std::endl;
        }

        int err = 0;
        if ( mitm.bind(listen_socket, port) < 0 )
            throw std::runtime_error("Couldn't bind socket");
        if ( (err = mitm.listen(listen_socket, 20)) != 0 ) {
            throw std::runtime_error("Couldn't listen on socket");
        }
        if ( mitm.make_socket_nonblocking(listen_socket) < 0 ) {
            throw std::runtime_error("make_socket_nonblocking() error");
        }
    }

    /* ^ Linux sockaddr definition has unsigned short sa_family.
     * MITM (lwIP actually) has char sa_len, char sa_family on the
     * same memory. shift left to erase sa_len.
     */
    static uint8_t read_mitm_sa_family(uint16_t sa_family) {
#ifndef __linux__
#error Linux-only code exists, read_mitm_sa_family()
#endif /* __linux__ */
        return sa_family >> sizeof(uint8_t) * CHAR_BIT;
    }

    void process() {
        struct sockaddr addr_new = {};
        unsigned int    addrsize = sizeof(addr_new);
        int             conn = 0;
        int             peer = 0;
        int             err;
        if ( (conn = mitm.accept(listen_socket, &addr_new, &addrsize)) < 0 &&
             errno != EWOULDBLOCK )
            ERROR("whoops on accept(), conn=%d,errno=%d", conn, errno);

        if ( conn > 0 ) {
            if ( read_mitm_sa_family(addr_new.sa_family) != AF_INET ) {
                throw std::runtime_error("Got non-IPv4 connection");
            }

            // connect to server:
            auto *info = reinterpret_cast<struct sockaddr_in *>(&addr_new);
            auto *conn_entry =
                mitm.lookup_conn(info->sin_addr.s_addr, 0, info->sin_port, 0);
            info->sin_addr.s_addr = conn_entry->dest_ip;
            info->sin_port = conn_entry->dest_port;

            if ( (peer = mitm.socket()) < 0 ) {
                ERROR("errno = %d", errno);
                throw std::runtime_error("mitm.socket() failed");
            }

            if ( mitm.make_socket_nonblocking(conn) < 0 ||
                 mitm.make_socket_nonblocking(peer) < 0 )
                throw std::runtime_error(
                    "mitm.make_socket_nonblocking() failed");

            if ( (err = mitm.connect(peer, &addr_new, addrsize)) < 0 &&
                 errno != EINPROGRESS ) {
                switch ( errno ) {
                    case ECONNREFUSED:
                        LOG("ECONNREFUSED on connect() after accept()");
                        if ( mitm.close(conn) < 0 || mitm.close(peer) < 0 ) {
                            throw std::runtime_error("mitm.close() error");
                        };
                        break;
                    default:
                        throw std::runtime_error("mitm.connect() failed");
                }
            } else {
                if ( (err = mitm.getsockname(peer, &addr_new, &addrsize)) < 0 ||
                     read_mitm_sa_family(addr_new.sa_family) != AF_INET ) {
                    throw std::runtime_error("mitm.getsockname() failed");
                }

                assert(info == (void *)&addr_new);
                conn_entry->MITM_ext_port = info->sin_port;
                connections.emplace_back(conn, peer);
            }
            conn = -1;
            peer = -1;
        }

        for ( auto item = connections.begin(); item != connections.end(); ) {
            if ( item->peers.at(0).is_done() && item->peers.at(1).is_done() ) {
                item = connections.erase(item);
                continue;
            }

            // run twice - transfer data from and to both sides
            for ( auto &active_conn : item->peers ) {
                int    &conn_socket = active_conn.socket;
                int    &peer_socket = active_conn.peer.socket;
                auto   &data = active_conn.data;
                bool   &finished_receiving = active_conn.finished_receiving;
                bool   &finished_sending = active_conn.finished_sending;
                size_t &data_recvd = active_conn.data_recvd;
                size_t &data_sent = active_conn.data_sent;

                struct linger ling = {.l_onoff = 1, .l_linger = 0};

                if ( active_conn.is_done() ) {
                    continue;
                }

                if ( data_recvd >= data.size() ) data.resize(data.size() * 2);

                pollfd pfd{.fd = conn_socket,
                           .events = MITM_POLLIN | MITM_POLLOUT | MITM_POLLERR,
                           .revents = 0};
                if ( mitm.poll(&pfd, 1, 0) < 0 ) {
                    throw std::runtime_error("poll failed");
                };

                if ( pfd.revents & MITM_POLLERR ) {
                    int          errno_val = 0;
                    unsigned int val_len = sizeof(errno_val);
                    if ( mitm.getsockopt_SOLSOCKET_SOERROR(
                             conn_socket, SOL_SOCKET, SO_ERROR, &errno_val,
                             &val_len) < 0 ) {
                        throw std::runtime_error("mitm.getsockopt() failed");
                    };
                    LOG("POLLERR: errno_val = %d. %s", errno_val,
                        strerror(errno_val));

                    switch ( errno_val ) {
                            // not sure about this case..
                        case 0:
                            break;
                            /* connect() on socket, connect
                             * refused/reset/aborted.. */
                        case ECONNABORTED:
                            LOG("-------ECONNABORTED");
                        case ECONNREFUSED:
                        case ECONNRESET:
                            // trigger RST for peer too
                            if ( mitm.setsockopt_SOLSOCKET_SOLINGER(
                                     active_conn.peer.socket, SOL_SOCKET,
                                     SO_LINGER, &ling, sizeof(ling)) < 0 ) {
                                ERROR("setsockopt: errno=%d, %s", errno,
                                      strerror(errno));
                                throw std::runtime_error("setsockopt() failed");
                            };
                        /* connect() on socket, timed out */
                        case ETIMEDOUT:
                            active_conn.mark_done();
                            active_conn.peer.mark_done();
                        /* connect() still in progress */
                        case EINPROGRESS:
                            continue;
                        default:
                            ERROR("errno = %d", errno_val);
                            ERROR("err: %s, socket = %d", strerror(errno_val),
                                  conn_socket);
                            throw std::runtime_error("Unhandled errno_val");
                    }
                } else if ( !((pfd.revents & MITM_POLLOUT) ||
                              (pfd.revents & MITM_POLLIN)) ) {
                    // socket not connected yet
                    continue;
                }

                if ( !finished_receiving ) {
                    ssize_t actual_len =
                        mitm.recv(conn_socket, data.data() + data_recvd,
                                  data.size() - data_recvd);
                    if ( actual_len < 0 ) {
                        switch ( errno ) {
                                /* connect() still in progress */
                            case EINPROGRESS:
                                continue;
#if EAGAIN != EWOULDBLOCK
                            case EAGAIN:
#endif
                            case EWOULDBLOCK:
                                continue;
                            case ETIMEDOUT:
                            case ECONNRESET:
                                // trigger RST for peer too
                                if ( mitm.setsockopt_SOLSOCKET_SOLINGER(
                                         active_conn.peer.socket, SOL_SOCKET,
                                         SO_LINGER, &ling, sizeof(ling)) < 0 ) {
                                    ERROR("setsockopt: errno=%d, %s", errno,
                                          strerror(errno));
                                    throw std::runtime_error(
                                        "setsockopt() failed");
                                };
                            default:
                                active_conn.mark_done();
                                active_conn.peer.mark_done();
                                ERROR("whoops on recv, actual_len "
                                      "= %zd, errno = %d",
                                      actual_len, errno);
                                break;
                        }
                        continue;
                    } else if ( actual_len == 0 ) {
                        LOG("finished receiving on socket %d. filtering..",
                            conn_socket);
                        finished_receiving = true;
                        std::ofstream    file("filter_input.txt",
                                              std::ios::binary);
                        std::string_view str(data.data(), data_recvd);
                        file << str;
                        if ( filter_cb(data.data(), data_recvd) ==
                             FILTER_DROP ) {
                            LOG("filter dropped");
                            data.clear();
                            data_recvd = 0;
                        }
                    } else { /* actual_len > 0 */
                        LOG("actual_len = %zd, data_recvd = %zd, data.size() = "
                            "%zu",
                            actual_len, data_recvd, data.size());

                        data_recvd += actual_len;

                        if ( port == 80 && active_conn.is_http_client ) {
                            LOG("parsing http request");
                            auto parsed =
                                http_parse_request(data.data(), data_recvd);
                            if ( parsed.metadata_len < 0 ) {
                                if ( parsed.metadata_len == -1 ) {
                                    LOG("Rejecting malformed HTTP request");
                                    data.clear();
                                    continue;
                                } else if ( parsed.metadata_len == -2 ) {
                                    LOG("HTTP request incomplete");
                                    continue;
                                } else {
                                    throw std::runtime_error(
                                        "Unrecognized return value");
                                }
                            }
                            // check if content exists:
                            if ( data_recvd - parsed.metadata_len > 0 ) {
                                for ( int i = 0; i < parsed.num_headers; i++ ) {
                                    if ( parsed.headers.at(i).name ==
                                         "Content-Length" ) {
                                        LOG("found content-length header");
                                        active_conn.http_content_len = atoi(
                                            parsed.headers.at(i).value.data());
                                        active_conn.http_content_start =
                                            parsed.metadata_len;
                                    }
                                }
                            }
                            if ( filter_cb(data.data(), parsed.metadata_len) ==
                                     FILTER_DROP ||
                                 filter_cb(data.data() +
                                               active_conn.http_content_start,
                                           active_conn.http_content_len) ==
                                     FILTER_DROP ) {
                                LOG("filter dropped, http");
                                data.clear();
                                data_recvd = 0;
                            }
                            if ( (actual_len =
                                      mitm.send(peer_socket, data.data(),
                                                data_recvd)) < 0 ) {
                                LOG("http send: errno = %d, %s", errno,
                                    strerror(errno));
                                switch ( errno ) {
                                    case EWOULDBLOCK:
                                    case EINPROGRESS:
                                        continue;
                                    case ECONNRESET:
                                        active_conn.mark_done();
                                        active_conn.peer.mark_done();
                                        continue;
                                    default:
                                        ERROR("whoops on send, errno=%d, %s",
                                              errno, strerror(errno));
                                        break;
                                }
                            } else {
                                data_sent += actual_len;
                            }
                        }
                    }
                } else if ( !finished_sending ) {
                    LOG("sending on socket %d, data_sent=%zu", conn_socket,
                        data_sent);
                    ssize_t actual_len =
                        mitm.send(peer_socket, data.data() + data_sent,
                                  data_recvd - data_sent);
                    if ( actual_len < 0 ) {
                        LOG("send: errno = %d", errno);
                        switch ( errno ) {
#if EAGAIN != EWOULDBLOCK
                            case EAGAIN:
#endif
                            case EWOULDBLOCK:
                            case EINPROGRESS:
                                continue;
                            case EPIPE:
                                // below mitm.close() was already called
                                continue;
                            case ECONNRESET:
                                active_conn.mark_done();
                                active_conn.peer.mark_done();
                                continue;
                            default:
                                ERROR("whoops on send, errno=%d, %s", errno,
                                      strerror(errno));
                                break;
                        }
                    } else if ( actual_len == 0 ) {
                        assert(data_sent == data_recvd);
                        finished_sending = true;
                    } else { /* actual_len > 0 */
                        data_sent += actual_len;
                    }
                } else {
                    active_conn.mark_done();
                    // now peer can't send() to active_conn socket anymore, so:
                    active_conn.peer.mark_done();
                }
            }
            item++;
        }
    }
};

/* @brief receive a packet and make a decision whether to drop or pass the
 * packet.
 * @param pkt packet to make decision on.
 * @param ruletable ruletable to consult on static rules.
 * @param pkt_direction direction of the packet, becomes part of pkt_props.
 * @param logger logger instance to log packet decisions into.
 * @param conn_table connection table to consult if packet is TCP and has ACK=1.
 */
pkt_dc query_decision_and_log(rte_mbuf &pkt, const pkt_props pkt_props,
                              struct ruletable &ruletable, log_list &logger,
                              conn_table &conn_table, filter_fn filter_cb) {
    bool is_arp = pkt_props.eth_proto == FW_ETHTYPE_ARP;
    bool is_ipv4 = pkt_props.eth_proto == FW_ETHTYPE_IPV4;
    bool is_tcp = pkt_props.proto == IPPROTO_TCP;
    bool has_ack = is_tcp && pkt_props.tcp_flags & TCP_ACK_FLAG;
    bool do_filter =
        is_ipv4 && is_tcp &&
        (pkt_props.dport == http_port_be || pkt_props.dport == smtp_port_be ||
         pkt_props.sport == http_port_be || pkt_props.sport == smtp_port_be);
    decision_info dc;
    decision_info ruletable_dc = ruletable.query(&pkt_props, PKT_DROP);

    if ( ruletable_dc.decision == PKT_PASS && do_filter ) {
        /*
LOG("transmitting to MITM, TCP flags: R=%d, F=%d",
    (pkt_props.tcp_flags & TCP_RST_FLAG) != 0,
    (pkt_props.tcp_flags & TCP_FIN_FLAG) != 0);
LOG("src ip = %d", pkt_props.saddr);
        */
        rte_mbuf *mbuf = &pkt;
        // assuming that all headers fit in the first packet, so we got all the
        // info we needed in pkt_props - simply transmit rest of the packets
        pbuf *head = mitm.buf_alloc_copy((char *)get_eth_hdr(mbuf),
                                         rte_pktmbuf_data_len(mbuf));
        if ( head == nullptr ) {
            ERROR("mitm.buf_alloc_copy: failed allocating");
        }
        while ( (mbuf = mbuf->next) != nullptr ) {
            pbuf *chained_buf = nullptr;
            chained_buf = mitm.buf_alloc_copy((char *)get_eth_hdr(mbuf),
                                              rte_pktmbuf_data_len(mbuf));
            if ( chained_buf == nullptr ) {
                ERROR("mitm.buf_alloc_copy: failed allocating");
                break;
            }

            mitm.buf_chain(head, chained_buf);
        }
        if ( head != nullptr ) mitm.tx_eth_frame(head);
        return PKT_DROP;
    }

    if ( is_tcp && has_ack ) {
        dc = conn_table.tcp_existing_conn(pkt_props);
        if ( dc.decision == PKT_PASS && (pkt_props.sport == http_port_be ||
                                         pkt_props.sport == smtp_port_be) )
            do_filter = true;
    } else {
        dc = ruletable.query(&pkt_props, PKT_DROP);

        if ( is_tcp && dc.decision == PKT_PASS ) {
            dc = conn_table.tcp_new_conn(pkt_props, dc);
        }
    }

    if ( is_arp ) {
        auto *pbuf = mitm.buf_alloc_copy(rte_pktmbuf_mtod(&pkt, char *),
                                         rte_pktmbuf_pkt_len(&pkt));
        if ( pbuf == nullptr )
            ERROR("out of mem");
        else
            mitm.tx_eth_frame(pbuf);
    }

    if ( (pkt_props.tcp_flags & TCP_FIN_FLAG) != 0 ) {
        LOG("got FIN packet, do_filter = %s, dc.decision = %d, dc.reason = %d",
            do_filter ? "true" : "false", dc.decision, dc.reason);
    }

log:
    /* only log IPv4 traffic */
    if ( dc.reason != REASON_NONIPV4 )
        logger.store_log(log_row_t(pkt_props, dc));

    return dc.decision;
}

#include <rte_ether.h>
#include <rte_mbuf.h>

int add_ethernet_header(rte_mbuf *mbuf, const MAC_addr &src_mac,
                        const MAC_addr &dst_mac, const uint16_t ether_type) {

    struct rte_ether_hdr *eth_hdr = (struct rte_ether_hdr *)rte_pktmbuf_prepend(
        mbuf, sizeof(struct rte_ether_hdr));

    if ( eth_hdr == NULL ) {
        return -1;
    }

    memcpy(&eth_hdr->src_addr, src_mac.addr_bytes.data(), RTE_ETHER_ADDR_LEN);
    memcpy(&eth_hdr->dst_addr, dst_mac.addr_bytes.data(), RTE_ETHER_ADDR_LEN);
    /*
    MAC_addr tmp_mac;
    std::string tmp_mac_str = "42:dd:52:98:0f:4a";
    parse_mac_addr(tmp_mac_str, tmp_mac);
memcpy(&eth_hdr->dst_addr, tmp_mac.addr_bytes.data(), RTE_ETHER_ADDR_LEN);
    */

    eth_hdr->ether_type = rte_cpu_to_be_16(ether_type);

    mbuf->l2_len = sizeof(struct rte_ether_hdr);

    return 0;
}

/* @brief main DPDK loop that extracts packets, calls query_decision_and_log()
 * on each packet, and transmits the packet if the decision is PKT_PASS.

 * @param ruletable ruletable to pass to query_decision_and_log.
 * @param logger log instance to pass to query_decision_and_log.
 * @param conn_table connection table to pass to query_decision_and_log.
 * @param in_pdata DPDK port data of internal network NIC.
 * @param out_pdata DPDK port data of external network NIC.
 */
int firewall_loop(ruletable &ruletable, log_list &logger,
                  conn_table &conn_table, port_data &in_pdata,
                  port_data &out_pdata) {
    /*
     * 1. receive RX_BURST_SIZE packets (and store pointers to them in
     * recv_burst[]) using rte_eth_rx_burst()
     * 2. for each packet in recv_burst[], if packet is allowed, store it in
     * send_burst[].
     * 3. send all packets from send_burst[] with rte_eth_tx_burst()
     */
    uint16_t nb_pkts_rx = 0, nb_pkts_tx = 0, nb_pkts_tx_total = 0;
    uint16_t nb_ret_pkts = 0;
    /* how many packets to receive/transmit at once from NIC */
    constexpr auto   RX_BURST_SIZE = 10;
    struct rte_mbuf *recv_burst[RX_BURST_SIZE];
    struct rte_mbuf *send_burst[RX_BURST_SIZE];
    // array for "returning" packets (e.g packets from TCP reassembly), used by
    // pre_query_hook so its able to return more than 1 packet to be sent.
    struct rte_mbuf *send_returning[RX_BURST_SIZE];

    uint16_t in_port = in_pdata.port, out_port = out_pdata.port;
    // rx - receive, tx - transmit
    port_data *rx_pdata = &in_pdata;
    port_data *tx_pdata = &out_pdata;
    int        rx_port = in_port, tx_port = out_port;
    direction  direction = OUT;

    while ( !force_quit ) {
        /* switches between in_port and out_port, forwarding packets in both
         * directions in alternating order */
        std::swap(tx_pdata, rx_pdata);
        std::swap(tx_port, rx_port);
        direction = static_cast<enum direction>(direction ^ (OUT ^ IN));

        struct rte_mbuf *pkt;
        uint64_t         timestamp = rte_rdtsc();

        nb_pkts_rx = rte_eth_rx_burst(rx_port, 0, recv_burst, RX_BURST_SIZE);
        nb_pkts_tx_total = 0;
        nb_ret_pkts = 0;

        for ( int recv_pkt_idx = 0; recv_pkt_idx < nb_pkts_rx;
              recv_pkt_idx++ ) {
            // Pass the packet to the function - `pkt` should not be used
            // anymore.
            nb_ret_pkts =
                pre_query_hook(*rx_pdata, recv_burst[recv_pkt_idx],
                               &send_returning[nb_ret_pkts],
                               RX_BURST_SIZE - nb_ret_pkts, timestamp);

            for ( int i = 0; i < nb_ret_pkts; i++ ) {
                pkt = send_returning[i];
                pkt_props props = extract_pkt_props(*pkt, direction);
                if ( query_decision_and_log(*pkt, props, ruletable, logger,
                                            conn_table,
                                            filter_entry) == PKT_PASS ) {
                    send_burst[nb_pkts_tx_total++] = pkt;
                } else {
                    rte_pktmbuf_free(pkt);
                }
            }
        }

        static MITM_client client(80, filter_entry);
        client.process();

        struct rte_mbuf *mitm_send_burst_in[RX_BURST_SIZE];
        struct rte_mbuf *mitm_send_burst_out[RX_BURST_SIZE];
        int              mitm_nb_pkts_in_total = 0;
        int              mitm_nb_pkts_out_total = 0;
        size_t           mitm_buflen = 0;
        bool             datagram_dest_out;
        for ( int i = 0; i < RX_BURST_SIZE; i++ ) {
            auto buf_uptr = mitm.rx_eth_frame(&mitm_buflen);
            if ( buf_uptr == nullptr ) break;
            auto eth_type =
                ((struct rte_ether_hdr *)buf_uptr.get())->ether_type;
            struct rte_mbuf *mbuf = rte_pktmbuf_alloc(out_pdata.mempool);
            rte_pktmbuf_reset_headroom(mbuf);
            // check IP destination and send to correct network
            // (internal/external)
            if ( eth_type == FW_ETHTYPE_ARP ) {
                auto *arp_hdr = (struct rte_arp_hdr *)((char *)buf_uptr.get() +
                                                       ethhdr_size);
                // issue: if broadcast then should be sent on both ports,
                // technically...
                datagram_dest_out =
                    ((arp_hdr->arp_data.arp_tip & out_pdata.netmask) ==
                     out_pdata.routingprefix);
            } else if ( eth_type == FW_ETHTYPE_IPV4 ) {
                auto *buf_iphdr =
                    (struct rte_ipv4_hdr *)((char *)buf_uptr.get() +
                                            ethhdr_size);
                datagram_dest_out = (buf_iphdr->dst_addr & out_pdata.netmask) ==
                                    out_pdata.routingprefix;
                /*
                MAC_addr dest_mac =
                    (datagram_dest_out) ? out_pdata.mac : in_pdata.mac;
                MAC_addr src_mac =
                    (!datagram_dest_out) ? out_pdata.mac : in_pdata.mac;
                            if ( add_ethernet_header(mbuf, src_mac, dest_mac,
                FW_ETHTYPE_IPV4) != 0 ) { ERROR("Couldn't add ethernet header");
                    continue;
                }
                            */
            } else {
                throw std::runtime_error("Unknown ethernet protocol");
            }
            char *data = rte_pktmbuf_append(mbuf, mitm_buflen);
            if ( data == nullptr ) {
                ERROR("Couldn't append mitm_buflen");
                continue;
            }
            memcpy(data, buf_uptr.get(), rte_pktmbuf_data_len(mbuf));
            auto props = extract_pkt_props(*mbuf, datagram_dest_out ? OUT : IN);
            /*
if ( props.tcp_flags & TCP_ACK_FLAG ) {
    conn_table.tcp_existing_conn(props);
} else {
    decision_info dummy;
    dummy.decision = PKT_PASS;
    dummy.reason = REASON_RULE;
    dummy.rule_idx = -1;
    conn_table.tcp_new_conn(props, dummy);
}
            */
            if ( !datagram_dest_out )
                mitm_send_burst_in[mitm_nb_pkts_in_total++] = mbuf;
            else
                mitm_send_burst_out[mitm_nb_pkts_out_total++] = mbuf;
        }
        auto tx_frames = [](uint16_t port, struct rte_mbuf **pkts,
                            uint16_t nb_pkts_total) {
            /* rte_eth_tx_burst() is responsible for freeing sent packets */
            auto nb_pkts_tx = rte_eth_tx_burst(port, 0, pkts, nb_pkts_total);
            /* free unsent packets. if rte_eth_tx_burst() was unable to transmit
             * all packets, the tx queue is full. drop remaining packets to not
             * hold up the execution (instead of sending again) */
            for ( int i = nb_pkts_tx; i < nb_pkts_total; i++ ) {
                rte_pktmbuf_free(pkts[i]);
            }
        };
        if ( mitm_nb_pkts_in_total > 0 )
            LOG("sending %d packets in..", mitm_nb_pkts_in_total);
        tx_frames(in_port, mitm_send_burst_in, mitm_nb_pkts_in_total);

        if ( mitm_nb_pkts_out_total > 0 )
            LOG("sending %d packets out..", mitm_nb_pkts_out_total);
        tx_frames(out_port, mitm_send_burst_out, mitm_nb_pkts_out_total);

        tx_frames(tx_port, send_burst, nb_pkts_tx_total);

        // std::this_thread::sleep_for(std::chrono::milliseconds(70));
    }

    return 0;
}

/*
 * @brief initializes ports (NICs) with the specified MAC addresses, signal
 * handler SIGINT and starts the firewall
 * @param argc argv DPDK EAL params, see DPDK documentation on
 * linux_eal_parameters
 * @param ruletable reference to ruletable
 * @param in_mac out_mac MAC addresses of internal network NIC and external
 * network NIC respectively
 * @param logger log_list to record logs in
 */
int start_firewall(int argc, char **argv, ruletable &rt, MAC_addr in_mac,
                   be32_t in_routingprefix, be32_t in_netmask, MAC_addr out_mac,
                   be32_t out_routingprefix, be32_t out_netmask,
                   log_list &logger) {
    int ret;
    /* internal and external NIC identifiers, initialized with invalid
     * values (assigned real ones later) */
    struct rte_mempool *mbuf_pool;

    if ( init_sigint_handler() != 0 ) return EXIT_FAILURE;

    /* read about rte_eal_init() at
     * https://doc.dpdk.org/guides/prog_guide/env_abstraction_layer.html
     *
     * passing {argc, argv} allows passing special DPDK commandline options
     * and settings at execution. read more at
     * https://doc.dpdk.org/guides/linux_gsg/linux_eal_parameters.html
     *
     * documentation for error return values of rte_eal_init() are at
     * https://doc.dpdk.org/api/rte__eal_8h.html#a5c3f4dddc25e38c5a186ecd8a69260e3
     * there should be a switch() on rte_errno if error occurs
     */
    if ( (ret = rte_eal_init(argc, argv)) < 0 )
        rte_exit(EXIT_FAILURE, "error on initializing EAL. have you run "
                               "`sudo ./configure.sh`?\n");

    /* rte_eal_init may modify `ret` elements of argv, modify argc and argv
     * to match valid array elements */
    argc -= ret;
    argv += ret;

    /* create global DPDK memory pool */
    mbuf_pool = rte_pktmbuf_pool_create(
        "packet_pool",
        (nb_tx_rings + nb_rx_rings) * MBUF_POOL_ELMS_PER_RING * 2,
        0 /* setting cache_size to 0 disables this feature */, 0,
        MITM_MAX_EGRESS_DATAGRAM_SIZE + RTE_PKTMBUF_HEADROOM, SOCKET_ID_ANY);
    if ( mbuf_pool == NULL ) {
        rte_exit(1, "Couldn't create pktmbuf_pool");
    }

    /**************************
     * iterates over all available ports, checking each port's MAC. if the
     * MAC matches internal/external port MACs given in function parameters,
     * set int_port/ext_port to its matching DPDK port number.
     */

    /* NIC to initialize */
    uint16_t   port;
    port_data *pdata = nullptr;
    /* -1 is sentinel value to indicate failure */
    port_data int_port(-1, in_routingprefix, in_netmask, in_mac, mbuf_pool);
    port_data ext_port(-1, out_routingprefix, out_netmask, out_mac, mbuf_pool);
    RTE_ETH_FOREACH_DEV(port) {
        struct rte_ether_addr addr;
        if ( rte_eth_macaddr_get(port, &addr) < 0 ) {
            ERROR("Couldn't get MAC address for port %u", port);
            continue;
        }

        MAC_addr port_maddr = MAC_addr(addr.addr_bytes[0], addr.addr_bytes[1],
                                       addr.addr_bytes[2], addr.addr_bytes[3],
                                       addr.addr_bytes[4], addr.addr_bytes[5]);

        if ( port_maddr == in_mac ) {
            int_port.port = port;
            pdata = &int_port;
        } else if ( port_maddr == out_mac ) {
            ext_port.port = port;
            pdata = &ext_port;
        } else
            continue;

        if ( port_init(*pdata) < 0 ) {
            rte_exit(1, "Couldn't initialize port %u\n", port);
        }
        printf("Initialized port %u\n", port);
    }

    conn_table *conn_table = new class conn_table();

    if ( int_port.port == (uint16_t)(-1) ) {
        ERROR("Port with specified internal MAC address not found");
        goto cleanup;
    }

    if ( ext_port.port == (uint16_t)(-1) ) {
        ERROR("Port with specified external MAC address not found");
        goto cleanup;
    }

    /* main firewall loop. force_quit is used to stop the firewall loop when
     * Ctrl+C is pressed (see sigint_handler()). */
    if ( firewall_loop(rt, logger, *conn_table, int_port, ext_port) < 0 ) {
        ERROR("Couldn't execute firewall_loop()");
        goto cleanup;
    }

cleanup:
    if ( rte_eth_dev_stop(int_port.port) != 0 )
        rte_exit(1, "Couldn't stop internal port");
    if ( rte_eth_dev_stop(ext_port.port) != 0 )
        rte_exit(1, "Couldn't stop external port");

    // must free ip_frag_tbl before rte_eal_cleanup, or get segfault
    int_port.cleanup();
    ext_port.cleanup();

    if ( rte_eal_cleanup() < 0 ) {
        ERROR("error on releasing resources\n");
        return -1;
    }

    return 0;
}

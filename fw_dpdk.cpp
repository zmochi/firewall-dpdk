#include <cstring>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_memory.h>
#include <signal.h>

#include "utils.h"

static const uint16_t nb_rx_rings = 1, nb_tx_rings = 1;
const int             MBUF_POOL_ELMS_PER_RING = 1024;
static uint16_t       int_port, ext_port;
volatile bool         force_quit;

int port_init(uint16_t port, struct rte_mempool *mbuf_pool) {
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
    force_quit = true;

    printf("Stopping gracefully...\n");

    /*if ( sigaction(SIGINT, &old_act, nullptr) != 0 ) {
        ERROR("Couldn't install old signal handler");
        return;
    }

    raise(SIGINT);*/
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

/* eth, ip, and tcp header structs: */
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_tcp.h>

#include "conn_table.hpp"
#include "firewall.hpp"
#include "logger.hpp"
#include "packet.hpp"
#include "ruletable.hpp"

/* @brief fills pkt_props struct with data from packet.
 * if packet is not long enough to contain all fields in the pkt_props struct,
 * the struct instance is returned partially filled (unfilled fields get their
 * respective NUL/INVALID special values) with all available info.
 *
 * @return the pkt_props struct instance.
 */
pkt_props extract_pkt_props(struct rte_mbuf &pkt, direction pkt_direction) {
    struct pkt_props    pkt_props;
    struct rte_tcp_hdr *tcp_hdr = {};

    /* struct rte_mbuf of the packet is stored right behind it in memory.
     * rte_pktmbuf_mtod() returns a pointer to the data (the packet itself)
     * of a struct rte_mbuf. for details:
     * https://doc.dpdk.org/guides/prog_guide/mbuf_lib.html
     */
    struct rte_ether_hdr *eth_hdr =
        rte_pktmbuf_mtod(&pkt, struct rte_ether_hdr *);
    size_t           eff_pktlen = rte_pktmbuf_pkt_len(&pkt);
    constexpr size_t ethhdr_size = sizeof(struct rte_ether_hdr),
                     ipv4hdr_size = sizeof(struct rte_ipv4_hdr),
                     ipv6hdr_size = sizeof(struct rte_ipv6_hdr),
                     tcphdr_size = sizeof(struct rte_tcp_hdr),
                     udphdr_size = sizeof(struct rte_udp_hdr),
                     icmphdr_size = sizeof(struct rte_icmp_hdr);

    if ( eff_pktlen < ethhdr_size ) {
        ERROR("Packet too small to contain ethernet header");
        pkt_props.eth_proto = ETHTYPE_NUL;
        return pkt_props;
    }

    pkt_props.eth_proto = static_cast<eth_proto>(eth_hdr->ether_type);

    eff_pktlen -= ethhdr_size;

    if ( pkt_props.eth_proto == ETHTYPE_IPV4 ) {
        if ( eff_pktlen < ipv4hdr_size ) {
            pkt_props.eth_proto = ETHTYPE_NUL;
            return pkt_props;
        }
        struct rte_ipv4_hdr *ipv4_hdr =
            (struct rte_ipv4_hdr *)((char *)eth_hdr + ethhdr_size);
        pkt_props.proto = static_cast<proto>(ipv4_hdr->next_proto_id);

        /* store in network order */
        pkt_props.saddr = ipv4_hdr->src_addr;
        pkt_props.daddr = ipv4_hdr->dst_addr;

        eff_pktlen -= ipv4hdr_size;

        if ( ipv4_hdr->next_proto_id == IPPROTO_TCP ) {
            if ( eff_pktlen < tcphdr_size ) {
                pkt_props.proto = NUL_PROTO;
                return pkt_props;
            }
            tcp_hdr = (struct rte_tcp_hdr *)((char *)ipv4_hdr + ipv4hdr_size);
            pkt_props.sport = tcp_hdr->src_port;
            pkt_props.dport = tcp_hdr->dst_port;
            pkt_props.tcp_flags =
                static_cast<enum tcp_flags>(tcp_hdr->tcp_flags);
        } else if ( ipv4_hdr->next_proto_id == IPPROTO_UDP ) {
            if ( eff_pktlen < udphdr_size ) {
                pkt_props.proto = NUL_PROTO;
                return pkt_props;
            }
            struct rte_udp_hdr *udp_hdr =
                (struct rte_udp_hdr *)((char *)ipv4_hdr + ipv4hdr_size);
            pkt_props.sport = udp_hdr->src_port;
            pkt_props.dport = udp_hdr->dst_port;
        }
    }

    pkt_props.direction = pkt_direction;

    return pkt_props;
}

pkt_dc query_decision_and_log(struct rte_mbuf &pkt, struct ruletable &ruletable,
                              direction pkt_direction, log_list &logger,
                              conn_table &conn_table) {
    pkt_props     pkt_props = extract_pkt_props(pkt, pkt_direction);
    decision_info dc;

    if ( pkt_props.eth_proto != ETHTYPE_IPV4 ) {
        return PKT_PASS;
    }

    if ( pkt_props.proto == IPPROTO_TCP &&
         pkt_props.tcp_flags & TCP_ACK_FLAG ) {
        dc = conn_table.tcp_existing_conn(pkt_props);
    } else {
        dc = ruletable.query(&pkt_props, PKT_DROP);

        if ( pkt_props.proto == IPPROTO_TCP && dc.decision != PKT_DROP ) {
            dc = conn_table.tcp_new_conn(pkt_props, dc);
        }
    }

    /* only log IPv4 traffic */
    if ( dc.reason != REASON_NONIPV4 )
        logger.store_log(log_row_t(pkt_props, dc));

    return dc.decision;
}

/* @brief switches the source MAC address in pkt to the MAC address of port
 * @param pkt pointer to packet (rte_mbuf) whose src MAC address to switch
 * @param port identifier of port that has the new mac address
 */
int switch_src_maddr(struct rte_mbuf *pkt, uint16_t port) {
    if ( rte_pktmbuf_pkt_len(pkt) < sizeof(struct rte_ether_hdr) ) {
        ERROR(
            "Packet too short, not enough space to contain an ethernet header");
        return -1;
    }

    struct rte_ether_hdr *pkt_ethhdr =
        rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
    struct rte_ether_addr new_mac;
    rte_eth_macaddr_get(port, &new_mac);

    rte_ether_addr_copy(&new_mac, &pkt_ethhdr->src_addr);

    return 0;
}

int firewall_loop(struct ruletable &ruletable, log_list &logger,
                  conn_table &conn_table, uint16_t in_port, uint16_t out_port) {
    /*
     * 1. receive RX_BURST_SIZE packets (and store pointers to them in
     * recv_burst[]) using rte_eth_rx_burst()
     * 2. for each packet in recv_burst[], if packet is allowed, store it in
     * send_burst[].
     * 3. send all packets from send_burst[] with rte_eth_tx_burst()
     */
    uint16_t nb_pkts_rx = 0, nb_pkts_tx = 0, nb_pkts_tx_total = 0;
    /* how many packets to receive/transmit at once from NIC */
    constexpr auto   RX_BURST_SIZE = 10;
    struct rte_mbuf *recv_burst[RX_BURST_SIZE];
    struct rte_mbuf *send_burst[RX_BURST_SIZE];

    int       rx_port = in_port, tx_port = out_port;
    direction direction = OUT;

    while ( !force_quit ) {
        /* switches between in_port and out_port, forwarding packets in both
         * directions in alternating order */
        rx_port ^= (in_port ^ out_port);
        tx_port ^= (in_port ^ out_port);
        direction = static_cast<enum direction>(direction ^ (OUT ^ IN));

        nb_pkts_rx = rte_eth_rx_burst(rx_port, 0, recv_burst, RX_BURST_SIZE);

        nb_pkts_tx_total = 0;
        for ( int recv_pkt_idx = 0; recv_pkt_idx < nb_pkts_rx;
              recv_pkt_idx++ ) {
            if ( query_decision_and_log(*recv_burst[recv_pkt_idx], ruletable,
                                        direction, logger,
                                        conn_table) == PKT_PASS ) {
                struct rte_mbuf *pkt = recv_burst[recv_pkt_idx];
                send_burst[nb_pkts_tx_total++] = pkt;
            }
        }

        /* rte_eth_tx_burst() is responsible for freeing sent packets */
        nb_pkts_tx = rte_eth_tx_burst(tx_port, 0, send_burst, nb_pkts_tx_total);

        /* free unsent packets. if rte_eth_tx_burst() was unable to transmit all
         * packets, the tx queue is full. drop remaining packets to not hold up
         * the execution (instead of sending again) */
        for ( int i = nb_pkts_tx; i < nb_pkts_tx_total; i++ ) {
            rte_pktmbuf_free(send_burst[i]);
        }
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
                   MAC_addr out_mac, log_list &logger) {
    int ret;
    /* internal and external NIC identifiers, initialized with invalid values
     * (assigned real ones later) */
    struct rte_mempool *mbuf_pool;

    if ( init_sigint_handler() != 0 ) return EXIT_FAILURE;

    /* read about rte_eal_init() at
     * https://doc.dpdk.org/guides/prog_guide/env_abstraction_layer.html
     *
     * passing {argc, argv} allows passing special DPDK commandline options and
     * settings at execution. read more at
     * https://doc.dpdk.org/guides/linux_gsg/linux_eal_parameters.html
     *
     * documentation for error return values of rte_eal_init() are at
     * https://doc.dpdk.org/api/rte__eal_8h.html#a5c3f4dddc25e38c5a186ecd8a69260e3
     * there should be a switch() on rte_errno if error occurs
     */
    if ( (ret = rte_eal_init(argc, argv)) < 0 )
        rte_exit(
            EXIT_FAILURE,
            "error on initializing EAL. have you run `sudo ./configure.sh`?\n");

    /* rte_eal_init may modify `ret` elements of argv, modify argc and argv to
     * match valid array elements */
    argc -= ret;
    argv += ret;

    mbuf_pool = rte_pktmbuf_pool_create(
        "packet_pool",
        (nb_tx_rings + nb_rx_rings) * MBUF_POOL_ELMS_PER_RING * 2,
        0 /* setting cache_size to 0 disables this feature */, 0, 1024,
        SOCKET_ID_ANY);
    if ( mbuf_pool == NULL ) {
        rte_exit(1, "Couldn't create pktmbuf_pool");
    }

    /* sentinel values to indicate failure */
    int_port = 0xFFFF, ext_port = 0xFFFF;
    /* NIC to initialize */
    uint16_t port;
    RTE_ETH_FOREACH_DEV(port) {
        struct rte_ether_addr addr;
        if ( rte_eth_macaddr_get(port, &addr) < 0 ) {
            ERROR("Couldn't get MAC address for port %u", port);
            continue;
        }

        MAC_addr port_maddr = MAC_addr(addr.addr_bytes[0], addr.addr_bytes[1],
                                       addr.addr_bytes[2], addr.addr_bytes[3],
                                       addr.addr_bytes[4], addr.addr_bytes[5]);

        if ( port_maddr == in_mac )
            int_port = port;
        else if ( port_maddr == out_mac )
            ext_port = port;
        else
            continue;

        if ( port_init(port, mbuf_pool) < 0 ) {
            rte_exit(1, "Couldn't initialize port %u\n", port);
        }
        printf("Initialized port %u\n", port);
    }

    conn_table conn_table;

    if ( int_port == 0xFFFF ) {
        ERROR("Port with specified internal MAC address not found");
        goto cleanup;
    }

    if ( ext_port == 0xFFFF ) {
        ERROR("Port with specified external MAC address not found");
        goto cleanup;
    }

    force_quit = false;
    if ( firewall_loop(rt, logger, conn_table, int_port, ext_port) < 0 ) {
        ERROR("Couldn't execute firewall_loop()");
        goto cleanup;
    }

cleanup:
    if ( rte_eth_dev_stop(int_port) != 0 )
        rte_exit(1, "Couldn't stop internal port");
    if ( rte_eth_dev_stop(ext_port) != 0 )
        rte_exit(1, "Couldn't stop external port");

    if ( rte_eal_cleanup() < 0 ) {
        ERROR("error on releasing resources\n");
        return -1;
    }

    return 0;
}

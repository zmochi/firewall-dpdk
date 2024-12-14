#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_memory.h>
#include <signal.h>

#include "utils.h"

static const uint16_t nb_rx_rings = 1, nb_tx_rings = 1;
const int             MBUF_POOL_ELMS_PER_RING = 1024;

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

    if ( !rte_eth_dev_is_valid_port(port) ) return -1;

    ret = rte_eth_dev_info_get(port, &dev_info);
    uint64_t dev_tx_capa = dev_info.tx_offload_capa;
    uint64_t dev_rx_capa = dev_info.rx_offload_capa;
    if ( !(dev_tx_capa & RTE_ETH_TX_OFFLOAD_IPV4_CKSUM) ||
         !(dev_tx_capa & RTE_ETH_TX_OFFLOAD_TCP_CKSUM) ||
         !(dev_rx_capa & RTE_ETH_RX_OFFLOAD_IPV4_CKSUM) ||
         !(dev_rx_capa & RTE_ETH_RX_OFFLOAD_TCP_CKSUM) ) {
        ERROR("Device doesn't support required offload capabilities\n");
        return -1;
    }

    /* use default rx/tx configuration given by driver in
     * rte_eth_dev_info_get(), and have the device calculate and verify IP and
     * TCP checksums of incoming (rx) and outgoing (tx) packets.
     *
     * portconf is used to configure the NIC, rxconf and txconf are used to
     * configure each ring on the NIC (not sure if rxconf/txconf have to be
     * configured with the offloads separately) */
    uint64_t offloads =
        RTE_ETH_TX_OFFLOAD_IPV4_CKSUM | RTE_ETH_RX_OFFLOAD_TCP_CKSUM;
    txconf = dev_info.default_txconf;
    rxconf = dev_info.default_rxconf;
    port_conf.txmode.offloads |= offloads;
    port_conf.rxmode.offloads |= offloads;
    txconf.offloads |= offloads;
    rxconf.offloads |= offloads;

    /* configure NIC
     * must adjust port settings on port_conf before this */
    ret = rte_eth_dev_configure(port, nb_rx_rings, nb_tx_rings, &port_conf);

    /* if nb_rx/tx_dsc are above maximum number of rx/tx descriptors driver can
     * handle, this adjusts them to a valid value (rx/tx descriptors are slots
     * in the rx/tx rings that hold packets) */
    ret = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rx_dsc, &nb_tx_dsc);

    /* for each ring, set number of tx descriptors */
    for ( int i = 0; i < nb_tx_rings; i++ ) {
        ret = rte_eth_tx_queue_setup(port, i, nb_tx_dsc,
                                     rte_eth_dev_socket_id(port), &txconf);
        if ( ret < 0 ) return -1;
    }

    /* for each ring, set number of rx descriptors */
    for ( int i = 0; i < nb_rx_rings; i++ ) {
        ret = rte_eth_rx_queue_setup(port, i, nb_rx_dsc,
                                     rte_eth_dev_socket_id(port), &rxconf,
                                     mbuf_pool);
        if ( ret < 0 ) return -1;
    }

    return 0;
}

void sigint_handler(int sig) {
    if ( rte_eal_cleanup() < 0 ) rte_exit(1, "error on releasing resources\n");
}

int init_sigint_handler() {
    struct sigaction act;
    act.sa_handler = sigint_handler;
    if ( sigaction(SIGINT, &act, NULL) != 0 ) {
        printf("Couldn't assign handler to SIGINT\n");
    }

    return 0;
}

/* eth, ip, and tcp header structs: */
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_tcp.h>

#include "firewall.hpp"
#include "logger.hpp"
#include "packet.hpp"
#include "ruletable.hpp"

pkt_dc query_decision_and_log(struct rte_mbuf &pkt, struct ruletable &ruletable,
                              direction pkt_direction, int log_write_fd) {
    const rte_be16_t    ETHTYPE_IPV4 = htobe16(513);
    struct pkt_props    pkt_props;
    struct rte_tcp_hdr *tcp_hdr = {};
    // const unsigned char IPPROTO_TCP = 6;

    /* struct rte_mbuf of the packet is stored right behind it in memory.
     * rte_pktmbuf_mtod() returns a pointer to the data (the packet itself)
     * of a struct rte_mbuf. for details:
     * https://doc.dpdk.org/guides/prog_guide/mbuf_lib.html
     */
    struct rte_ether_hdr *eth_hdr =
        rte_pktmbuf_mtod(&pkt, struct rte_ether_hdr *);
    if ( eth_hdr->ether_type != ETHTYPE_IPV4 ) return PKT_DROP;

    struct rte_ipv4_hdr *ipv4_hdr =
        (struct rte_ipv4_hdr *)((char *)eth_hdr + sizeof(struct rte_ether_hdr));

    /* store in network order */
    pkt_props.saddr = ipv4_hdr->src_addr;
    pkt_props.daddr = ipv4_hdr->dst_addr;

    if ( ipv4_hdr->next_proto_id == IPPROTO_TCP ) {
        tcp_hdr = (struct rte_tcp_hdr *)((char *)ipv4_hdr +
                                         sizeof(struct rte_ipv4_hdr));
        pkt_props.sport = tcp_hdr->src_port;
        pkt_props.dport = tcp_hdr->dst_port;
        pkt_props.tcp_flags = static_cast<enum tcp_flags>(tcp_hdr->tcp_flags);
    }

    pkt_props.proto = static_cast<proto>(ipv4_hdr->next_proto_id);

    uint64_t XMAS_PKT_FLAGS = TCP_FIN_FLAG | TCP_URG_FLAG | TCP_PSH_FLAG;
    pkt_dc   dc;
    reason_t reason;

    if ( (pkt_props.tcp_flags & XMAS_PKT_FLAGS) == XMAS_PKT_FLAGS ) {
        dc = PKT_DROP;
        reason = REASON_XMAS_PKT;
    } else {
        decision_info dc_info = ruletable.query(&pkt_props);
        dc = dc_info.decision;
        /* either REASON_NO_RULE or REASON_RULE */
        reason = dc_info.reason;
    }

    pkt_props.direction = pkt_direction;
    write_log(pkt_props, dc, reason, log_write_fd);

    return dc;
}

int firewall_loop(struct ruletable &ruletable, int log_fd, uint16_t in_port,
                  uint16_t out_port, uint16_t int_port, uint16_t ext_port) {
    /*
     * 1. receive RX_BURST_SIZE packets (and store pointers to them in
     * recv_burst[]) using rte_eth_rx_burst()
     * 2. for each packet in recv_burst[], if packet is allowed, store it in
     * send_burst[].
     * 3. send all packets from send_burst[] with rte_eth_tx_burst()
     */
    uint16_t nb_pkts_in = 0, nb_pkts_sent = 0, nb_pkts_out_total = 0;
    /* how many packets to receive at once from NIC in_port */
    constexpr auto   RX_BURST_SIZE = 100;
    struct rte_mbuf *recv_burst[RX_BURST_SIZE];
    struct rte_mbuf *send_burst[RX_BURST_SIZE];
    direction        direction;
    if ( in_port == int_port && out_port == ext_port ) {
        direction = OUT;
    } else if ( in_port == ext_port && out_port == in_port ) {
        direction = IN;
    } else {
        ERROR("Bad port configuration");
        return -1;
    }

    while ( true ) {
        nb_pkts_in = rte_eth_rx_burst(out_port, 0, recv_burst, RX_BURST_SIZE);

        for ( int recv_pkt_idx = 0; recv_pkt_idx < nb_pkts_in;
              recv_pkt_idx++ ) {
            if ( query_decision_and_log(*recv_burst[recv_pkt_idx], ruletable,
                                        direction, log_fd) == PKT_PASS ) {
                send_burst[nb_pkts_out_total++] = recv_burst[recv_pkt_idx];
            }
        }

        while ( nb_pkts_sent < nb_pkts_out_total ) {
            nb_pkts_sent += rte_eth_tx_burst(
                in_port, 0, send_burst + nb_pkts_sent, nb_pkts_sent);
        }

        nb_pkts_out_total = nb_pkts_sent = 0;
    }
}

/*
 * @brief initializes ports (NICs) with the specified MAC addresses, signal
 * handler SIGINT and starts the firewall
 * @param argc argv DPDK EAL params, see DPDK documentation on
 * linux_eal_parameters
 * @param ruletable reference to ruletable
 * @param in_mac out_mac MAC addresses of internal network NIC and external
 * network NIC respectively
 * @param log_fd file descriptor for transmitting logs, each write to the fd is
 * an entire log_row_t
 */
int start_firewall(int argc, char **argv, struct ruletable &ruletable,
                   MAC_addr in_mac, MAC_addr out_mac, int log_fd) {
    int ret;
    /* internal and external NIC identifiers, initialized with invalid values
     * (assigned real ones later) */
    uint16_t            int_port = 0xFFFF, ext_port = 0xFFFF;
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
        rte_exit(EXIT_FAILURE, "error on initializing EAL\n");

    /* rte_eal_init may modify `ret` elements of argv, modify argc and argv to
     * match valid array elements */
    argc -= ret;
    argv += ret;

    mbuf_pool = rte_pktmbuf_pool_create(
        "packet_pool", (nb_tx_rings + nb_rx_rings) * MBUF_POOL_ELMS_PER_RING,
        0 /* setting cache_size to 0 disables this feature */, 0, 1024,
        SOCKET_ID_ANY);
    if ( mbuf_pool == NULL ) {
        rte_exit(1, "Couldn't create pktmbuf_pool");
    }

    /* NIC to initialize */
    uint16_t port;
    RTE_ETH_FOREACH_DEV(port) {
        struct rte_ether_addr addr;
        if ( rte_eth_macaddr_get(port, &addr) < 0 ) {
            ERROR("Couldn't get MAC address for port %u", port);
            continue;
        }

        if ( memcmp(addr.addr_bytes, in_mac.addr_bytes, MAC_ADDR_LEN) == 0 )
            int_port = port;
        else if ( memcmp(addr.addr_bytes, out_mac.addr_bytes, MAC_ADDR_LEN) ==
                  0 )
            ext_port = port;
        else
            continue;

        if ( port_init(port, mbuf_pool) < 0 ) {
            ERROR("Couldn't initialize port %u", port);
            return -1;
        }
        printf("initialized port %u\n", port);
    }

    if ( int_port == 0xFFFF ) {
        ERROR("Port with specified internal MAC address not found");
        goto cleanup;
    }

    if ( ext_port == 0xFFFF ) {
        ERROR("Port with specified external MAC address not found");
        goto cleanup;
    }

    firewall_loop(ruletable, log_fd, int_port, ext_port);

    // int ruletable_fd = shm_open(RULETABLE_SHM_KEY, O_RDONLY,
    // RULETABLE_SHM_MODE); ruletable = mmap(NULL, RULETABLE_SIZE, PROT_READ,
    // MAP_SHARED, ruletable_fd, 0);

    /* cleanup also handled in SIGINT handler */
cleanup:
    if ( rte_eal_cleanup() < 0 ) rte_exit(1, "error on releasing resources\n");
}

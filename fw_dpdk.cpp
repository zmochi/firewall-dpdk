#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_memory.h>
#include <signal.h>

#define EXT_IFACE 1
#define INT_IFACE 0

static const uint16_t nb_rx_rings = 1, nb_tx_rings = 1;
const int MBUF_POOL_ELMS_PER_RING = 1024;

uint16_t tx_cb(uint16_t port_id, uint16_t queue, struct rte_mbuf *pkts[],
		uint16_t nb_pkts, void *user_param) {
	printf("hello from tx! port %u\n", port_id);
}

uint16_t rx_cb(uint16_t port_id, uint16_t queue, struct rte_mbuf *pkts[],
		uint16_t nb_pkts, uint16_t max_pkts, void *user_param) {
	printf("hello from rx! port %u\n", port_id);
}

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
	int ret;
	struct rte_eth_conf port_conf = {};
	struct rte_eth_dev_info dev_info;
	struct rte_eth_txconf txconf;
	struct rte_eth_rxconf rxconf;
	uint16_t nb_rx_dsc = MBUF_POOL_ELMS_PER_RING, nb_tx_dsc = MBUF_POOL_ELMS_PER_RING;

	if (!rte_eth_dev_is_valid_port(port))
		return -1;

	ret = rte_eth_dev_info_get(port, &dev_info);
	uint64_t dev_tx_capa = dev_info.tx_offload_capa;
	uint64_t dev_rx_capa = dev_info.rx_offload_capa;
	if(!(dev_tx_capa & RTE_ETH_TX_OFFLOAD_IPV4_CKSUM) || !(dev_tx_capa & RTE_ETH_TX_OFFLOAD_TCP_CKSUM) || !(dev_rx_capa & RTE_ETH_RX_OFFLOAD_IPV4_CKSUM) || !(dev_rx_capa & RTE_ETH_RX_OFFLOAD_TCP_CKSUM)) {
		printf("%s: Device doesn't support required offload capabilities\n", __func__);
		return -1;
	}

	/* use default rx/tx configuration given by driver in rte_eth_dev_info_get(), and have the device
	 * calculate and verify IP and TCP checksums of incoming (rx) and outgoing (tx) packets.
	 *
	 * portconf is used to configure the NIC, rxconf and txconf are used to configure each ring on the NIC 
	 * (not sure if rxconf/txconf have to be configured with the offloads separately) */
	txconf = dev_info.default_txconf;
	rxconf = dev_info.default_rxconf;
	port_conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_IPV4_CKSUM | RTE_ETH_RX_OFFLOAD_TCP_CKSUM;
	port_conf.rxmode.offloads |= RTE_ETH_RX_OFFLOAD_IPV4_CKSUM | RTE_ETH_RX_OFFLOAD_TCP_CKSUM;
	txconf.offloads |= RTE_ETH_TX_OFFLOAD_IPV4_CKSUM | RTE_ETH_RX_OFFLOAD_TCP_CKSUM;
	rxconf.offloads |= RTE_ETH_RX_OFFLOAD_IPV4_CKSUM | RTE_ETH_RX_OFFLOAD_TCP_CKSUM;

	/* configure NIC
	 * must adjust port settings on port_conf before this */
	ret = rte_eth_dev_configure(port, nb_rx_rings, nb_tx_rings, &port_conf);

	/* if nb_rx/tx_dsc are above maximum number of rx/tx descriptors driver can handle, this adjusts them to a valid value 
	 * (rx/tx descriptors are slots in the rx/tx rings that hold packets) */
	ret = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rx_dsc, &nb_tx_dsc);

	/* for each ring, set number of tx descriptors */
	for (int i = 0; i < nb_tx_rings; i++) {
		ret = rte_eth_tx_queue_setup(port, i, nb_tx_dsc,
				rte_eth_dev_socket_id(port), &txconf);
		if (ret < 0)
			return -1;
	}

	/* for each ring, set number of rx descriptors */
	for (int i = 0; i < nb_rx_rings; i++) {
		ret = rte_eth_rx_queue_setup(
				port, i, nb_rx_dsc, rte_eth_dev_socket_id(port), &rxconf, mbuf_pool);
		if (ret < 0)
			return -1;
	}

	/* add callbacks for each ring */
	//for (int i = 0; i < nb_tx_rings; i++) {
	//	rte_eth_add_tx_callback(port, i, tx_cb, NULL);
	//}

	//for (int i = 0; i < nb_rx_rings; i++) {
	//	rte_eth_add_rx_callback(port, i, rx_cb, NULL);
	//}
}

void sigint_handler() {
	if (rte_eal_cleanup() < 0)
		rte_exit(1, "error on releasing resources\n");
}

int init_sigint_handler() {
	struct sigaction act;
	act.sa_handler = sigint_handler;
	if(sigaction(SIGINT, &act, NULL) != 0) {
		printf("Couldn't assign handler to SIGINT\n");
		///* use fwrite in case SIGINT interrupts a print function.
		// * add \n before err_msg in case printing was interrupted */
		//const char* err_msg = "\nCouldn't assign handler to SIGINT\n";
		//fwrite(err_msg, sizeof(*err_msg), strlen(err_msg), stdout);
	}

	return 0;
}

/* shared memory: */
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
/* eth, ip, and tcp header structs: */
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_ether.h>

#include "packet.h"
#include "ruletable.h"
#include "logger.h"

/* change RULETABLE_SIZE */
#define RULETABLE_SHM_MODE 600

pkt_dc incoming_packet_ok(struct rte_mbuf* pkt, struct ruletable* ruletable) {
	const rte_be16_t ETHTYPE_IPV4 = htobe16(513);
	struct pkt_props pkt_props = {};
	struct rte_tcp_hdr* tcp_hdr = {};
	//const unsigned char IPPROTO_TCP = 6;

	/* struct rte_mbuf of the packet is stored right behind it in memory.
	 * rte_pktmbuf_mtod() returns a pointer to the data (the packet itself)
	 * of a struct rte_mbuf. for details:
	 * https://doc.dpdk.org/guides/prog_guide/mbuf_lib.html
	 */
	struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr*);
	if(eth_hdr->ether_type != ETHTYPE_IPV4)
		return PKT_DROP;

	struct rte_ipv4_hdr *ipv4_hdr = (struct rte_ipv4_hdr*)((char*)eth_hdr + sizeof(struct rte_ether_hdr));

	/* store in network order */
	pkt_props.saddr = ipv4_hdr->src_addr;
	pkt_props.daddr = ipv4_hdr->dst_addr;

	if(ipv4_hdr->next_proto_id == IPPROTO_TCP) {
		tcp_hdr = (struct rte_tcp_hdr*)((char*)ipv4_hdr + sizeof(struct rte_ipv4_hdr));
		pkt_props.sport = tcp_hdr->src_port;
		pkt_props.dport = tcp_hdr->dst_port;
		pkt_props.tcp_flags = tcp_hdr->tcp_flags;
	}

	pkt_props.proto = ipv4_hdr->next_proto_id;

	pkt_dc dc = query_ruletable(ruletable, &pkt_props);
	write_log(pkt_props, dc, REASON_RULE, log_write_fd);

	return dc;
}

int start_firewall(int argc, char **argv, struct ruletable* ruletable) {
	int ret;
	int interface;
	/* NIC to initialize */
	uint16_t port;
	/* internal and external NIC identifiers */
	uint16_t int_port = -1, ext_port = -1;
	struct rte_mempool *mbuf_pool;

	if(init_sigint_handler() != 0)
		return EXIT_FAILURE;

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
	if ((ret = rte_eal_init(argc, argv)) < 0)
		rte_exit(EXIT_FAILURE, "error on initializing EAL\n");

	/* rte_eal_init may modify `ret` elements of argv, modify argc and argv to
	 * match valid array elements */
	argc -= ret;
	argv += ret;

	/* TODO: parse args to get internal and external interface using MAC addresses as identifiers from user */

	mbuf_pool = rte_pktmbuf_pool_create(
			"packet_pool", (nb_tx_rings + nb_rx_rings) * MBUF_POOL_ELMS_PER_RING,
			0 /* setting cache_size to 0 disables this feature */, 0, 1024,
			SOCKET_ID_ANY);
	if (mbuf_pool == NULL) {
		rte_exit(1, "Couldn't create pktmbuf_pool");
	}

	printf("%u\n", rte_eth_dev_count_avail());

	RTE_ETH_FOREACH_DEV(port) {
		port_init(port, mbuf_pool);
		printf("initialized port %u\n", port);
	}

	/* get pointer to ruletable in shared memory */

	//int ruletable_fd = shm_open(RULETABLE_SHM_KEY, O_RDONLY, RULETABLE_SHM_MODE);
	//ruletable = mmap(NULL, RULETABLE_SIZE, PROT_READ, MAP_SHARED, ruletable_fd, 0);

	/* 
	 * 1. receive RX_BURST_SIZE packets (and store pointers to them in recv_burst[]) using rte_eth_rx_burst()
	 * 2. for each packet in recv_burst[], if packet is allowed, store it in send_burst[].
	 * 3. send all packets from send_burst[] with rte_eth_tx_burst()
	 */
	uint16_t nb_pkts_recv = 0, nb_pkts_send = 0;
	const int RX_BURST_SIZE = 100;
	struct rte_mbuf* recv_burst[RX_BURST_SIZE];
	struct rte_mbuf* send_burst[RX_BURST_SIZE];

	while(true) {
		nb_pkts_recv = rte_eth_rx_burst(ext_port, 0, recv_burst, RX_BURST_SIZE);

		for(int recv_pkt_idx = 0; recv_pkt_idx < nb_pkts_recv; recv_pkt_idx++) {
			if(incoming_packet_ok(recv_burst[recv_pkt_idx], ruletable)) {
				send_burst[nb_pkts_send++] = recv_burst[recv_pkt_idx];
			}
		}

		rte_eth_tx_burst(int_port, 0, send_burst, nb_pkts_send);
	}

	/* cleanup handled in SIGINT handler */
	if (rte_eal_cleanup() < 0)
		rte_exit(1, "error on releasing resources\n");
}

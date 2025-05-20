#ifndef __CONN_TABLE_H
#define __CONN_TABLE_H

#include "endian.hpp"
#include "fnv_hash.hpp"
#include "packet.hpp"
#include <unordered_map>

/* states aligned with names in Wikipedia table
 * en.wikipedia.org/wiki/Transmission_Control_Protocol#Protocol_operation
 * under "Protocol operation"
 */

/* TWH stands for Three Way Handshake */
enum state_t {
    STATE_NUL,
    TWH_SYN_SENT,
    TWH_SYN_ACK_RECEIVED,
    TWH_SYN_ACK_SENT,
    TWH_ACK_RECEIVED,
    CONN_ESTABLISHED,
    /* fin sent only */
    FIN_SENT,
    /* fin sent and acked */
    FIN_ACKED,
};

#include <iostream>
struct conn_table_entry {
    be32_t  client_addr = 0;
    be32_t  server_addr = 0;
    be16_t  client_port = 0;
    be16_t  server_port = 0;
    state_t client_state = STATE_NUL;
    state_t server_state = STATE_NUL;
    int     rule_idx = -1;
    /* stores the sequence number of FIN. use 0 to indicate no FIN was sent (0
     * is a valid value but low probability to be hit so I guess this is okay)
     */
    seq_t server_fin = 0;
    seq_t client_fin = 0;
    /* (TODO) current or initial (TODO) client/server sequence numbers */
    seq_t server_seq;
    seq_t client_seq;

	void* user_arg = nullptr;

    /* empty constructor to be able to assign entries[conn_table_entry] =
     * entry_instance*/
    conn_table_entry() {}

	~conn_table_entry() {
		// dear god...
		if(user_arg){
			if(server_addr == 0 && server_port == 0) delete (conn_table_entry*)user_arg;
			else std::cout << "suspicious user_arg in conn_table_entry" << std::endl;
		}
	}

    conn_table_entry(pkt_props pkt)
        : client_addr(pkt.saddr), server_addr(pkt.daddr),
          client_port(pkt.sport), server_port(pkt.dport),
          client_state(STATE_NUL) {}

    conn_table_entry(pkt_props pkt, state_t state)
        : client_addr(pkt.saddr), server_addr(pkt.daddr),
          client_port(pkt.sport), server_port(pkt.dport), client_state(state) {}

    conn_table_entry(be32_t saddr, be32_t daddr, be16_t sport, be16_t dport)
        : client_addr(saddr), server_addr(daddr), client_port(sport),
          server_port(dport), client_state(STATE_NUL) {}

    /* must be implemented for hashing */
    bool operator==(const conn_table_entry &other) const {
        return (other.client_addr == client_addr &&
                other.server_addr == server_addr &&
                other.client_port == client_port &&
                other.server_port == server_port) ||
               (other.client_addr == server_addr &&
                other.server_addr == client_addr &&
                other.client_port == server_port &&
                other.server_port == client_port);
    }
};

#include <cassert>
struct conn_table_entry_hasher {
    /* hash input doesn't change when you exchange src ip <-> dst ip AND src
     * port <-> dst port */
    static uint64_t get_hash_input(const conn_table_entry &entry) {
        be32_t saddr = entry.client_addr, daddr = entry.server_addr;
        be16_t sport = entry.client_port, dport = entry.server_port;
        auto   combine = [](be32_t ip, be16_t port) {
            uint64_t seed = 0;
            return fnv_hash(seed | ((uint64_t)port << 32) | ip);
        };

        return combine(saddr, sport) ^ combine(daddr, dport);
    }

    std::size_t operator()(const conn_table_entry &entry) const {
        uint64_t hash_input = get_hash_input(entry);
        /* no special reason to use fnv_hash() instead of std::hash(), I just
         * didn't know std::hash() existed before */
        return static_cast<std::size_t>(fnv_hash(hash_input));
    }

    static void test_hash() {
        /* test symmetry */
        assert(fnv_hash(get_hash_input(conn_table_entry(10, 15, 20, 30))) ==
               fnv_hash(get_hash_input(conn_table_entry(15, 10, 30, 20))));
        assert(fnv_hash(get_hash_input(conn_table_entry(10, 15, 20, 30))) !=
               fnv_hash(get_hash_input(conn_table_entry(15, 10, 20, 30))));
        assert(fnv_hash(get_hash_input(conn_table_entry(10, 15, 20, 30))) !=
               fnv_hash(get_hash_input(conn_table_entry(10, 15, 30, 20))));
    }
};

class conn_table {
  private:
    std::unordered_map<conn_table_entry, conn_table_entry,
                       conn_table_entry_hasher>
        entries;

  public:
    conn_table() : entries() {}

    decision_info tcp_new_conn(pkt_props props, decision_info static_rt_dc);

    decision_info tcp_existing_conn(pkt_props props);

    void add_entry(conn_table_entry entry);

    conn_table_entry *lookup_entry(conn_table_entry entry);

    void remove_entry(conn_table_entry &entry);
};

#endif /* __CONN_TABLE_H */

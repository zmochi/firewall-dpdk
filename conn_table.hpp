#ifndef __CONN_TABLE_H
#define __CONN_TABLE_H

#include "endian.hpp"
#include "fnv_hash.hpp"
#include "packet.hpp"
#include <memory>
#include <optional>
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

    // can keep reference to another conn_table_entry
    conn_table_entry *ref;
    void             *user_arg;

    /* empty constructor to be able to assign entries[conn_table_entry] =
     * entry_instance*/
    conn_table_entry() {}

    // enable copying but settings `ref` to nullptr
    conn_table_entry(const conn_table_entry &other)
        : client_addr(other.client_addr), server_addr(other.server_addr),
          client_port(other.client_port), server_port(other.server_port),
          client_state(other.client_state), server_state(other.server_state),
          rule_idx(other.rule_idx), server_fin(other.server_fin),
          client_fin(other.client_fin), server_seq(other.server_seq),
          client_seq(other.client_seq), ref(nullptr), user_arg(other.user_arg) {
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
    conn_table() : entries() {
	}

	void test() {
		conn_table_entry a1(16843018,33685770,43671,2048);
		conn_table_entry a2(33685770,16843018,2048,43671);
		conn_table_entry a1_invalid(16843018,33685770,2048,43671);
		conn_table_entry a2_invalid(33685770,16843018,43671,2048);
		add_entry(a1);
		assert(lookup_entry(a1) == lookup_entry(a2));
		assert(nullptr == lookup_entry(a1_invalid));
		assert(nullptr == lookup_entry(a2_invalid));
	}

    decision_info tcp_new_conn(pkt_props props, decision_info static_rt_dc);

    decision_info tcp_existing_conn(pkt_props props);

    void add_entry(conn_table_entry entry);

    conn_table_entry *lookup_entry(conn_table_entry entry);

    void remove_entry(conn_table_entry &entry);
};

#endif /* __CONN_TABLE_H */

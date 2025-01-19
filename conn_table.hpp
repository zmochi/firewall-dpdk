#ifndef __CONN_TABLE_H
#define __CONN_TABLE_H

#include "endian.hpp"
#include "fnv_hash.hpp"
#include "packet.hpp"
#include <unordered_map>

enum state_t {
    STATE_NUL,
    STATE_SYN,
    STATE_SYN_ACK,
    STATE_ESTABLISHED,
    STATE_FTP_ESTABLISHED,
    STATE_FTP_DATA,
};

struct conn_table_entry {
    be32_t  saddr;
    be32_t  daddr;
    be16_t  sport;
    be16_t  dport;
    state_t state;
    int     rule_idx;

    /* empty constructor to be able to assign entries[conn_table_entry] =
     * entry_instance*/
    conn_table_entry() {}

    conn_table_entry(pkt_props pkt)
        : saddr(pkt.saddr), daddr(pkt.daddr), sport(pkt.sport),
          dport(pkt.dport), state(STATE_NUL) {}

    conn_table_entry(pkt_props pkt, state_t state)
        : saddr(pkt.saddr), daddr(pkt.daddr), sport(pkt.sport),
          dport(pkt.dport), state(state) {}

    conn_table_entry(be32_t saddr, be32_t daddr, be16_t sport, be16_t dport)
        : saddr(saddr), daddr(daddr), sport(sport), dport(dport),
          state(STATE_NUL) {}

    /* must be implemented for hashing */
    bool operator==(const conn_table_entry &other) const {
        return (other.saddr == saddr && other.daddr == daddr &&
                other.sport == sport && other.dport == dport) ||
               (other.saddr == daddr && other.daddr == saddr &&
                other.sport == dport && other.dport == sport);
    }
};

#include <cassert>
struct conn_table_entry_hasher {
    static uint64_t get_hash_input(const conn_table_entry &entry) {
        be32_t saddr = entry.saddr, daddr = entry.daddr;
        be16_t sport = entry.sport, dport = entry.dport;
        auto   combine = [](be32_t ip, be16_t port) {
            uint64_t seed = 0;
            return fnv_hash(seed | ((uint64_t)port << 32) | ip);
        };

        return combine(saddr, sport) ^ combine(daddr, dport);
    }

    std::size_t operator()(const conn_table_entry &entry) const {
        uint64_t hash_input = get_hash_input(entry);
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
    decision_info tcp_new_conn(pkt_props props, decision_info static_rt_dc);

    decision_info tcp_existing_conn(pkt_props props);

    void add_entry(conn_table_entry entry);

    conn_table_entry *lookup_entry(conn_table_entry entry);

    void remove_entry(conn_table_entry &entry);
};

void tcp_new_conn(pkt_props props, pkt_dc static_rt_dc, conn_table &table);

decision_info tcp_existing_conn(pkt_props props, conn_table &table);

#endif /* __CONN_TABLE_H */

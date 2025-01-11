#ifndef __LOGGER_H
#define __LOGGER_H

#include "endian.hpp"
#include "packet.hpp"
#include "ruletable.hpp"
#include <cstring> /* for memcpy */
#include <unordered_map>

#define LOG_MQUEUE_NAME "/log_mqueue"

typedef uint64_t count_t;

uint64_t get_timestamp_now();

struct log_row_t {
    time_t   timestamp;
    proto    protocol;
    pkt_dc   action;
    be32_t   saddr;
    be32_t   daddr;
    be16_t   sport;
    be16_t   dport;
    reason_t reason;
    /* only relevant if reason is REASON_RULE */
    size_t  reason_idx;
    count_t count;

    /* implement == to use this struct as key in hashamp */
    bool operator==(const log_row_t &other) const {
        return other.protocol == protocol && other.action == action &&
               other.saddr == saddr && other.daddr == daddr &&
               other.sport == sport && other.dport == dport &&
               other.reason == reason;
    }

    log_row_t() {}

    log_row_t(pkt_props pkt, decision_info dc)
        : timestamp(get_timestamp_now()), protocol(pkt.proto),
          action(dc.decision), saddr(pkt.saddr), daddr(pkt.daddr),
          sport(pkt.sport), dport(pkt.dport), reason(dc.reason),
          reason_idx(dc.rule_idx) {}

    log_row_t(proto protocol, pkt_dc action, be32_t saddr, be32_t daddr,
              be16_t sport, be16_t dport, reason_t reason)
        : timestamp(get_timestamp_now()), protocol(protocol), action(action),
          saddr(saddr), daddr(daddr), sport(sport), dport(dport),
          reason(reason) {}
    log_row_t(time_t timestamp, proto protocol, pkt_dc action, be32_t saddr,
              be32_t daddr, be16_t sport, be16_t dport, reason_t reason)
        : log_row_t(protocol, action, saddr, daddr, sport, dport, reason) {
        this->timestamp = timestamp;
    }
};

struct hasher_log_row_t {
    /* callable struct that calculates hash of a log entry */

    /* packs dest port, src port and src addr into 64 bits for hashing:
     * (16 bits dest port) (16 bits src port) (32 bits src addr)
     */
#define ROW_HASH_DATA(row)                                                     \
    (((uint64_t)row.dport << 48) | ((uint64_t)row.sport << 32) |               \
     ((uint64_t)row.saddr))

    std::size_t operator()(const log_row_t &log_row) const { /* do hashing */
        /* values of FNV_offset_basis, FNV_prime and algorithm taken from
         * https://en.wikipedia.org/wiki/Fowler–Noll–Vo_hash_function
         */

        /* store in array to iterate over each byte separately */
        uint64_t      raw_hash_data = ROW_HASH_DATA(log_row);
        unsigned char data_to_hash[sizeof(raw_hash_data)];
        memcpy(data_to_hash, &raw_hash_data, sizeof(uint64_t));

        uint64_t FNV_offset_basis = 0xcbf29ce484222325;
        uint64_t FNV_prime = 0x00000100000001b3;
        uint64_t hash = FNV_offset_basis;

        /* TODO: add unroll directive? */
        for ( int i = 0; i < sizeof(data_to_hash); i++ ) {
            hash ^= data_to_hash[i];
            hash *= FNV_prime;
        }

        return static_cast<std::size_t>(hash);
    }
};

#define MB             (1 << 20)
#define LOGS_INIT_SIZE 8 * MB

struct log_list {
    /* TODO: make this private and add access functions */
    std::unordered_map<log_row_t, log_row_t, hasher_log_row_t> log_hashmap;
    std::mutex                                                 log_hashmap_lock;

    log_list() : log_hashmap() { log_hashmap.reserve(LOGS_INIT_SIZE); }

    int start_logger();
    int store_log(log_row_t log_row);
    int export_log();
};

#endif /* __LOGGER_H */

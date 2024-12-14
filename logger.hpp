#ifndef __LOGGER_H
#define __LOGGER_H

#include "endian.hpp"
#include "packet.hpp"
#include <array>
#include <cstring>
#include <time.h>
#include <unordered_map>

typedef uint64_t count_t;

typedef enum {
  REASON_XMAS_PKT,
  REASON_NO_RULE,
  REASON_RULE,
} reason_t;

#include <chrono>

uint64_t get_timestamp_now();

struct log_row_t {
  time_t timestamp;
  proto protocol;
  pkt_dc action;
  be32_t saddr;
  be32_t daddr;
  be16_t sport;
  be16_t dport;
  reason_t reason;
  count_t count;

  log_row_t() {}

  log_row_t(pkt_props pkt, pkt_dc action, reason_t reason) : timestamp(get_timestamp_now()), protocol(pkt.proto), action(action), saddr(pkt.saddr), daddr(pkt.daddr), sport(pkt.sport), dport(pkt.dport), reason(reason) {

  }

  log_row_t(proto protocol, pkt_dc action, be32_t saddr, be32_t daddr,
            be16_t sport, be16_t dport, reason_t reason)
      : protocol(protocol), action(action), saddr(saddr), daddr(daddr),
        sport(sport), dport(dport), reason(reason) {
			this->timestamp = get_timestamp_now();
  }
  log_row_t(time_t timestamp, proto protocol, pkt_dc action, be32_t saddr,
            be32_t daddr, be16_t sport, be16_t dport, reason_t reason)
      : log_row_t(protocol, action, saddr, daddr, sport, dport, reason) {
    this->timestamp = timestamp;
  }
};

struct hasher_log_row_t {
  /* callable struct that calculates hash of a log entry */

  /* packs dest port, src port and src addr into 64 bits:
   * (16 bits dest port) (16 bits src port) (32 bits src addr)
   */
#define ROW_HASH_DATA(row)                                                     \
  (((uint64_t)row.dport << 48) | ((uint64_t)row.sport << 32) |                 \
   ((uint64_t)row.saddr))

  std::size_t operator()(const log_row_t &log_row) { /* do hashing */
    /* values of FNV_offset_basis, FNV_prime and algorithm taken from
     * https://en.wikipedia.org/wiki/Fowler–Noll–Vo_hash_function
     */

    /* store in array to iterate over each byte separately */
    uint64_t raw_hash_data = ROW_HASH_DATA(log_row);
    unsigned char data_to_hash[sizeof(raw_hash_data)];
    memcpy(data_to_hash, &raw_hash_data, sizeof(uint64_t));

    uint64_t FNV_offset_basis = 0xcbf29ce484222325;
    uint64_t FNV_prime = 0x00000100000001b3;
    uint64_t hash = FNV_offset_basis;

	/* TODO: add unroll directive? */
    for (int i = 0; i < sizeof(data_to_hash); i++) {
      hash ^= data_to_hash[i];
      hash *= FNV_prime;
    }

    return static_cast<std::size_t>(hash);
  }
};

#define MB (1 << 20)
#define LOGS_INIT_SIZE 8 * MB

struct log_list {
	int log_read_fd;
  std::unordered_map<log_row_t, log_row_t, hasher_log_row_t> log_hashmap;

  log_list(int log_read_fd) : log_hashmap(), log_read_fd(log_read_fd) { log_hashmap.reserve(LOGS_INIT_SIZE); }

  /*
   * @brief start receiving packet logs using the reading end of the pipe
   * @param log_read_fd reading end of a pipe, to be called from the logger
   * process
   */
  int start_logger();
  int store_log(log_row_t log_row);
  int export_log();
};

/*
 * @brief log a packet from another process using the writing end of the pipe
 */
int write_log(struct pkt_props pkt, pkt_dc action, reason_t reason,
              int log_write_fd);

log_row_t read_log(int log_read_fd);

#endif /* __LOGGER_H */

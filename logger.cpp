#include "logger.hpp"
#include "packet.hpp"
#include "utils.h"
#include <cassert>
#include <chrono>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

#define LOGS_PER_NODE 64

uint64_t get_timestamp_now() {
    using namespace std::chrono;
    auto now = system_clock::now();

    static_assert(sizeof(milliseconds) == sizeof(uint64_t),
                  "Miliseconds have unexpected size");
    return duration_cast<milliseconds>(now.time_since_epoch()).count();
}

int log_list::store_log(log_row_t log_row) {
    auto item = log_hashmap.find(log_row);
    if ( item != log_hashmap.end() )
        item->second.count++;
    else {
        if ( log_row.timestamp != 0 ) {
            ERROR("log timestamp must be initialized before storing");
            return -1;
        }
        log_row.count = 0;
        log_hashmap.emplace(log_row);
    }

    return 0;
}

#include <mqueue.h>

int log_list::start_logger() {
    static constexpr auto LOG_MAX_MQ_MSGS = (1 << 14);
    static constexpr auto LOG_PERMISSIONS = 0600;
    mq_attr               mqueue_attributes = {.mq_maxmsg = LOG_MAX_MQ_MSGS,
                                               .mq_msgsize = sizeof(log_row_t)};

    /* O_EXCL: return error if this mqueue already exists */
    mqd_t mqueue = mq_open(LOG_MQUEUE_NAME, O_CREAT | O_RDWR | O_EXCL,
                           LOG_PERMISSIONS, &mqueue_attributes);
    if ( mqueue < 0 ) {
        ERROR("Error creating POSIX message queue");
        exit(1);
    }

    log_row_t pkt_log;

    while ( 1 ) {
        /* this call blocks if there's nothing to read */
        if( read_log(mqueue, pkt_log) < 0) {
			ERROR("read_log failed");
			return -1;
		}
        store_log(pkt_log);
    }
}

int write_log(struct pkt_props pkt, pkt_dc action, reason_t reason,
              int log_write_fd) {
    log_row_t log_row(pkt, action, reason);
    int       bytes_sent =
        mq_send(log_write_fd, (const char *)&log_row, sizeof(log_row), 0);
    if ( bytes_sent < 0 ) {
        ERROR("mq_send() call failed");
        return -1;
    }
    assert(bytes_sent == sizeof(log_row));

    return 0;
}

int read_log(int log_read_fd, log_row_t &dst) {
    log_row_t log_row;
    int       bytes_read =
        mq_receive(log_read_fd, (char *)&log_row, sizeof(log_row), NULL);
    if ( bytes_read < 0 ) {
        /* mq_receive() error */
        ERROR("mq_receive call failed");
        return -1;
    }
    assert(bytes_read == sizeof(log_row));

    dst = log_row;

    return 0;
}

int test_logger_correctness() {
    mq_attr mqueue_attributes = {.mq_maxmsg = 10,
                                 .mq_msgsize = sizeof(log_row_t)};
    mqd_t mq_fd = mq_open("/mqueue_test_correctness", O_CREAT | O_RDWR | O_EXCL,
                          600, &mqueue_attributes);

#define LE_IPADDR(o4, o3, o2, o1)                                              \
    (uint32_t)((o4 << 24) | (o3 << 16) | (o2 << 8) | (o1))
#define LE_PORT(o2, o1) (uint16_t)((o2 << 8) | (o1))
    uint32_t  test_saddr = htobe32(LE_IPADDR(100, 10, 102, 1));
    uint32_t  test_daddr = htobe32(LE_IPADDR(192, 168, 0, 1));
    uint16_t  test_sport = htobe16(LE_PORT(40, 42));
    uint16_t  test_dport = htobe16(LE_PORT(17, 73));
    pkt_props pkt = pkt_props(TCP, test_saddr, test_daddr, test_sport,
                              test_dport, TCP_NUL_FLAG);
    log_row_t log_out = log_row_t(pkt, PKT_DROP, REASON_XMAS_PKT);

    int pid_reader = fork();
    if ( pid_reader < 0 ) {
        ERROR_EXIT("Couldn't fork mq reader process");
    } else if ( pid_reader == 0 ) {
        /* reader */
        log_row_t log_in;
        if ( read_log(mq_fd, log_in) < 0 ) {
            ERROR("Couldn't read log");
        }

        assert(log_in.protocol == TCP && log_in.action == PKT_DROP &&
               log_in.saddr == test_saddr && log_in.daddr == test_daddr &&
               log_in.sport == test_sport && log_in.dport == test_dport &&
               log_in.reason == REASON_XMAS_PKT);
        LOG("Reader success");
        exit(0);
    } else {
        /* writer */
        write_log(pkt, PKT_DROP, REASON_XMAS_PKT, mq_fd);
        LOG("Writer success");
        wait(NULL);
    }
}

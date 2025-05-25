#include <cstring>
#include <memory>
#include <queue>
#include <stdexcept>

#include "../conn_table.hpp"
#include "../endian.hpp"
#include "../external/lwipopts.h"

#define MITM_MAX_EGRESS_DATAGRAM_SIZE PBUF_POOL_BUFSIZE

constexpr auto MITM_POLLIN = 0x1;
constexpr auto MITM_POLLOUT = 0x2;
constexpr auto MITM_POLLERR = 0x4;
constexpr auto MITM_POLLNVAL = 0x8;

// if class Derived wants to be Singleton, it should inherit from
// Singleton<Derived>
template <class Derived> class Singleton {
    void helper(bool create) {
        static bool singleton_created = false;
        if ( create && singleton_created )
            throw std::runtime_error("Only one class instance may be created");
        singleton_created = create;
    }

  public:
    Singleton() { helper(true); }

    ~Singleton() { helper(false); }
};

struct mitm_buffer {
    std::unique_ptr<char[]> data;
    size_t                  len;

    mitm_buffer(char *orig_data, size_t len) : data(new char[len]), len(len) {
        memcpy(data.get(), orig_data, len);
    }
};

struct MITM_conn_data {
    // entry with tuple (dest_ip, 0, dest_port, 0)
    conn_table_entry *entry1 = nullptr;
    // entry with tuple (src_ip, 0, src_port, 0)
    conn_table_entry *entry2 = nullptr;
    be32_t            src_ip = 0;
    be32_t            dest_ip = 0;
    be16_t            src_port = 0;
    be16_t            dest_port = 0;
    be16_t            MITM_ext_port = 0;
};

class MITM : Singleton<MITM> {
    std::unique_ptr<struct netif> netif;
    // stored in network order
    const be32_t netif_ip, netif_netmask;
    conn_table   conntable;

    void new_conn(be32_t src_ip, be32_t dest_ip, be16_t src_port,
                  be16_t dest_port);

  public:
    struct MITM_conn_data  *lookup_conn(be32_t src_ip, be32_t dest_ip,
                                        be16_t src_port, be16_t dest_port);
    std::queue<mitm_buffer> outgoing_queue;

    MITM();
    ~MITM();
    void                    test();
    void                    tx_eth_frame(struct pbuf *buf);
    std::unique_ptr<char[]> rx_eth_frame(size_t *len);
    struct pbuf            *mitm_buf_alloc(size_t len);
    struct pbuf            *buf_alloc_copy(char *data, size_t len);
    void                    buf_chain(struct pbuf *buf, struct pbuf *new_tail);
    int                     socket();
    int                     make_socket_nonblocking(int sock);
    int setsockopt_SOLSOCKET_SOLINGER(int s, int level, int optname,
                                      const void *optval, unsigned int optlen);
    int getsockopt_SOLSOCKET_SOERROR(int s, int level, int optname,
                                     void *optval, unsigned int *optlen);
    int poll(struct pollfd *fds, unsigned int nfds, int timeout);
    // all of the following function return -1 on error, or positive value
    int bind(int socket, uint16_t port);
    int listen(int socket, uint8_t backlog);
    int accept(int listen_socket, struct sockaddr *addr,
               unsigned int *addrsize);
    int close(int socket);
    int shutdown(int socket, bool ingress, bool egress);
    int connect(int socket, struct sockaddr *name, unsigned int name_len);
    int getsockname(int socket, struct sockaddr *addr, unsigned int *addr_len);
    // buffer points to where data should be copied, buf_cap holds buffer
    // capacity
    ssize_t recv(int socket, char *buffer, size_t buf_cap);
    // blocks until all data is sent
    ssize_t send(int socket, char *src, size_t len);
};

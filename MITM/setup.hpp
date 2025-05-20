#include <cstring>
#include <memory>
#include <queue>
#include <stdexcept>

#include "../conn_table.hpp"
#include "../endian.hpp"
#include "../external/lwipopts.h"

#define ERR -1
#define OK  0

#define MITM_MAX_EGRESS_DATAGRAM_SIZE PBUF_POOL_BUFSIZE

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
    void                    tx_ip_datagram(char *frame, size_t len);
    std::unique_ptr<char[]> rx_ip_datagram(size_t *len);
    int socket();
	int make_socket_nonblocking(int  sock);
    // all of the following function return -1 on error, or positive value
    int bind(int socket, uint16_t port);
    int listen(int socket, uint8_t backlog);
    int accept(int listen_socket, struct sockaddr* addr, unsigned int *addrsize);
    int close(int socket);
    int shutdown(int socket, bool ingress, bool egress);
    // buffer points to where data should be copied, buf_cap holds buffer
    // capacity
    ssize_t recv(int socket, char *buffer, size_t buf_cap);
    // blocks until all data is sent
    ssize_t send(int socket, char *src, size_t len);
};

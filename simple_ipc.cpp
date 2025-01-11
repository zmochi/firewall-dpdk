#include "simple_ipc.hpp"
#include "utils.h"
#include <climits>
#include <fcntl.h>
#include <stdexcept>
#include <string>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include <iostream>

/* stupid wrappers around send/recv. I want to pass either of them to io_helper
 * which takes in a specific function with a specific signature, but their
 * arguments differ - the second `buf` arguments is const in send and non-const
 * in recv. :( */
static ssize_t send_wp(int fd, void *buf, size_t len, int flags) {
    return send(fd, buf, len, flags);
}
static ssize_t recv_wp(int fd, void *buf, size_t len, int flags) {
    return recv(fd, buf, len, flags);
}

/* signature of send and recv */
using io_fn = ssize_t (*)(int fd, void *buf, size_t len, int flags);

/* helper function to wrap recurring pattern for both send() and recv(). send_wp() and recv_wp() are equivalent to send() and recv() */
template <io_fn fn> size_t io_helper(int fd, void *buf, size_t len) {
    size_t bytes_sent_or_recv = 0;
    size_t ret;

    while ( bytes_sent_or_recv < len ) {
        if ( (ret = fn(fd, (char *)buf + bytes_sent_or_recv, len - bytes_sent_or_recv, 0)) < 0 )
            return -1;
        bytes_sent_or_recv += ret;
    }

    return bytes_sent_or_recv;
}

template <typename actionEnum>
IPC_Server<actionEnum>::IPC_Server(const std::string msgfile_path,
                                   int msgfile_perms, int backlog, callback cb)
    : msgfile_path(msgfile_path), msgfile_perms(msgfile_perms),
      server_backlog(backlog), cb(cb) {}

template <typename actionEnum>
int IPC_Server<actionEnum>::start_server(void *user_arg) {
    struct sockaddr_un unix_sock_opts = {.sun_family = AF_UNIX};
    strcpy(unix_sock_opts.sun_path, msgfile_path.data());

    int listen_sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if ( listen_sockfd < 0 ) {
        ERROR("Couldn't open IPC server socket");
        return -1;
    }

    unlink(msgfile_path.data());

    int err = bind(listen_sockfd, (struct sockaddr *)&unix_sock_opts,
                   sizeof(unix_sock_opts));
    if ( err < 0 ) {
        ERROR("Couldn't bind IPC server socket");
        switch ( err ) {}
        return -1;
    }

    int ret;
    if ( (ret = chmod(msgfile_path.data(), msgfile_perms)) < 0 ) {
        ERROR("Couldn't set permissions to file %s", msgfile_path.data());
        return -1;
    }

    if ( listen(listen_sockfd, server_backlog) < 0 ) {
        ERROR("Couldn't listen on IPC server socket");
        return -1;
    }

    int        new_sockfd;
    size_t     msg_size;
    actionEnum action;


    while ( 1 ) {
        new_sockfd = accept(listen_sockfd, nullptr, nullptr);
        if ( new_sockfd < 0 ) {
            ERROR("Couldn't accept IPC server connection on socket");
            return -1;
        }

        if ( io_helper<recv_wp>(new_sockfd, &action, sizeof(action)) < 0 ) {
            ERROR("Couldn't receive action from IPC server socket");
            return -1;
        }

        if ( cb(*this, action, msg_size, new_sockfd, user_arg) < 0 ) {
            ERROR("Error on IPC server callback. Exiting.");
            return -1;
        }
    }
}

template <typename actionEnum>
ssize_t IPC_Server<actionEnum>::recv_size(int fd, void *buf, size_t len) {
    if ( len > SSIZE_MAX ) return -1;
    size_t bytes_recv = 0;
    size_t msg_len = 0;
    size_t ret;

    if ( (ret = io_helper<recv_wp>(fd, &msg_len, sizeof(msg_len))) < 0 ) {
        return -1;
    }

    if ( msg_len > len ) {
        ERROR("Client sent message that is too big");
        return -1;
    }

    if ( (ret = io_helper<recv_wp>(fd, buf, msg_len)) < 0 ) {
        return -1;
    }
    bytes_recv += ret;

    return bytes_recv;
}

template <typename actionEnum>
ssize_t IPC_Server<actionEnum>::send_size(int fd, void *buf, size_t len) {
    ssize_t bytes_sent = 0;
    size_t  ret;
    if ( (ret = io_helper<send_wp>(fd, &len, sizeof(len))) < 0 ) return -1;

    if ( (ret = io_helper<send_wp>(fd, buf, len)) < 0 ) return -1;
    bytes_sent += ret;

    return bytes_sent;
}

template <typename actionEnum>
IPC_Client<actionEnum>::IPC_Client(const std::string msgfile_path)
    : msgfile_path(msgfile_path), server_fd(socket(AF_UNIX, SOCK_STREAM, 0)) {
    if ( server_fd < 0 ) {
        throw std::runtime_error("Can't open msg file " + msgfile_path + "\n");
    }
    struct sockaddr_un server = {.sun_family = AF_UNIX};
    strncpy(server.sun_path, msgfile_path.data(), msgfile_path.length());

    if ( connect(server_fd, (struct sockaddr *)&server, sizeof(server)) < 0 )
        throw std::runtime_error("Couldn't connect to server at " +
                                 msgfile_path);
}

template <typename actionEnum> IPC_Client<actionEnum>::~IPC_Client() {
    close(server_fd);
}

template <typename actionEnum>
ssize_t IPC_Client<actionEnum>::send_action(actionEnum action) {
    size_t bytes_sent = 0;
    size_t ret;
    if ( (ret = io_helper<send_wp>(server_fd, &action, sizeof(action))) < 0 ) {
        return -1;
    }
    bytes_sent += ret;

    return bytes_sent;
}

template <typename actionEnum>
ssize_t IPC_Client<actionEnum>::send_size(void *msg, size_t msg_len) {
    size_t bytes_sent = 0;
    size_t ret;

    if ( io_helper<send_wp>(server_fd, &msg_len, sizeof(msg_len)) < 0 ) {
        return -1;
    }

    if ( (ret = io_helper<send_wp>(server_fd, msg, msg_len)) < 0 ) {
        return -1;
    }
    bytes_sent += ret;

    return bytes_sent;
}

template <typename actionEnum>
ssize_t IPC_Client<actionEnum>::recv_size(void *dst, size_t cap) {
    size_t msg_size = 0;
    size_t ret;

    if ( (ret = io_helper<recv_wp>(server_fd, &msg_size, sizeof(msg_size))) <
         0 ) {
        return -1;
    }

    if ( cap < msg_size ) {
        ERROR("Capacity too small, can't receive message");
        return -1;
    }

    if ( (ret = io_helper<recv_wp>(server_fd, dst, msg_size)) < 0 ) {
        return -1;
    }

    return static_cast<ssize_t>(msg_size);
}

enum simple_ipc_code {
    HELLO = 0x1,
};
static void simple_ipc_tests() {
	const std::string ruletable_path = "/dev/test_simple_ipc";
    /* create file */
    close(open(ruletable_path.data(), O_CREAT, 0));

    if ( fork() == 0 ) {
        /* client process */
        IPC_Client<simple_ipc_code> client(ruletable_path);
        char                        msg[40] = "hello from client";
        ssize_t                     ret = client.send_action(HELLO);
        if ( ret < 0 ) {
            ERROR("failed sending client action HELLO");
            return;
        }

        ret = client.send_size(msg, strlen(msg));
        if ( ret < 0 ) {
            ERROR("failed sending client msg");
            return;
        }

        ssize_t msg_len = client.recv_size(msg, sizeof(msg));
        if ( msg_len < 0 ) {
            ERROR("failed receiving server msg at client");
            return;
        }

        std::cout << "Client: done!" << std::endl;
        return;
    } else {
        /* server process */
        IPC_Server<simple_ipc_code> server(
            ruletable_path, 0600, 1,
            [](auto &server, simple_ipc_code action, size_t msg_size,
               int sockfd, void *arg) {
                char client_msg[20];

                ssize_t ret =
                    server.recv_size(sockfd, client_msg, sizeof(client_msg));
                if ( ret < 0 ) {
                    ERROR("Failed receiving client message");
                    return -1;
                }

                char response[] = "hello from server";

                ret = server.send_size(sockfd, response, sizeof(response));
                if ( ret < 0 ) {
                    ERROR("failed sending response in simple_ipc_tests()");
                    return -1;
                }

                std::cout << "Server done" << std::endl;
                return 0;
            });

        server.start_server(nullptr);
        return;
    }
}

/* TODO: separate sockets (files..) for sending and receiving */
// int main(void) { simple_ipc_tests(); }

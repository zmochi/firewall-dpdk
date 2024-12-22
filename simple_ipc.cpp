#include "simple_ipc.hpp"
#include "utils.h"
#include <string>
#include <sys/socket.h>

template <typename actionEnum>
    IPC_Server<actionEnum>::IPC_Server(const std::string msgfile_path, int msgfile_perms, int backlog,
               callback cb)
        : msgfile_path(msgfile_path), msgfile_perms(msgfile_perms),
          server_backlog(backlog), cb(cb) {}

template <typename actionEnum>
    int IPC_Server<actionEnum>::start_server(void* user_arg) {
        struct sockaddr_un unix_sock_opts = {.sun_family = AF_UNIX};
        strcpy(unix_sock_opts.sun_path, msgfile_path.data());

        int listen_sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
        if ( listen_sockfd < 0 ) {
            ERROR("Couldn't open IPC server socket");
            return -1;
        }

        /* TODO: fchown() to set perms */

        int err =
            bind(listen_sockfd, (struct sockaddr *)&unix_sock_opts,
                 msgfile_path.length() + sizeof(unix_sock_opts.sun_family));
        if ( err < 0 ) {
            ERROR("Couldn't bind IPC server socket");
            return -1;
        }

        if ( listen(listen_sockfd, server_backlog) < 0 ) {
            ERROR("Couldn't listen on IPC server socket");
            return -1;
        }

        int        new_sockfd;
        int        bytes_recv, bytes_sent;
        actionEnum action;

        while ( 1 ) {
            int new_sockfd = accept(listen_sockfd, nullptr, nullptr);
            if ( new_sockfd < 0 ) {
                ERROR(
                    "Couldn't accept IPC server connection on socket");
                return -1;
            }

            if ( recv_size(new_sockfd, &action, sizeof(action)) < 0 )
                ERROR(
                    "Couldn't receive action from IPC server socket");

            cb(action, new_sockfd, user_arg);
        }
    }

template <typename actionEnum>
    int IPC_Server<actionEnum>::recv_size(int fd, void *buf, size_t len) {
        size_t bytes_recv = 0;
        while ( bytes_recv < len )
            if ( recv(fd, (char *)buf + bytes_recv, len - bytes_recv, 0) < 0 )
                return -1;

        return 0;
    }

template <typename actionEnum>
    int IPC_Server<actionEnum>::send_size(int fd, void *buf, size_t len) {
        size_t bytes_sent = 0;
        while ( bytes_sent < len ) {
            if ( send(fd, buf, len, 0) < 0 ) return -1;
        }

        return 0;
    }

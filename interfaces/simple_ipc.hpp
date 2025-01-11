#ifndef __SIMPLE_IPC_H
#define __SIMPLE_IPC_H

#include <cstdint>
#include <string>

template <typename actionEnum> class IPC_Server {
    static_assert(
        sizeof(actionEnum) == sizeof(uint32_t),
        "IPC_Server enum template argument must match size of uint32_t");
    int listen_sockfd;

  public:
    using callback = int (*)(IPC_Server<actionEnum> &server, actionEnum action,
                             size_t msg_size, int msg_sockfd, void *user_arg);
    const std::string msgfile_path;
    int               msgfile_perms;
    int               server_backlog;
    callback          cb;

    IPC_Server(const std::string msgfile_path, int msgfile_perms, int backlog,
               callback cb);
    ssize_t recv_size(int fd, void *buf, size_t len);
    ssize_t send_size(int fd, void *buf, size_t len);
    int     start_server(void *user_arg);
};

template <typename actionEnum> class IPC_Client {
  public:
    const std::string msgfile_path;
    const int         server_fd;

    IPC_Client(const std::string msgfile_path);
    ~IPC_Client();
    ssize_t send_action(actionEnum action);
    ssize_t send_size(void *msg, size_t msg_len);
    ssize_t recv_size(void *dst, size_t capacity);
};

/* include implementations for above classes. must be done in the same file
 * and not in a separate compilation unit */
#include "simple_ipc.cpp"

#endif /* __SIMPLE_IPC_H */

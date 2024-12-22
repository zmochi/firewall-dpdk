#include <cstdint>
#include <string>

template <typename actionEnum> class IPC_Server {
    static_assert(
        sizeof(actionEnum) == sizeof(uint32_t),
        "IPC_Server enum template argument must match size of uint32_t");
    int listen_sockfd;

  public:
    using callback = void (*)(IPC_Server<actionEnum> &inst, actionEnum action,
                              int msg_sockfd, void *user_arg);
    const std::string msgfile_path;
    int               msgfile_perms;
    int               server_backlog;
    callback          cb;

    IPC_Server(const std::string msgfile_path, int msgfile_perms, int backlog,
               callback cb);
    int recv_size(int fd, void *buf, size_t len);
    int send_size(int fd, void *buf, size_t len);
    int start_server(void *user_arg);
};

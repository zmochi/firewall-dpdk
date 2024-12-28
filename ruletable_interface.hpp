#include <cstdint>

#define RULETABLE_INTERFACE_PATH "/dev/ruletable"
static constexpr auto RULETABLE_INTERFACE_PIPE_PERMISSIONS = 0600;
constexpr auto        RULETABLE_PATH_MAXLEN = 1 << 9; /* 512 */

#define BIT(i) (1ULL << i)

enum ruletable_action : uint32_t {
    LOAD_RULETABLE = BIT(1),
    SHOW_RULETABLE = BIT(2),
    RST_RULETABLE = BIT(3),
    OK = BIT(4),
    BAD_MSG = BIT(5),
};

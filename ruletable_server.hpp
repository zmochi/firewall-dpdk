#include <string>

/* @brief start server that handles show_rules, load_rules with IPC mechanisms
 * @param ruletable ruletable to read/load to
 * @param interface_path where to create interface file, to send show/load rules commands (currently AF_UNIX socket)
 * @param permissions for the new file (e.g 0600)
 */
int start_ruletable(struct ruletable &ruletable,
                    const std::string interface_path, int interface_perms);

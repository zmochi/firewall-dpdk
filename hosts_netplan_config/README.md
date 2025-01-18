Netplan configs to set up the interfaces on external and internal endpoints.

Place the `.yaml` file in the machine's `/etc/netplan/50-cloud-init.yaml` (Possibly requires `cloudinit` or something) and run `netplan apply` as root to apply the new config.

The MAC address specified in `enp0s2` should be changed to match the real MAC address of the interface connecting the machine to the internet.

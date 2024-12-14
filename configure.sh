#!/usr/bin/env bash

devbind="/home/fw/DPDK/dpdk-devbind.py"
hugepages="/home/fw/DPDK/dpdk-hugepages.py"
interfaces=("host1" "host2")

if [[ "$(whoami)" != "root" ]]; then
	echo "Must be root, use \'sudo -s\'"
	exit 1
fi

modprobe vfio-pci
$hugepages --setup 512MB

for iface in ${interfaces[@]}; do
	ip link set $iface down
	$devbind -b vfio-pci $iface
done
#!/usr/bin/env bash

# configure.sh binds the internal and external NICs to DPDK.
# This script binds those NICs back to the kernel

devbind="/home/fw/DPDK/dpdk-devbind.py"

# last two e1000 interfaces listed in `lspci` command
pci_list=("00:03.0" "00:04.0")

if [[ "$(whoami)" != "root" ]]; then
	echo "Must be root"
	exit 1
fi

for pci in ${pci_list[@]}; do
	$devbind -b e1000 $pci
done

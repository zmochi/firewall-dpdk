#!/usr/bin/env bash

# fail if the shell variables read below don't exist
set -u

qemu-system-x86_64 \
	-machine q35,accel=kvm,kernel-irqchip=split \
	-m 1024 \
	-cpu host,+ssse3,+sse2,+sse4a,+sse4.2,+sse4.1,+sse \
	-nic user,model=e1000,hostfwd=tcp::1337-:22 \
	-device intel-iommu,intremap=on \
	-drive file=fw.qcow2,media=disk,if=virtio \
	-device e1000,mac=56:e4:7f:f0:9a:fa,netdev=vlan1 \
	-netdev tap,id=vlan1,ifname=$INT_FW_TAP,script=no \
	-device e1000,mac=7a:db:a5:08:d3:9c,netdev=vlan2 \
	-netdev tap,id=vlan2,ifname=$EXT_FW_TAP,script=no \
	-smp 2 \
	-display none \
	-daemonize

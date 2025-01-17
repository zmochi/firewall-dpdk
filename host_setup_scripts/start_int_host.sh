#!/usr/bin/env bash

# fail if the shell variables read below don't exist
set -u

qemu-system-x86_64  \
  -machine accel=kvm,type=q35 \
  -cpu host \
  -m 256M \
  -device virtio-net-pci,netdev=net0 \
  -netdev user,id=net0,hostfwd=tcp::1338-:22 \
  -device e1000,mac=26:30:98:5d:9c:85,netdev=vlan1 \
  -netdev tap,id=vlan1,ifname=$INT_HOST_TAP,script=no \
  -drive if=virtio,format=qcow2,file=int_host.img \
  -display none \
  -daemonize

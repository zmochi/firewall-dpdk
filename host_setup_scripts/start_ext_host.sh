#!/usr/bin/env bash

# fail if the shell variables read below don't exist
set -u

qemu-system-x86_64  \
  -machine accel=kvm,type=q35 \
  -cpu host \
  -m 256M \
  -device virtio-net-pci,netdev=net0 \
  -netdev user,id=net0,hostfwd=tcp::1339-:22 \
  -device e1000,mac=8A:6C:1B:CD:4D:1E,netdev=vlan2 \
  -netdev tap,id=vlan2,ifname=$EXT_HOST_TAP,script=no \
  -drive if=virtio,format=qcow2,file=ext_host.img \
  -display none \
  -daemonize

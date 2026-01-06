#!/bin/bash
set -e
mkdir -p rootfs/{bin,lib,lib64,dev,proc,sys,tmp,usr}
cp /bin/busybox rootfs/bin/
chroot rootfs /bin/busybox --install -s /bin

#!/bin/bash
mkdir -p rootfs
sudo mount debian.sfs rootfs -t squashfs
./container -f "rootfs" -n container /sbin/init 3
sudo umount rootfs

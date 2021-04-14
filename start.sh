#!/bin/bash
mkdir -p rootfs
sudo mount debian.sfs rootfs -t squashfs
./container.py -f "rootfs" -n container /sbin/init 6
sudo umount rootfs

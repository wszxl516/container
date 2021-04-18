#!/bin/bash
mkdir -p rootfs
sudo mount debian.sfs rootfs -t squashfs
./container --rootfs "rootfs" --name container /sbin/init 3
sudo umount rootfs

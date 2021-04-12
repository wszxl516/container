#!/bin/bash
mkdir -p rootfs
sudo mount debian.sfs rootfs -t squashfs
python3 container.py -f "rootfs" -n container /init eth0 "10.0.0.10/24"
sudo umount rootfs

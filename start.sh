#!/bin/bash
path=$(pwd)
python3 container.py -f $path"/rootfs" -n container /init eth0 "10.0.0.10/24"

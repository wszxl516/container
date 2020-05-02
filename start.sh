#!/bin/bash
echo use  [nsenter -F -a -t PID] to enter container
path=$(pwd)
python3 container.py -f $path"/rootfs" -n container /init eth0 "10.0.1.10/24"

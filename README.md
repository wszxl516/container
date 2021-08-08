#   prepare
```shell
mkdir rootfs

wget https://www.busybox.net/downloads/binaries/1.31.0-defconfig-multiarch-musl/busybox-x86_64 -O rootfs/busybox 
```
#  start container

```shell
sudo ./target/debug/container start -r rootfs -i "/busybox" -a "sh"
```

#   enter container

```shell
sudo ./target/debug/container enter -p PID -c "/busybox sh"
```

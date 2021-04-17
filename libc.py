import ctypes
import sys
from ctypes import util as c_util
from functools import wraps
import os

# /usr/include/bits/sched.h
CLONE_VM = 0x00000100
CLONE_FS = 0x00000200
CLONE_FILES = 0x00000400
CLONE_SIGHAND = 0x00000800
CLONE_PTRACE = 0x00002000
CLONE_VFORK = 0x00004000
CLONE_PARENT = 0x00008000
CLONE_THREAD = 0x00010000
CLONE_NEWNS = 0x00020000
CLONE_SYSVSEM = 0x00040000
CLONE_SETTLS = 0x00080000
CLONE_PARENT_SETTID = 0x00100000
CLONE_CHILD_CLEARTID = 0x00200000
CLONE_DETACHED = 0x00400000
CLONE_UNTRACED = 0x00800000
CLONE_CHILD_SETTID = 0x01000000
CLONE_NEWCGROUP = 0x02000000
CLONE_NEWUTS = 0x04000000
CLONE_NEWIPC = 0x08000000
CLONE_NEWUSER = 0x10000000
CLONE_NEWPID = 0x20000000
CLONE_NEWNET = 0x40000000
CLONE_IO = 0x80000000

# /usr/include/linux/mount.h
MS_RDONLY = 1
MS_NOSUID = 2
MS_NODEV = 4
MS_NOEXEC = 8
MS_SYNCHRONOUS = 16
MS_REMOUNT = 32
MS_MANDLOCK = 64
MS_DIRSYNC = 128
MS_NOATIME = 1024
MS_NODIRATIME = 2048
MS_BIND = 4096
MS_MOVE = 8192
MS_REC = 16384
MS_SILENT = 32768
MS_POSIXACL = (1 << 16)  # VFS does not apply the umask
MS_UNBINDABLE = (1 << 17)  # change to unbindable
MS_PRIVATE = (1 << 18)  # change to private
MS_STRICTATIME = (1 << 24)  # Always perform atime updates
MS_MGC_VAL = 0xC0ED0000  # Old magic mount flag

# /usr/include/sys/mount.h
MNT_FORCE = 1
MNT_DETACH = 2
MNT_EXPIRE = 4
UMOUNT_NOFOLLOW = 8

libc = ctypes.CDLL(c_util.find_library('c'), use_errno=True)


def catch_error(func):
    @wraps(func)
    def catch(*args, **kwargs):
        ret = func(*args, **kwargs)
        if ret < 0:
            err_no = ctypes.get_errno()
            print(func.__name__, args if args else kwargs, os.strerror(err_no))
            sys.exit(1)
    return catch


@catch_error
def mount(source: str, target: str, flag: int, fs=None, options=None):
    return libc.mount(
        source.encode(),
        target.encode(),
        fs.encode() if isinstance(fs, str) else None,
        flag,
        options.encode() if isinstance(options, str) else None,
    )


@catch_error
def unmount(target: str):
    return libc.umount2(target.encode(), MNT_DETACH)


@catch_error
def unshare(flags):
    return libc.unshare(flags)


@catch_error
def pivot_root(new_root: str, old_root: str):
    return libc.pivot_root(new_root.encode(), old_root.encode())


@catch_error
def set_ns(fd: int, flag: int):
    return libc.setns(fd, flag)


@catch_error
def chroot(path: str):
    return libc.chroot(path.encode())


@catch_error
def fchdir(fd: int):
    return libc.fchdir(fd)


if __name__ == '__main__':
    print(mount('1', '2', '3', 1))

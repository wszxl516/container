#!/usr/bin/env python3
import argparse
import ctypes
from ctypes import util as c_util
import os
import signal
import socket
import sys

from pyroute2 import IPRoute
import multiprocessing

# pulled from linux/sched.h
CLONE_VM = 0x00000100  # set if VM shared between processes
CLONE_FS = 0x00000200  # set if fs info shared between processes
CLONE_FILES = 0x00000400  # set if open files shared between processes
CLONE_SIGHAND = 0x00000800  # set if signal handlers and blocked signals shared
CLONE_PTRACE = 0x00002000  # set if we want to let tracing continue on the child too
CLONE_VFORK = 0x00004000  # set if the parent wants the child to wake it up on mm_release
CLONE_PARENT = 0x00008000  # set if we want to have the same parent as the cloner
CLONE_THREAD = 0x00010000  # Same thread group?
CLONE_NEWNS = 0x00020000  # New mount namespace group
CLONE_SYSVSEM = 0x00040000  # share system V SEM_UNDO semantics
CLONE_SETTLS = 0x00080000  # create a new TLS for the child
CLONE_PARENT_SETTID = 0x00100000  # set the TID in the parent
CLONE_CHILD_CLEARTID = 0x00200000  # clear the TID in the child
CLONE_DETACHED = 0x00400000  # Unused, ignored
CLONE_UNTRACED = 0x00800000  # set if the tracing process can't force CLONE_PTRACE on this clone
CLONE_CHILD_SETTID = 0x01000000  # set the TID in the child
CLONE_NEWCGROUP = 0x02000000  # New cgroup namespace
CLONE_NEWUTS = 0x04000000  # New utsname namespace
CLONE_NEWIPC = 0x08000000  # New ipc namespace
CLONE_NEWUSER = 0x10000000  # New user namespace
CLONE_NEWPID = 0x20000000  # New pid namespace
CLONE_NEWNET = 0x40000000  # New network namespace
CLONE_IO = 0x80000000  # Clone io context

# pulled from linux/fs.h
MS_RDONLY = 1  # Mount read-only
MS_NOSUID = 2  # Ignore suid and sgid bits
MS_NODEV = 4  # Disallow access to device special files
MS_NOEXEC = 8  # Disallow program execution
MS_SYNCHRONOUS = 16  # Writes are synced at once
MS_REMOUNT = 32  # Alter flags of a mounted FS
MS_MANDLOCK = 64  # Allow mandatory locks on an FS
MS_DIRSYNC = 128  # Directory modifications are synchronous
MS_NOATIME = 1024  # Do not update access times.
MS_NODIRATIME = 2048  # Do not update directory access times
MS_BIND = 4096
MS_MOVE = 8192
MS_REC = 16384

MS_SILENT = 32768
MS_POSIXACL = (1 << 16)  # VFS does not apply the umask
MS_UNBINDABLE = (1 << 17)  # change to unbindable
MS_PRIVATE = (1 << 18)  # change to private
MS_STRICTATIME = (1 << 24)  # Always perform atime updates

MS_MGC_VAL = 0xC0ED0000  # Old magic mount flag

MNT_FORCE = 0x00000001  # Attempt to forcibily umount
MNT_DETACH = 0x00000002  # Just detach from the tree
MNT_EXPIRE = 0x00000004  # Mark for expiry
UMOUNT_NOFOLLOW = 0x00000008  # Don't follow symlink on umount
UMOUNT_UNUSED = 0x80000000  # Flag guaranteed to be unused
libc = ctypes.CDLL(c_util.find_library('c'), use_errno=True)


def unshare(flags):
    sys_unshare = 272  # https://filippo.io/linux-syscall-table/
    libc.syscall.argtypes = [ctypes.c_int, ctypes.c_int]
    r = libc.syscall(sys_unshare, flags)
    if r < 0:
        err_no = ctypes.get_errno()
        raise RuntimeError(f"Error running unshare: {os.strerror(err_no)}")


def mount(source, target, fs, flags, options=None):
    r = libc.mount(
        source.encode("utf-8"),
        target.encode("utf-8"),
        fs.encode("utf-8") if isinstance(fs, str) else None,
        flags,
        options.encode("utf-8") if options else None,
    )
    if r < 0:
        err_no = ctypes.get_errno()
        raise RuntimeError(
            f"Error mount {source} ({fs}) to {target} with options '{options}': {os.strerror(err_no)}"
        )


def umount(target):
    r = libc.umount2(target.encode("utf-8"), MNT_DETACH)
    if r < 0:
        err_no = ctypes.get_errno()
        raise RuntimeError(f"Error umount {target}: {os.strerror(err_no)}")


def map_user(id_inside_ns, id_outside_ns, length=1, pid=None):
    if pid is None:
        pid = os.getpid()
    with open(f"/proc/{pid}/uid_map", "w") as f:
        f.write(f"{id_inside_ns} {id_outside_ns} {length}")


def map_group(id_inside_ns, id_outside_ns, length=1, pid=None):
    if pid is None:
        pid = os.getpid()
    with open("/proc/{}/gid_map".format(pid), "w") as f:
        f.write(f"{id_inside_ns} {id_outside_ns} {length}")


def set_groups_write(pid=None):
    if pid is None:
        pid = os.getpid()
    with open(f"/proc/{pid}/setgroups", "w") as f:
        f.write("deny")


def set_mount_propagation():
    mount("none", "/", None, MS_REC | MS_PRIVATE, None)


def pivot_root(new_root_dir):
    mount(new_root_dir, new_root_dir, "bind", MS_BIND | MS_REC)
    tmp_root = "tmp/"
    old_root = os.path.join(new_root_dir, tmp_root)
    if not os.path.exists(old_root):
        os.makedirs(old_root)
    ret = libc.pivot_root(new_root_dir.encode("utf-8"), old_root.encode("utf-8"))
    if ret < 0:
        err_no = ctypes.get_errno()
        raise RuntimeError(f"Error pivot root {new_root_dir}: {os.strerror(err_no)}")
    os.chdir("/")
    old_root = os.path.join("/", tmp_root)
    return old_root


def bind_dev_nodes(old_root):
    devices = (
        "dev/tty",
        "dev/null",
        "dev/zero",
        "dev/random",
        "dev/urandom",
        "dev/full",
    )
    for device in devices:
        new_device = os.path.join("/", device)
        host_device = os.path.join(old_root, device)
        if os.path.isfile(new_device):
            os.remove(new_device)
        open(new_device, "a").close()
        mount(host_device, new_device, "bind", MS_BIND)


def symlink_many(mapping):
    for source, destination in mapping.items():
        os.symlink(source, destination)


def setup_fs(rootfs):
    old_root = pivot_root(rootfs)
    mount("proc", "/proc", "proc", MS_MGC_VAL)
    mount("tmpfs", "/dev", "tmpfs", MS_NOSUID | MS_STRICTATIME, "mode=755")
    os.makedirs('/dev/shm', 0o755)
    mount("tmpfs", "/dev/shm", "tmpfs", MS_NOSUID | MS_STRICTATIME, "mode=755")
    bind_dev_nodes(old_root)
    os.makedirs("/dev/pts", 0o755)
    mount(
        "devpts",
        "/dev/pts",
        "devpts",
        MS_NOEXEC | MS_NOSUID,
        "newinstance,ptmxmode=0666,mode=620",
    )

    symlink_many(
        {
            "/dev/pts/ptmx": "/dev/ptmx",
            "/proc/self/fd": "/dev/fd",
            "/proc/self/fd/0": "/dev/stdin",
            "/proc/self/fd/1": "/dev/stdout",
            "/proc/self/fd/2": "/dev/stderr",
        }
    )
    mount("sysfs", "/sys", "sysfs", MS_RDONLY | MS_NOSUID | MS_NOEXEC | MS_NODEV)
    umount(old_root)


def get_tasks(p_pid):
    """
    :param p_pid: parent pid
    :return: children pid
    """
    tasks = []
    for pid in os.listdir('/proc'):
        if not pid.isnumeric():
            continue
        try:
            with open('/proc/{}/stat'.format(pid))as fp:
                if p_pid.__str__() in fp.read().split(' '):
                    tasks.append(pid)
        except FileNotFoundError:
            pass
    return [int(t) for t in tasks]


def mk_veth():
    import time
    while True:
        p_pid = os.getppid()
        pid = os.getpid()
        tasks = get_tasks(p_pid)
        tasks.remove(pid)
        tasks.remove(p_pid)
        if not tasks:
            time.sleep(0.1)
            continue
        else:
            pid = tasks[0]
            break

    ip_route = IPRoute()
    ip_route.link('add', ifname='eth0', kind='veth', peer='eth1')
    eth_0 = ip_route.link_lookup(ifname='eth0')[0]
    eth_1 = ip_route.link_lookup(ifname='eth1')[0]
    ip_route.addr('add', index=eth_1, address='10.0.0.1', broadcast='10.0.0.255', mask=24)
    ip_route.link('set', index=eth_0, net_ns_pid=pid)
    ip_route.link('set', index=eth_1, state='up')


def start_container(name, rootfs, command, args):
    th = multiprocessing.Process(target=mk_veth)
    th.start()
    user_id = os.geteuid()
    group_id = os.getegid()
    unshare(
        CLONE_NEWPID  # pid namespace
        | CLONE_NEWNET  # network namespace
        | CLONE_NEWNS  # mount namespace (confusingly named)
        | CLONE_NEWUTS  # hostname namespace (allows a different hostname)
        | CLONE_NEWCGROUP  # cgroup namespace
        | CLONE_NEWIPC  # unix IPC namespace
        | CLONE_NEWUSER  # user namespace (allow user mappings)
    )
    # stop mounts leaking to host
    set_mount_propagation()
    # allow us to modify groups in a namespace
    set_groups_write()
    # map current user to root
    map_user(0, user_id)
    # map current group to group 0 (normally wheel)
    map_group(0, group_id)
    # add a new hostname
    socket.sethostname(name)
    # fork to enter the namespace
    pid = os.fork()
    # check if we're in the child process or the parent
    if pid == 0:
        setup_fs(rootfs)
        os.execve(command, [command] + args, {
            "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "LD_LIBRARY_PATH": "/usr/lib:/usr/local/lib:/lib:/lib64",
            "TERM": "xterm",
        })
    else:
        # this is the parent, just wait for the child to exit
        print('Container\tPID:', pid)
        try:
            os.waitpid(pid, 0)
        except (KeyboardInterrupt, EOFError):
            os.kill(pid, signal.SIGKILL)


def ns_enter(pid):
    ns_type = {'pid': CLONE_NEWPID,
               'net': CLONE_NEWNET,
               'uts': CLONE_NEWUTS,
               'cgroup': CLONE_NEWCGROUP,
               'ipc': CLONE_NEWIPC,
               'user': CLONE_NEWUSER,
               'mnt': CLONE_NEWNS}
    for name, flags in ns_type.items():
        fd = os.open(f'/proc/{pid}/ns/{name}', os.O_RDONLY)
        libc.setns(fd, flags)
        os.close(fd)
    ret = libc.chroot('.')
    if ret < 0:
        err_no = ctypes.get_errno()
        raise RuntimeError(f"Error chroot .: {os.strerror(err_no)}")
    ret = libc.chdir('/')
    if ret < 0:
        err_no = ctypes.get_errno()
        raise RuntimeError(f"Error chdir /: {os.strerror(err_no)}")
    fd = os.open('.', os.O_RDONLY)
    ret = libc.fchdir(fd)
    os.close(fd)
    if ret < 0:
        err_no = ctypes.get_errno()
        raise RuntimeError(f"Error fchdir .: {os.strerror(err_no)}")
    # ret = libc.setgroups(0, None)
    # if ret < 0:
    #     err_no = ctypes.get_errno()
    #     raise RuntimeError(f"Error setgroups 0: {os.strerror(err_no)}")
    pid = os.fork()
    if pid == 0:
        os.execve('/bin/bash', ['/bin/bash'], {
            "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "LD_LIBRARY_PATH": "/usr/lib:/usr/local/lib:/lib:/lib64",
            "TERM": "xterm",
        })
    else:
        print('Container\tPID:', pid)
        try:
            os.waitpid(pid, 0)
        except (KeyboardInterrupt, EOFError):
            os.kill(pid, signal.SIGKILL)


def get_arguments(_type='container'):
    parser = argparse.ArgumentParser(description="Toy container runtime")
    if _type == 'container':
        parser.add_argument(
            "-n",
            "--name",
            metavar="hostname",
            default=socket.gethostname() + 'container',
            help="name of  container",
        )

        parser.add_argument(
            "-f",
            "--rootfs",
            help=" container` rootfs",
        )
        parser.add_argument(
            "command", metavar="COMMAND", help="command to run in the container"
        )
        parser.add_argument(
            "args",
            metavar="ARG",
            nargs=argparse.REMAINDER,
            help="arguments to be passed to command",
        )
    elif _type == 'enter':
        parser.add_argument(
            "-p",
            "--pid",
            metavar="pid",
            default=True,
            help="start shell into container",
        )
    return parser.parse_args()


if __name__ == "__main__":
    program = os.path.basename(sys.argv[0])
    if program == 'enter':
        args = get_arguments('enter')
        ns_enter(int(args.pid))
    elif program == 'container':
        args = get_arguments()
        try:
            start_container(
                args.name,
                args.rootfs,
                args.command,
                args.args,
            )
        except KeyboardInterrupt:
            ip = IPRoute()
            eth1 = ip.link_lookup(ifname='eth1')[0]
            ip.link('del', index=eth1)

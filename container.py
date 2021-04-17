#!/usr/bin/env python3
import argparse
import libc
import os
import signal
import socket
from pyroute2 import IPRoute
import sys
import multiprocessing


class Veth(multiprocessing.Process):
    def __init__(self, name):
        super(Veth, self).__init__(group=None, target=None, name=name, args=(), kwargs={}, daemon=True)

    def run(self) -> None:
        self.create_veth()

    @staticmethod
    def get_child(p_pid):
        """
        :param p_pid: parent pid
        :return: children pid
        """
        child = []
        for pid in os.listdir('/proc'):
            if not pid.isnumeric():
                continue
            try:
                with open('/proc/{}/stat'.format(pid))as fp:
                    stat = fp.read().split(' ')
                    if p_pid.__str__() == stat[3]:
                        child.append(int(pid))
            except FileNotFoundError:
                pass
        return child

    def create_veth(self):
        import time
        while True:
            pid = os.getpid()
            tasks = self.get_child(os.getppid())
            tasks.remove(pid)
            if not tasks:
                time.sleep(1)
                continue
            else:
                pid = tasks[0]
                break
        ip_route = IPRoute()
        ip_route.link('add', ifname=self.name + '_eth0', kind='veth', peer='eth0')
        eth_0 = ip_route.link_lookup(ifname='eth0')[0]
        eth_1 = ip_route.link_lookup(ifname=self.name + '_eth0')[0]
        ip_route.addr('add', index=eth_1, address='10.0.0.1', broadcast='10.0.0.255', mask=24)
        ip_route.link('set', index=eth_0, net_ns_pid=pid)
        ip_route.link('set', index=eth_1, state='up')


class Container:
    def __init__(self, name: str, rootfs: str, cmd: list):
        self.name = name
        self.rootfs = rootfs
        self.cmd = cmd
        self.bind_dev_nodes = (
            'dev/tty',
            'dev/null',
            'dev/zero',
            'dev/random',
            'dev/urandom',
            'dev/full',
        )
        self.symbolic_link = (
            ('/dev/pts/ptmx', '/dev/ptmx'),
            ('/proc/self/fd', '/dev/fd'),
            ('/proc/self/fd/0', '/dev/stdin'),
            ('/proc/self/fd/1', '/dev/stdout'),
            ('/proc/self/fd/2', '/dev/stderr')
        )
        self.pid = os.getpid()
        self.uid = os.geteuid()
        self.gid = os.getegid()
        self.eth = Veth(self.name)

    def set_groups_write(self):
        with open(f'/proc/{self.pid}/setgroups', 'w') as f:
            f.write('deny')

    def map_user_group(self, ns_id, user_id, group_id, length=1):
        with open(f'/proc/{self.pid}/uid_map', 'w') as f:
            f.write(f'{ns_id} {user_id} {length}')
        with open(f'/proc/{self.pid}/gid_map', 'w') as f:
            f.write(f'{ns_id} {group_id} {length}')

    def start(self):
        self.eth.start()
        libc.unshare(
            libc.CLONE_NEWPID
            | libc.CLONE_NEWNET
            | libc.CLONE_NEWNS
            | libc.CLONE_NEWUTS
            | libc.CLONE_NEWCGROUP
            | libc.CLONE_NEWIPC
            | libc.CLONE_NEWUSER
        )
        # stop mounts leaking to host
        libc.mount(source='none', target='/', flag=libc.MS_REC | libc.MS_PRIVATE)
        # allow us to modify groups in a namespace
        self.set_groups_write()
        # map current user to root map current group to group 0 (normally wheel)
        self.map_user_group(0, self.uid, self.gid)
        # add a new hostname
        socket.sethostname(self.name)
        self.fork_cmd()

    def setup_fs(self, ):
        libc.mount(self.rootfs, self.rootfs, libc.MS_BIND | libc.MS_REC, 'bind')
        tmp = 'tmp/'
        old_root = os.path.join(self.rootfs, tmp)
        if not os.path.exists(old_root):
            os.makedirs(old_root)
        libc.pivot_root(self.rootfs, old_root)
        os.chdir('/')
        old_root = os.path.join('/', tmp)
        libc.mount(source='proc', target='/proc', flag=libc.MS_MGC_VAL, fs='proc')
        libc.mount(source='tmpfs', target='/dev', flag=libc.MS_NOSUID | libc.MS_STRICTATIME,
                   fs='tmpfs', options='mode=755')
        os.makedirs('/dev/shm', 0o755)
        libc.mount(source='tmpfs', target='/dev/shm', flag=libc.MS_NOSUID | libc.MS_STRICTATIME,
                   fs='tmpfs', options='mode=755')

        for device in self.bind_dev_nodes:
            new_device = os.path.join('/', device)
            host_device = os.path.join(old_root, device)
            if os.path.isfile(new_device):
                os.remove(new_device)
            open(new_device, 'a').close()
            libc.mount(host_device, new_device, libc.MS_BIND, 'bind')
        os.makedirs('/dev/pts', 0o755)
        libc.mount(
            source='devpts',
            target='/dev/pts',
            flag=libc.MS_NOEXEC | libc.MS_NOSUID,
            fs='devpts',
            options='newinstance,ptmxmode=0666,mode=620',
        )
        for src, dist in self.symbolic_link:
            os.symlink(src, dist)
        libc.mount(source='sysfs', target='/sys',
                   flag=libc.MS_RDONLY | libc.MS_NOSUID | libc.MS_NOEXEC | libc.MS_NODEV,
                   fs='sysfs')
        libc.unmount(old_root)

    def fork_cmd(self):
        # fork to enter the namespace
        pid = os.fork()
        # check if we're in the child process or the parent
        if pid == 0:
            self.setup_fs()
            os.execve(self.cmd[0], self.cmd, {
                'PATH': '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
                'LD_LIBRARY_PATH': '/usr/lib:/usr/local/lib:/lib:/lib64',
                'TERM': 'xterm',
            })
        else:
            # this is the parent, just wait for the child to exit
            print('Container\tPID:', pid)
            try:
                os.waitpid(pid, 0)
            except (KeyboardInterrupt, EOFError):
                os.kill(pid, signal.SIGKILL)


class Enter:
    def __init__(self, pid: int, cmd: list):
        self.pid = pid
        self.cmd = cmd
        self.child = None

    def __enter__(self):
        ns_type = {'pid': libc.CLONE_NEWPID,
                   'net': libc.CLONE_NEWNET,
                   'uts': libc.CLONE_NEWUTS,
                   'cgroup': libc.CLONE_NEWCGROUP,
                   'ipc': libc.CLONE_NEWIPC,
                   'user': libc.CLONE_NEWUSER,
                   'mnt': libc.CLONE_NEWNS}
        for name, flags in ns_type.items():
            fd = os.open(f'/proc/{self.pid}/ns/{name}', os.O_RDONLY)
            libc.set_ns(fd, flags)
            os.close(fd)
        libc.chroot('.')
        os.chdir('/')
        fd = os.open('.', os.O_RDONLY)
        libc.fchdir(fd)
        os.close(fd)
        self.fork_cmd()

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.child is not None:
            os.kill(self.child, signal.SIGKILL)

    def fork_cmd(self):
        pid = os.fork()
        if pid == 0:
            os.execve(self.cmd[0], self.cmd, {
                'PATH': '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
                'LD_LIBRARY_PATH': '/usr/lib:/usr/local/lib:/lib:/lib64',
                'TERM': 'xterm',
            })
        else:
            print('Container\tPID:', pid)
            try:
                os.waitpid(pid, 0)
            except (KeyboardInterrupt, EOFError):
                os.kill(pid, signal.SIGKILL)


def get_arguments(_type='container'):
    parser = argparse.ArgumentParser(description='Toy container runtime')
    if _type == 'container':
        parser.add_argument(
            '-n',
            '--name',
            metavar='hostname',
            default=socket.gethostname() + 'container',
            help='name of  container',
        )

        parser.add_argument(
            '-f',
            '--rootfs',
            help=' container` rootfs',
        )
        parser.add_argument(
            'command',
            metavar='ARG',
            nargs=argparse.REMAINDER,
            help='command and arguments',
        )
    elif _type == 'enter':
        parser.add_argument(
            '-p',
            '--pid',
            metavar='pid',
            default=True,
            help='start shell into container',
        )
    return parser.parse_args()


if __name__ == '__main__':
    program = os.path.basename(sys.argv[0])
    if program == 'enter':
        args = get_arguments('enter')
        with Enter(int(args.pid), ['/bin/bash']):
            pass
    elif program == 'container':
        args = get_arguments()
        try:
            Container(
                args.name,
                args.rootfs,
                args.command,
            ).start()
        except KeyboardInterrupt:
            ip = IPRoute()
            eth = ip.link_lookup(ifname=args.name + 'eth0')
            if eth:
                ip.link('del', index=eth[0])

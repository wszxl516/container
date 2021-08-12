mod net;
use std::collections::HashMap;
use std::ffi::CString;
use std::fmt::{Display, Formatter};
use std::{fs};
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path};
#[allow(unused_imports)]
use log::{debug, info};
use nix::{mount, sched, sys, unistd};
use nix::unistd::ForkResult;
use anyhow;
use std::os::unix::io::AsRawFd;
use env_logger::{fmt::Color, Builder};
use std::io::Write;
use log::Level;
use anyhow::Context;


const BIND_DEV_NODES: [&str; 6] = [
    "dev/tty",
    "dev/null",
    "dev/zero",
    "dev/random",
    "dev/urandom",
    "dev/full",
];
const SYMBOLIC_LINK: [(&str, &str); 5] = [
    ("/dev/pts/ptmx", "/dev/ptmx"),
    ("/proc/self/fd", "/dev/fd"),
    ("/proc/self/fd/0", "/dev/stdin"),
    ("/proc/self/fd/1", "/dev/stdout"),
    ("/proc/self/fd/2", "/dev/stderr")
];
const NS_TYPE: [(&str, sched::CloneFlags); 7] = [
    ("pid", sched::CloneFlags::CLONE_NEWPID),
    ("net", sched::CloneFlags::CLONE_NEWNET),
    ("uts", sched::CloneFlags::CLONE_NEWUTS),
    ("cgroup", sched::CloneFlags::CLONE_NEWCGROUP),
    ("ipc", sched::CloneFlags::CLONE_NEWIPC),
    ("user", sched::CloneFlags::CLONE_NEWUSER),
    ("mnt", sched::CloneFlags::CLONE_NEWNS)
];

#[derive(Debug, Clone)]
pub struct Env {
    record: HashMap<String, String>,
}

impl Env {
    #[allow(dead_code)]
    pub fn new() -> Env {
        Env { record: HashMap::new() }
    }
    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.record.len()
    }
    #[allow(dead_code)]
    pub fn insert(&mut self, key: String, value: String) -> () {
        self.record.insert(key, value);
    }
}

impl Display for Env {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.as_env())
    }
}

impl Default for Env {
    #[allow(dead_code)]
    fn default() -> Self {
        let mut default = HashMap::new();
        default.extend([
            ("HOME".to_string(), "/root".to_string()),
            ("TERM".to_string(), "linux".to_string()),
            ("USER".to_string(), "root".to_string()),
            ("PWD".to_string(), "/root".to_string()),
            ("PATH".to_string(), "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_string())
        ]);
        return Env { record: default };
    }
}

trait Convert2env {
    fn as_env(&self) -> Vec<CString>;
}

impl Convert2env for Env {
    #[allow(dead_code)]
    fn as_env(&self) -> Vec<CString> {
        self.record.iter()
            .map(|(k, v)| CString::new(format!("{}={}", k, v))
                .unwrap())
            .collect::<Vec<CString>>()
    }
}

#[derive(Debug, Clone)]
pub struct Args {
    pub record: Vec<String>,
}

impl Args {
    #[allow(dead_code)]
    pub fn new() -> Args {
        Args { record: Vec::<String>::new() }
    }
    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.record.len()
    }
    #[allow(dead_code)]
    pub fn insert(&mut self, arg: String) -> () {
        self.record.insert(self.record.len(), arg)
    }
}

impl Display for Args {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.as_args())
    }
}

trait Convert2args {
    fn as_args(&self) -> Vec<CString>;
}

impl Convert2args for Args {
    #[allow(dead_code)]
    fn as_args(&self) -> Vec<CString> {
        self.record.iter()
            .map(|s| CString::new(s.as_str()).unwrap())
            .collect::<Vec<CString>>()
    }
}

pub struct Container<'a> {
    name: &'a str,
    root: &'a str,
    init: &'a str,
    args: Args,
    env: Env,
    pid: unistd::Pid,
    uid: unistd::Uid,
    gid: unistd::Gid,
    out_address: String,
    ns_address: String
}

impl<'a> Container<'a> {
    pub fn new(name: &'a str,
               root: &'a str,
               init: &'a str,
               args: Args,
               env: Env,
               out_addr: String,
               ns_addr: String
    ) -> Self {
        Container {
            name,
            root,
            init,
            args,
            env,
            pid: unistd::getpid(),
            uid: unistd::geteuid(),
            gid: unistd::getegid(),
            out_address: out_addr,
            ns_address: ns_addr
        }
    }
    fn map_usr_grp(&self)->Result<(), anyhow::Error> {
        debug!("{}",format!("write /proc/{}/setgroups!", self.pid));
        let mut f = fs::File::create(format!("/proc/{}/setgroups", self.pid))?;
        f.write("deny".as_bytes())?;
        debug!("{}", format!("write /proc/{}/uid_map!", self.pid));
        let mut f = fs::File::create(format!("/proc/{}/uid_map", self.pid))?;
        f.write(format!("0 {} 1", self.uid).as_bytes())?;
        debug!("{}", format!("write /proc/{}/gid_map!", self.pid));
        let mut f = fs::File::create(format!("/proc/{}/gid_map", self.pid))?;
        f.write(format!("0 {} 1", self.gid).as_bytes())?;
        Ok(())
    }
    fn setup_fs(&self)-> Result<(), anyhow::Error>{
        info!("root filesystem {}!", self.root);
        mount::mount(Some(self.root), self.root,
                     Some(""),
                     mount::MsFlags::MS_REC | mount::MsFlags::MS_BIND,
                     Some(""))?;
        let tmp_dir = Path::new("tmp");
        let mut old_root = Path::new(self.root).join(tmp_dir);
        debug!("old root: {}", old_root.to_str().unwrap());
        debug!("pivot root!");
        unistd::pivot_root(self.root, old_root.to_str().unwrap())?;
        unistd::chdir("/")?;
        old_root = Path::new("/").join(tmp_dir);
        debug!("old root: {}", old_root.to_str().unwrap());
        debug!("mount proc!");
        mount::mount(Some("proc"),
                     "/proc",
                     Some("proc"),
                     mount::MsFlags::MS_MGC_VAL,
                     Some(""))?;
        debug!("mount /dev!");
        mount::mount(Some("tmpfs"),
                     "/dev",
                     Some("tmpfs"),
                     mount::MsFlags::MS_NOSUID | mount::MsFlags::MS_STRICTATIME,
                     Some("mode=755"))?;
        debug!("mount /dev/shm!");
        fs::create_dir("/dev/shm")?;
        fs::set_permissions("/dev/shm", fs::Permissions::from_mode(0o755))?;
        mount::mount(Some("tmpfs"),
                     "/dev/shm",
                     Some("tmpfs"),
                     mount::MsFlags::MS_NOSUID | mount::MsFlags::MS_STRICTATIME,
                     Some("mode=755"))?;
        for dev in BIND_DEV_NODES {
            let new_dev = Path::new("/").join(dev);
            let host_dev = Path::new(old_root.as_path()).join(dev);
            debug!("bind {} to {}!", host_dev.to_str().unwrap(), new_dev.to_str().unwrap());
            new_dev.is_file().then(|| fs::remove_file(&new_dev));
            fs::File::create(&new_dev)?;
            mount::mount(Some(host_dev.to_str().unwrap()),
                         &new_dev,
                         Some("bind"),
                         mount::MsFlags::MS_BIND,
                         Some(""))?;
        }
        Path::new("/dev/pts").exists().eq(&false).then(|| fs::create_dir("/dev/pts").unwrap());
        fs::set_permissions("/dev/pts", fs::Permissions::from_mode(0o755))?;
        mount::mount(Some("devpts"),
                     "/dev/pts",
                     Some("devpts"),
                     mount::MsFlags::MS_NOSUID | mount::MsFlags::MS_NOEXEC,
                     Some("newinstance,ptmxmode=0666,mode=620"))?;
        for (src, dst) in SYMBOLIC_LINK {
            debug!("create symbolic link {} to {}", src, dst);
            symlink(src, dst)?;
        }
        debug!("mount sysfs!");
        Path::new("/sys").exists().eq(&false).then(|| fs::create_dir("/sys").unwrap());
        mount::mount(Some("sysfs"),
                     "/sys",
                     Some("sysfs"),
                     mount::MsFlags::MS_RDONLY | mount::MsFlags::MS_NOSUID | mount::MsFlags::MS_NOEXEC | mount::MsFlags::MS_NODEV,
                     Some(""),
        )?;
        debug!("umount old root {}", old_root.to_str().unwrap());
        mount::umount2(old_root.to_str().unwrap(), mount::MntFlags::MNT_DETACH)?;
        Ok(())
    }
    pub fn start(&'a mut self) -> Result<(), anyhow::Error>{
        for sys_path in ["proc", "dev", "tmp", "sys"]{
            Path::new(self.root)
                .join(sys_path)
                .exists().eq(&false)
                .then(||fs::create_dir(Path::new(self.root)
                    .join(sys_path)));
        }
        match unsafe { unistd::fork() }? {
            ForkResult::Parent { child:_, .. } => {}
            ForkResult::Child => {
                let n = net::Network::new(self.name.to_string(),
                                              self.out_address.clone(),
                                              self.ns_address.clone(),
                                              self.pid.as_raw() as i32);
                n.start()?;
                Enter::new(self.pid.as_raw(),
                           Args::new(),
                           Default::default(),
                           false).start(||n.enable_network().unwrap())?;

                std::process::exit(0);
            }
        }
        let flags = sched::CloneFlags::CLONE_NEWPID |
            sched::CloneFlags::CLONE_NEWNET |
            sched::CloneFlags::CLONE_NEWNS |
            sched::CloneFlags::CLONE_NEWUTS |
            sched::CloneFlags::CLONE_NEWCGROUP |
            sched::CloneFlags::CLONE_NEWIPC |
            sched::CloneFlags::CLONE_NEWUSER;
        debug!("unshare!");
        sched::unshare(flags)?;
        mount::mount(Some("none"),
                     "/",
                     Some(""),
                     mount::MsFlags::MS_REC | mount::MsFlags::MS_PRIVATE,
                     Some(""))?;
        self.map_usr_grp().with_context(||"failed to map_usr_grp!")?;
        info!("set hostname to {}", self.name);
        unistd::sethostname(self.name).with_context(||"failed to set hostname!")?;
        debug!("fork!");
        match unsafe { unistd::fork() }? {
            ForkResult::Parent { child, .. } => {
                info!("container pid: {}", child);
                sys::wait::waitpid(child, None)?;
            }
            ForkResult::Child => {
                self.setup_fs().with_context(||"failed to setup fs!")?;
                let cmd = CString::new(self.init).unwrap();
                info!("start init {}!", self.init);
                info!("arguments: {}", self.args);
                info!("environment : {}", self.env);
                unistd::execve(cmd.as_c_str().as_ref(),
                               self.args.as_args().as_slice(),
                               self.env.as_env().as_slice()).with_context(||format!("failed to execve {:?}!", cmd))?;
            }

        }
        Ok(())
    }
}

pub struct Enter {
    pid: i32,
    cmd: Args,
    env: Env,
    console: bool,
}

impl Enter {
    pub fn new(pid: i32, cmd: Args, env: Env, console: bool) -> Enter {
        Enter {
            pid,
            cmd,
            env,
            console,
        }
    }
    pub fn start<F>(&self, f: F)-> Result<(), anyhow::Error>
        where F: Fn(){
        for (name, flag) in NS_TYPE{
            sched::setns(fs::File::open(format!("/proc/{}/ns/{}", self.pid, name)).unwrap().as_raw_fd(),
                         flag)?;
        }
        unistd::chroot(".")?;
        unistd::chdir("/")?;
        unistd::fchdir(fs::File::open("../../..").unwrap().as_raw_fd())?;
        match unsafe { unistd::fork() }? {
            ForkResult::Parent { child, .. } => {
                sys::wait::waitpid(child, None)?;
            }
            ForkResult::Child => {
                if self.console {
                    let cmd = CString::new(self.cmd.record.first().unwrap().as_str()).unwrap();
                    info!("start init {}!", self.cmd.record.first().unwrap());
                    info!("arguments: {}", self.cmd);
                    info!("environment : {}", self.env);
                    unistd::execve(cmd.as_c_str().as_ref(),
                                   self.cmd.as_args().as_slice(),
                                   self.env.as_env().as_slice())?;
                }
                f()
            }
        }
        Ok(())
    }
}

pub fn init_logger() {
    let env = env_logger::Env::default()
        .filter_or("log", "info")
        .write_style_or("log", "always");
    Builder::from_env(env)
        .format(|buf, record| {
            let mut style = buf.style();
            let color = match record.level(){
                Level::Error => {
                    Color::Red
                }
                Level::Warn => {
                    Color::Yellow
                }
                Level::Info => {
                    Color::Green
                }
                Level::Debug => {
                    Color::Blue
                }
                Level::Trace => {
                    Color::Magenta
                }
            };
            style.set_color(color).set_intense(false);
            let timestamp = buf.timestamp();
            writeln!(
                buf,
                "[{} {} {}]: {}",
                style.clone()
                    .set_intense(true)
                    .set_color(Color::Rgb(100, 100, 100))
                    .set_bold(true)
                    .value("container"),
                timestamp,
                style.clone()
                    .set_intense(true)
                    .set_bold(true)
                    .value(record.level()),
                style.value(record.args())
            )
        })
        .init();
}
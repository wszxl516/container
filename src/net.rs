use std::collections::HashSet;
use std::fs;
use std::io::Read;
use std::thread;
use std::time;
use nix::unistd;

use futures::stream::TryStreamExt;
use ipnetwork::IpNetwork;
use rtnetlink::new_connection;

#[derive(Clone, Debug)]
pub struct Network {
    name: String,
    pid: i32,
    ip_address0: IpNetwork,
    ip_address1: IpNetwork,
}

impl Network {
    pub fn new(name: String, ip_address0: String, ip_address1: String, pid: i32) -> Network {
        Network {
            name,
            pid,
            ip_address0: ip_address0.parse::<IpNetwork>().unwrap(),
            ip_address1: ip_address1.parse::<IpNetwork>().unwrap()
        }
    }
    pub fn start(&mut self) -> Result<(), anyhow::Error>{
        loop {
            let x = Network::find_child(self.pid);
            if x > 0 {
                break;
            }
            thread::sleep(time::Duration::new(0, 0));
        }

        tokio::runtime::Builder::new_multi_thread()
            .enable_io()
            .build()
            .unwrap()
            .block_on(self.v_eth())?;
        Ok(())
    }
    async fn v_eth(&mut self) -> Result<(), anyhow::Error> {
        let (connection, handle, _) = new_connection().unwrap();
        tokio::spawn(connection);
        handle
            .link()
            .add()
            .veth(format!("{}_eth0", self.name), format!("{}_eth1", self.name))
            .execute()
            .await?;
        let eth0 = handle
            .link()
            .get()
            .set_name_filter(format!("{}_eth0", self.name))
            .execute()
            .try_next()
            .await
            .unwrap()
            .unwrap();
        handle.address()
            .add(eth0.header.index, self.ip_address0.ip(), self.ip_address0.prefix())
            .execute().await?;
        handle.link().set(eth0.header.index).up().execute().await?;
        let eth1 = handle
            .link()
            .get()
            .set_name_filter(format!("{}_eth1", self.name))
            .execute()
            .try_next()
            .await
            .unwrap()
            .unwrap();
        handle.link().set(eth1.header.index)
            .setns_by_pid(self.pid as u32)
            .execute().await?;
        Ok(())
    }
    pub fn set_ns(&mut self) -> Result<(), anyhow::Error>{
        tokio::runtime::Builder::new_multi_thread()
            .enable_io()
            .build()
            .unwrap()
            .block_on(self.ns_ip())?;
        Ok(())
    }
    async fn ns_ip(&self)-> Result<(), anyhow::Error>{
        let (connection, handle, _) = new_connection().unwrap();
        tokio::spawn(connection);
        let eth1 = handle
            .link()
            .get()
            .set_name_filter(format!("{}_eth1", self.name))
            .execute()
            .try_next()
            .await
            .unwrap()
            .unwrap();
        handle.address()
            .add(eth1.header.index, self.ip_address1.ip(), self.ip_address1.prefix())
            .execute().await?;
        handle.link().set(eth1.header.index).up().execute().await?;
        Ok(())
    }
    fn find_child(ppid: i32) -> i32 {
        let mut pid = fs::read_dir("/proc")
            .unwrap()
            .filter(|p| {
                match p
                    .as_ref()
                    .unwrap()
                    .file_name()
                    .to_str()
                    .unwrap()
                    .parse::<u64>() {
                    Ok(_) => true,
                    Err(_) => false
                }
            }
            )
            .map(|pid| {
                let mut data = Vec::new();
                fs::File::open(format!("{}/stat", pid
                    .as_ref()
                    .unwrap()
                    .path()
                    .to_str()
                    .unwrap()))
                    .unwrap()
                    .read_to_end(&mut data)
                    .unwrap();
                let ppid_1 = String::from_utf8(data)
                    .unwrap()
                    .as_str()
                    .split(" ")
                    .map(|x| x.parse::<i32>().unwrap_or(0)).collect::<Vec<i32>>()[3];
                if ppid_1 == ppid {
                    pid.as_ref().unwrap().file_name().to_str().unwrap().parse::<i32>().unwrap()
                } else {
                    0
                }
            }).collect::<HashSet<i32>>();
        let net_pid = unistd::getpid().as_raw();
        pid.remove(&0i32);
        pid.remove(&net_pid);
        match pid.is_empty() {
            true => { 0 }
            false => {
                pid.iter().collect::<Vec<&i32>>()[0].clone()
            }
        }
    }
}
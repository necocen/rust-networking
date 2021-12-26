use anyhow::{bail, Result};
use ifstructs::ifreq;
use libc::{
    __errno_location, bind, c_void, close, ioctl, poll, pollfd, read, sockaddr_ll, socket, write,
    AF_PACKET, EINTR, ETH_P_ALL, PF_PACKET, POLLERR, POLLIN, SIOCGIFFLAGS, SOCK_RAW,
};
use std::{
    intrinsics::transmute,
    mem::{size_of, zeroed},
    sync::{Arc, Mutex},
};

use crate::constants::*;

#[derive(Debug, Clone)]
pub struct Socket {
    inner: Arc<Mutex<SocketInner>>,
}

#[derive(Debug, Clone)]
struct SocketInner {
    soc: i32,
    device_name: String,
}

impl SocketInner {
    fn close(&self) -> Result<()> {
        let mut if_req: ifreq = unsafe { zeroed() };

        if_req.set_name(&self.device_name)?;
        if unsafe { ioctl(self.soc, SIOCGIFFLAGS, &if_req) } < 0 {
            bail!("ioctl");
        }

        unsafe {
            if_req.ifr_ifru.ifr_flags &= !IFF_PROMISC;
        }
        if unsafe { ioctl(self.soc, SIOCGIFFLAGS, &if_req) } < 0 {
            bail!("ioctl");
        }

        unsafe {
            close(self.soc);
        }

        log::info!("Socket closed");

        Ok(())
    }
}

impl Drop for SocketInner {
    fn drop(&mut self) {
        if let Some(err) = self.close().err() {
            eprintln!("{}", err);
        }
    }
}

impl Socket {
    pub fn new(device_name: &str) -> Result<Socket> {
        let mut if_req: ifreq = unsafe { zeroed() };
        let mut sockaddr: sockaddr_ll = unsafe { zeroed() };

        let soc = unsafe { socket(AF_PACKET, SOCK_RAW, ETH_P_ALL.to_be()) };
        if soc < 0 {
            bail!("socket");
        }

        if_req.set_name(device_name)?;
        if unsafe { ioctl(soc, SIOCGIFINDEX, &if_req) } < 0 {
            unsafe {
                close(soc);
            }
            bail!("ioctl");
        }

        sockaddr.sll_family = PF_PACKET as u16;
        sockaddr.sll_protocol = (ETH_P_ALL as u16).to_be();
        sockaddr.sll_ifindex = unsafe { if_req.ifr_ifru.ifr_ifindex };
        if unsafe { bind(soc, transmute(&sockaddr), size_of::<sockaddr_ll>() as u32) } < 0 {
            unsafe {
                close(soc);
            }
            bail!("bind");
        }

        if unsafe { ioctl(soc, SIOCGIFFLAGS, &if_req) } < 0 {
            unsafe {
                close(soc);
            }
            bail!("ioctl");
        }

        unsafe { if_req.ifr_ifru.ifr_flags |= IFF_PROMISC | IFF_UP };
        if unsafe { ioctl(soc, SIOCGIFFLAGS, &if_req) } < 0 {
            unsafe {
                close(soc);
            }
            bail!("ioctl");
        }
        Ok(Socket {
            inner: Arc::new(Mutex::new(SocketInner {
                soc,
                device_name: device_name.to_owned(),
            })),
        })
    }

    pub fn write(&self, data: &[u8]) {
        let soc = self.inner.lock().unwrap().soc;
        unsafe {
            write(soc, data.as_ptr() as *const c_void, data.len());
        }
        log::debug!("Write {} bytes to socket", data.len());
    }

    pub fn read(&self, buffer: &mut [u8]) -> Result<usize> {
        let soc = self.inner.lock().unwrap().soc;
        // TODO: これは配列を経由しなくてもいいよね
        let mut targets: [pollfd; 1] = unsafe { zeroed() };
        targets[0].fd = soc;
        targets[0].events = POLLIN | POLLERR;
        let ready = unsafe { poll(&mut targets as *mut pollfd, 1, 1000) };
        match ready {
            -1 => {
                let errno = unsafe { __errno_location().read() };
                if errno != EINTR {
                    bail!("poll error");
                } else {
                    bail!("unknown error: {}", errno);
                }
            }
            0 => {
                bail!("timeout");
            }
            _ => {
                if targets[0].revents & (POLLIN | POLLERR) != 0 {
                    let len = unsafe { read(soc, buffer as *mut _ as *mut c_void, buffer.len()) };
                    if len <= 0 {
                        bail!("read");
                    } else {
                        Ok(len as usize)
                    }
                } else {
                    bail!("unknown error");
                }
            }
        }
    }
}

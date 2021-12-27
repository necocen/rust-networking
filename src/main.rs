use crate::{
    arp::ArpClient, cmd::Cmd, constants::*, ether::EtherClient, icmp::IcmpClient, ip::IpClient,
    receiver::Receiver, socket::Socket, udp::UdpClient,
};
use anyhow::bail;
use ifstructs::ifreq;

use libc::{
    __errno_location, c_char, close, fgets, ioctl, poll, pollfd, signal, sockaddr_in, socket,
    AF_INET, EINTR, POLLERR, POLLIN, SIGINT, SIGPIPE, SIGQUIT, SIGTERM, SIG_IGN, SIOCGIFADDR,
    SIOCGIFFLAGS, SIOCGIFHWADDR, SIOCGIFMTU, SOCK_DGRAM, STDIN_FILENO,
};
use mac_addr::MacAddr;
use params::Params;

use std::{
    ffi::CStr,
    mem::{transmute, zeroed},
    net::Ipv4Addr,
    sync::atomic::{AtomicBool, Ordering},
    thread::spawn,
};

mod arp;
mod cmd;
mod constants;
mod ether;
mod icmp;
mod ip;
mod mac_addr;
mod params;
mod receiver;
mod socket;
mod udp;
mod utils;

extern "C" {
    pub static stdin: *mut libc::FILE;
}

fn show_if_req(params: &mut Params) -> anyhow::Result<()> {
    let soc = unsafe { socket(AF_INET, SOCK_DGRAM, 0) };
    let mut if_req: ifreq = unsafe { zeroed() };
    if soc == -1 {
        bail!("socket");
    }

    if_req.set_name(&params.device)?;
    if unsafe { ioctl(soc, SIOCGIFFLAGS, &if_req) } == -1 {
        unsafe {
            close(soc);
        }
        bail!("ioctl:flags");
    }

    unsafe {
        if if_req.ifr_ifru.ifr_flags & IFF_UP != 0 {
            print!("UP ");
        }
        if if_req.ifr_ifru.ifr_flags & IFF_BROADCAST != 0 {
            print!("BROADCAST ");
        }
        if if_req.ifr_ifru.ifr_flags & IFF_PROMISC != 0 {
            print!("PROMISC ");
        }
        if if_req.ifr_ifru.ifr_flags & IFF_MULTICAST != 0 {
            print!("MULTICAST ");
        }
        if if_req.ifr_ifru.ifr_flags & IFF_LOOPBACK != 0 {
            print!("LOOPBACK ");
        }
        if if_req.ifr_ifru.ifr_flags & IFF_POINTOPOINT != 0 {
            print!("P2P ");
        }
        println!();
    }

    if unsafe { ioctl(soc, SIOCGIFMTU, &if_req) } == -1 {
        eprintln!("ioctl:mtu");
    } else {
        unsafe { println!("mtu = {:}", if_req.ifr_ifru.ifr_mtu) };
    }

    if unsafe { ioctl(soc, SIOCGIFADDR, &if_req) } == -1 {
        eprintln!("ioctl:addr");
    } else if unsafe { if_req.ifr_ifru.ifr_addr.sa_family } != AF_INET as u16 {
        println!("not AF_INET");
    } else {
        let addr: sockaddr_in = unsafe { transmute(if_req.ifr_ifru.ifr_addr) };
        let my_ip = Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr));
        println!("my_ip = {:}", my_ip.to_string());
        params.my_ip = my_ip;
    }

    unsafe {
        close(soc);
    }

    let my_mac = get_mac_address(&params.device)?;
    println!("my_mac = {}", my_mac);
    params.my_mac = my_mac;

    Ok(())
}

fn get_mac_address(device: &str) -> anyhow::Result<MacAddr> {
    let mut if_req: ifreq = unsafe { zeroed() };
    let soc = unsafe { socket(AF_INET, SOCK_DGRAM, 0) };
    if soc < 0 {
        bail!("socket");
    }

    if_req.set_name(device)?;
    if unsafe { ioctl(soc, SIOCGIFHWADDR, &if_req) } == -1 {
        unsafe {
            close(soc);
        }
        bail!("ioctl:hwaddr");
    }

    let mut hwaddr = [0; 6];
    hwaddr.copy_from_slice(&unsafe { if_req.ifr_ifru.ifr_hwaddr.sa_data }[..6]);

    unsafe {
        close(soc);
    }
    Ok(hwaddr.into())
}

fn main() -> anyhow::Result<()> {
    env_logger::init();

    let file = std::fs::read_to_string("./config.toml")?;
    let mut params = params::Params::from_str(&file)?;

    println!("IP-TTL = {}", params.ip_ttl);
    println!("MTU = {}", params.mtu);

    println!("device = {:}", params.device);
    println!("+++++++++++++++++++++++++++++++++++++++++++++");
    show_if_req(&mut params)?;
    println!("+++++++++++++++++++++++++++++++++++++++++++++");
    println!("virtual_mac = {:}", params.virtual_mac);
    println!("virtual_ip = {:}", params.virtual_ip);
    println!("virtual_mask = {:}", params.virtual_mask);
    println!("gateway = {:}", params.gateway);

    /// スレッド停止フラグ
    static RUNNING: AtomicBool = AtomicBool::new(true);
    extern "C" fn sig_term(sig: libc::c_int) {
        RUNNING.store(false, Ordering::Relaxed);
        eprintln!("SIGNAL: {:}", sig);
    }

    unsafe {
        signal(SIGINT, sig_term as libc::sighandler_t);
        signal(SIGTERM, sig_term as libc::sighandler_t);
        signal(SIGQUIT, sig_term as libc::sighandler_t);
        signal(SIGPIPE, SIG_IGN);
    }
    let socket = Socket::new(&params.device)?;
    let ether_client = EtherClient::new(socket.clone());
    let arp_client = ArpClient::new(ether_client.clone());
    let ip_client = IpClient::new(ether_client.clone(), arp_client.clone());
    let icmp_client = IcmpClient::new(ip_client.clone());
    let udp_client = UdpClient::new(ip_client.clone());

    let cmd = Cmd {
        arp_client: arp_client.clone(),
        icmp_client: icmp_client.clone(),
        udp_client,
        params: params.clone(),
    };
    let receiver = Receiver {
        ether_client,
        arp_client: arp_client.clone(),
        ip_client,
        icmp_client,
        params: params.clone(),
    };
    let cmd_thread_handler = spawn(move || {
        let mut targets: [pollfd; 1] = unsafe { zeroed() };
        let mut buf: [u8; 2048] = unsafe { zeroed() };
        targets[0].fd = STDIN_FILENO;
        targets[0].events = POLLIN | POLLERR;
        while RUNNING.load(Ordering::Relaxed) {
            let ready = unsafe { poll(&mut targets as *mut pollfd, 1, 1000) };
            match ready {
                -1 => {
                    let errno = unsafe { __errno_location().read() };
                    if errno != EINTR {
                        eprintln!("poll");
                    }
                }
                0 => {} // noop
                _ => {
                    if targets[0].revents & (POLLIN | POLLERR) != 0 {
                        unsafe {
                            fgets(&mut buf as *mut c_char, buf.len() as i32, stdin);
                        }
                        let args = unsafe { CStr::from_ptr(buf.as_ptr()) }.to_str().unwrap();
                        if let Err(e) = cmd.do_cmd(args) {
                            eprintln!("{:?}", e);
                        }
                    }
                }
            }
        }
    });

    let eth_thread_handler = spawn(move || {
        let mut buf: [u8; 2048] = unsafe { zeroed() };
        while RUNNING.load(Ordering::Relaxed) {
            let len = match socket.read(&mut buf) {
                Ok(len) => len,
                Err(e) => {
                    if e.to_string() != "timeout" {
                        eprintln!("{}", e);
                    }
                    continue;
                }
            };
            if let Err(e) = receiver.receive(&buf[..len]) {
                if e.to_string() != "other" {
                    eprintln!("{}", e);
                }
            }
        }
    });

    if !arp_client.check_ip_unique(&params) {
        bail!("IP check failed");
    }

    let _ = eth_thread_handler.join();
    let _ = cmd_thread_handler.join();

    Ok(())
}

use std::{
    ffi::CString,
    net::Ipv4Addr,
    sync::{Arc, Mutex},
    thread::sleep,
    time::Duration,
};

use anyhow::{bail, Context as C, Result};
use libc::{kill, SIGTERM};

use crate::{
    arp::ArpClient, constants::*, context::Context, icmp::IcmpClient, tcp::TcpClient,
    udp::UdpClient, utils::unescape,
};

#[derive(Debug, Clone)]
pub struct Cmd {
    pub arp_client: ArpClient,
    pub icmp_client: IcmpClient,
    pub udp_client: UdpClient,
    pub tcp_client: TcpClient,
    pub context: Arc<Mutex<Context>>,
}

impl Cmd {
    fn ping<'a>(&self, args: &mut impl Iterator<Item = &'a str>) -> Result<()> {
        let arg = args.next().context("do_cmd_ping: no args")?;
        let dst_ip: Ipv4Addr = arg.parse()?;
        let size: usize = if let Some(arg) = args.next() {
            arg.parse()?
        } else {
            DEFAULT_PING_SIZE
        };
        for i in 0..4 {
            // PING_SEND_NO
            self.icmp_client.send_echo(&dst_ip, i + 1, size)?;
            sleep(Duration::from_secs(1));
        }
        Ok(())
    }

    fn arp<'a>(&self, args: &mut impl Iterator<Item = &'a str>) -> Result<()> {
        let arg = args.next().context("do_cmd_arp: no args")?;
        match arg {
            "-a" => {
                self.arp_client.print_table();
            }
            "-d" => {
                let arg = args.next().context("do_cmd_arp: -d has no args")?;
                let ip: Ipv4Addr = arg.parse()?;
                self.arp_client.remove_ip(&ip);
                println!("deleted / not exists");
            }
            _ => {
                bail!("do_cmd_arp: unknown arg: {}", arg);
            }
        }
        Ok(())
    }

    fn udp<'a>(&self, args: &mut impl Iterator<Item = &'a str>) -> Result<()> {
        let arg = args.next().context("do_cmd_udp: no args")?;
        match arg {
            "open" => {
                let port = if let Some(arg) = args.next() {
                    self.udp_client.open(arg.parse()?)?
                } else {
                    self.udp_client.open(0)?
                };
                println!("do_cmd_udp: opened port {}", port);
            }
            "close" => {
                let arg = args.next().context("do_cmd_udp: close has no args")?;
                self.udp_client.close(arg.parse()?);
                println!("do_cmd_udp: closed port {}", arg);
            }
            "send" => {
                let context = self.context.lock().unwrap().clone();
                let arg = args.next().context("do_cmd_udp: send has no args")?;
                let src_port: u16 = arg.parse()?;
                let arg = args.next().context("do_cmd_udp: send has no destination")?;
                // addr:portの形式
                let mut iter = arg.split(':');
                let dst_ip: Ipv4Addr = iter
                    .next()
                    .context("do_cmd_udp: send has no destination ip")?
                    .parse()?;
                let dst_port: u16 = iter
                    .next()
                    .context("do_cmd_udp: send has no destination port")?
                    .parse()?;
                let arg = args.next().context("do_cmd_udp: send has no content")?;
                let content = CString::new(unescape(arg))?;
                self.udp_client.send(
                    &context.virtual_ip,
                    &dst_ip,
                    src_port,
                    dst_port,
                    false,
                    content.as_bytes(),
                )?;
            }
            _ => {
                bail!("do_cmd_udp: unknown arg: {}", arg);
            }
        }
        Ok(())
    }

    fn netstat(&self) {
        println!("----------------------------------------");
        println!("protocol: port=data");
        println!("----------------------------------------");
        self.udp_client.show_table();
        self.tcp_client.show_table();
    }

    fn tcp<'a>(&self, args: &mut impl Iterator<Item = &'a str>) -> Result<()> {
        let arg = args.next().context("do_cmd_tcp: no args")?;
        match arg {
            "listen" => {
                let port: u16 = args.next().and_then(|p| p.parse().ok()).unwrap_or(0);
                self.tcp_client.listen(port)?;
                println!("do_cmd_tcp: listen {}", port);
            }
            "close" => {
                let port: u16 = args
                    .next()
                    .and_then(|p| p.parse().ok())
                    .context("do_cmd_tcp: close: invalid port")?;
                self.tcp_client.close(port)?;
                println!("do_cmd_tcp: close {}", port);
            }
            "reset" => {
                let port: u16 = args
                    .next()
                    .and_then(|p| p.parse().ok())
                    .context("do_cmd_tcp: reset: invalid port")?;
                self.tcp_client.reset(port)?;
                println!("do_cmd_tcp: reset {}", port);
            }
            "connect" => {
                let src_port: u16 = args
                    .next()
                    .and_then(|p| p.parse().ok())
                    .context("do_cmd_tcp: connect: invalid port")?;
                let arg = args
                    .next()
                    .context("do_cmd_tcp: connect: has no destination")?;
                // addr:portの形式
                let mut iter = arg.split(':');
                let dst_ip: Ipv4Addr = iter
                    .next()
                    .context("do_cmd_tcp: connect: has no destination ip")?
                    .parse()?;
                let dst_port: u16 = iter
                    .next()
                    .context("do_cmd_tcp: connect: has no destination port")?
                    .parse()?;
                self.tcp_client.connect(src_port, &dst_ip, dst_port)?;
            }
            "send" => {
                let arg = args.next().context("do_cmd_tcp: send has no args")?;
                let src_port: u16 = arg.parse()?;
                let arg = args.next().context("do_cmd_tcp: send has no content")?;
                let content = CString::new(unescape(arg))?;
                self.tcp_client.send(src_port, content.as_bytes())?;
            }
            _ => {
                bail!("do_cmd_tcp: unknown arg: {}", arg);
            }
        }
        Ok(())
    }

    pub fn do_cmd(&self, cmd: &str) -> Result<()> {
        let mut args = cmd.split_ascii_whitespace().peekable();
        if args.peek() == None {
            println!("do_cmd: no cmd");
            println!("----------------------------------------");
            println!("arp -a : show arp table");
            println!("arp -d <addr> : remove <addr> from arp table");
            println!("ping addr <size> : send ping");
            println!("ifconfig : show interface configuration");
            println!("netstat : show active ports");
            println!("udp open <port> : open udp-recv port");
            println!("udp close <port> : close udp-recv port");
            println!("udp send <sport> <daddr>:<dport> <data> : send udp");
            println!("tcp listen <port> : listen tcp-accept port");
            println!("tcp close <port> : close tcp port");
            println!("tcp reset <port> : reset tcp port");
            println!("tcp connect <sport> <daddr>:<dport> : tcp connect");
            println!("tcp send <sport> <data> : send tcp");
            println!("end : end program");
            println!("----------------------------------------");
            return Ok(());
        }

        let cmd = args.next().unwrap();
        match cmd {
            "arp" => self.arp(&mut args),
            "ping" => self.ping(&mut args),
            "ifconfig" => {
                self.context.lock().unwrap().print();
                Ok(())
            }
            "udp" => self.udp(&mut args),
            "tcp" => self.tcp(&mut args),
            "netstat" => {
                self.netstat();
                Ok(())
            }
            "end" => {
                unsafe { kill(std::process::id() as i32, SIGTERM) };
                Ok(())
            }
            _ => {
                bail!("do_cmd: unknown cmd : {}", cmd);
            }
        }
    }
}

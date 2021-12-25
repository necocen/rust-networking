use std::{net::Ipv4Addr, thread::sleep, time::Duration};

use anyhow::{bail, Context, Result};
use libc::{kill, SIGTERM};

use crate::{arp::ArpClient, constants::*, icmp::IcmpClient, params::Params};

#[derive(Debug, Clone)]
pub struct Cmd {
    pub arp_client: ArpClient,
    pub icmp_client: IcmpClient,
    pub params: Params,
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
            self.icmp_client
                .send_echo(&self.params, &dst_ip, i + 1, size)?;
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

    pub fn do_cmd(&self, cmd: &str) -> Result<()> {
        let mut args = cmd.split_ascii_whitespace().peekable();
        if args.peek() == None {
            println!("do_cmd: no cmd");
            println!("----------------------------------------");
            println!("arp -a : show arp table");
            println!("arp -d <addr> : remove <addr> from arp table");
            println!("ping addr <size> : send ping");
            println!("ifconfig : show interface configuration");
            println!("end : end program");
            println!("----------------------------------------");
            return Ok(());
        }

        let cmd = args.next().unwrap();
        match cmd {
            "arp" => self.arp(&mut args),
            "ping" => self.ping(&mut args),
            "ifconfig" => {
                self.params.print();
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

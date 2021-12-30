use std::{
    mem::size_of,
    net::Ipv4Addr,
    sync::{Arc, Mutex},
};

use anyhow::{Context as C, Result};
use chrono::Local;
use libc::ARPOP_REQUEST;

use crate::{
    arp::ArpClient,
    constants::*,
    context::Context,
    dhcp::DhcpClient,
    ether::{EtherClient, EtherData},
    icmp::{IcmpClient, IcmpHeader},
    ip::IpClient,
    udp::{UdpClient, UdpHeader},
};

#[derive(Debug, Clone)]
pub struct Receiver {
    pub ether_client: EtherClient,
    pub arp_client: ArpClient,
    pub ip_client: IpClient,
    pub icmp_client: IcmpClient,
    pub udp_client: UdpClient,
    pub dhcp_client: DhcpClient,
    pub context: Arc<Mutex<Context>>,
}

impl Receiver {
    pub fn receive(&self, data: &[u8]) -> Result<()> {
        let context = self.context.lock().unwrap().clone();
        self.ether_client.receive(data).and_then(|data| {
            match data {
                EtherData::Arp(eh, data) => {
                    let arp = self.arp_client.receive(data)?;
                    if u16::from_be(arp.arp_op) == ARPOP_REQUEST {
                        self.arp_client.send_reply(&eh, &arp)?;
                    }
                }
                EtherData::Ip(_, data) => {
                    let (ip, data) = self.ip_client.receive(data)?;

                    match (ip.ip_p, data) {
                        (_, None) => {}
                        (IPPROTO_ICMP, Some(data)) => {
                            let icmp = self.icmp_client.receive(&ip, &data)?;
                            if icmp.icmp_type == ICMP_ECHO {
                                self.icmp_client.send_echo_reply(
                                    &ip,
                                    &icmp,
                                    &data[size_of::<IcmpHeader>()..],
                                    context.ip_ttl,
                                )?;
                            }
                        }
                        (IPPROTO_UDP, Some(data)) => {
                            match self.udp_client.receive(&ip, &data) {
                                Ok(udp) if u16::from_be(udp.uh_dport) == DHCP_CLIENT_PORT => {
                                    let dhcp = self
                                        .dhcp_client
                                        .receive(&data[size_of::<UdpHeader>()..])?;
                                    if dhcp.op == DHCP_BOOTREPLY {
                                        // TODO: やっぱこういうのはちょっと変というか、DhcpClientで完結できるものはDhcpClientでやる設計にすべきっぽい
                                        if let Some(ty) = dhcp.get_option(53) {
                                            match ty[0] {
                                                DHCP_OFFER => {
                                                    let ip = dhcp
                                                        .get_option(54)
                                                        .map(|ip| {
                                                            Ipv4Addr::from([
                                                                ip[0], ip[1], ip[2], ip[3],
                                                            ])
                                                        })
                                                        .context("Dhcp: invalid server ip")?;
                                                    self.dhcp_client.send_request(
                                                        &Ipv4Addr::from(u32::from_be(dhcp.yiaddr)),
                                                        &ip,
                                                    )?;
                                                }
                                                DHCP_ACK => {
                                                    // TODO: virtual_ip書き換えが生じる
                                                    let ip =
                                                        Ipv4Addr::from(u32::from_be(dhcp.yiaddr));
                                                    let dhcp_server = dhcp
                                                        .get_option(54)
                                                        .map(|ip| {
                                                            Ipv4Addr::from([
                                                                ip[0], ip[1], ip[2], ip[3],
                                                            ])
                                                        })
                                                        .context("Dhcp: invalid dhcp server ip")?;
                                                    let mask = dhcp
                                                        .get_option(1)
                                                        .map(|ip| {
                                                            Ipv4Addr::from([
                                                                ip[0], ip[1], ip[2], ip[3],
                                                            ])
                                                        })
                                                        .context("Dhcp: invalid netmask")?;
                                                    let gateway = dhcp
                                                        .get_option(3)
                                                        .map(|ip| {
                                                            Ipv4Addr::from([
                                                                ip[0], ip[1], ip[2], ip[3],
                                                            ])
                                                        })
                                                        .context("Dhcp: invalid gateway")?;
                                                    let lease_time = dhcp
                                                        .get_option(51)
                                                        .map(|data| {
                                                            u32::from_be_bytes([
                                                                data[0], data[1], data[2], data[3],
                                                            ])
                                                        })
                                                        .context("Dhcp: invalid lease time")?;
                                                    log::info!("ip = {}", ip);
                                                    log::info!("mask = {}", mask);
                                                    log::info!("gateway = {}", gateway);
                                                    log::info!("DHCP server = {}", dhcp_server);
                                                    log::info!(
                                                        "DHCP start time = {}",
                                                        Local::now()
                                                    );
                                                    log::info!("DHCP lease time = {}", lease_time);
                                                }
                                                DHCP_NAK => {
                                                    // TODO: virtual_ip書き換えが生じる
                                                    self.dhcp_client.send_discover()?;
                                                }
                                                _ => {}
                                            }
                                        }
                                    }
                                }
                                Ok(_) => {}
                                Err(e) if e.to_string() == "other" => {
                                    let dst_ip = Ipv4Addr::from(u32::from_be(ip.ip_src));
                                    self.icmp_client
                                        .send_destination_unreachable(&ip, &dst_ip, &data)?;
                                }
                                Err(e) => {
                                    return Err(e);
                                }
                            }
                        }
                        _ => {
                            log::warn!("Unknown protocol: {}", ip.ip_p);
                        }
                    }
                }
            }
            Ok(())
        })
    }
}

use std::{mem::size_of, net::Ipv4Addr};

use anyhow::Result;
use libc::ARPOP_REQUEST;

use crate::{
    arp::ArpClient,
    constants::*,
    ether::{EtherClient, EtherData},
    icmp::{IcmpClient, IcmpHeader},
    ip::{IpClient, IpHeader},
    params::Params,
    udp::UdpClient,
};

#[derive(Debug, Clone)]
pub struct Receiver {
    pub ether_client: EtherClient,
    pub arp_client: ArpClient,
    pub ip_client: IpClient,
    pub icmp_client: IcmpClient,
    pub udp_client: UdpClient,
    pub params: Params,
}

impl Receiver {
    pub fn receive(&self, data: &[u8]) -> Result<()> {
        self.ether_client
            .receive(&self.params, data)
            .and_then(|data| {
                match data {
                    EtherData::Arp(eh, data) => {
                        let arp = self.arp_client.receive(&self.params, data)?;
                        if u16::from_be(arp.arp_op) == ARPOP_REQUEST {
                            self.arp_client.send_reply(&self.params, &eh, &arp)?;
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
                                        &self.params,
                                        &ip,
                                        &icmp,
                                        &data[size_of::<IcmpHeader>()..],
                                        self.params.ip_ttl,
                                    )?;
                                }
                            }
                            (IPPROTO_UDP, Some(data)) => {
                                match self.udp_client.receive(&ip, &data) {
                                    Ok(udp) if u16::from_be(udp.uh_dport) == DHCP_CLIENT_PORT => {
                                        todo!("dhcp receive");
                                    }
                                    Ok(_) => {}
                                    Err(e) if e.to_string() == "other" => {
                                        let dst_ip = Ipv4Addr::from(u32::from_be(ip.ip_src));
                                        self.icmp_client.send_destination_unreachable(
                                            &self.params,
                                            &ip,
                                            &dst_ip,
                                            &data,
                                        )?;
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

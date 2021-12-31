use std::{
    net::Ipv4Addr,
    sync::{Arc, Mutex},
};

use anyhow::{bail, Result};

use crate::{
    arp::ArpClient, constants::*, context::Context, dhcp::DhcpClient, ether::EtherClient,
    icmp::IcmpClient, ip::IpClient, udp::UdpClient,
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
        self.ether_client.receive(data).and_then(|(eh, data)| {
            match u16::from_be(eh.ether_type) {
                ETH_P_ARP => {
                    self.arp_client.receive(&eh, data)?;
                }
                ETH_P_IP => {
                    let (ip, data) = self.ip_client.receive(data)?;
                    match (ip.ip_p, data) {
                        (_, None) => {}
                        (IPPROTO_ICMP, Some(data)) => {
                            self.icmp_client.receive(&ip, &data)?;
                        }
                        (IPPROTO_UDP, Some(data)) => match self.udp_client.receive(&ip, &data) {
                            Ok((udp, data)) if u16::from_be(udp.uh_dport) == DHCP_CLIENT_PORT => {
                                self.dhcp_client.receive(data)?;
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
                        },
                        _ => {
                            log::warn!("Unknown protocol: {}", ip.ip_p);
                        }
                    }
                }
                _ => {
                    bail!("unknown protocol")
                }
            }
            Ok(())
        })
    }
}

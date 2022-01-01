use std::{
    net::Ipv4Addr,
    sync::{Arc, Mutex},
};

use anyhow::{bail, Result};

use crate::{
    arp::ArpClient,
    constants::*,
    context::Context,
    dhcp::DhcpClient,
    ether::{EtherClient, EtherHeader},
    icmp::IcmpClient,
    ip::{IpClient, IpHeader},
    udp::UdpClient,
};

#[derive(Debug, Clone)]
pub struct Receiver {
    pub ether_client: EtherClient,
    pub arp_client: ArpClient,
    pub ip_client: IpClient,
    pub icmp_client: IcmpClient,
    pub udp_client: UdpClient,
    pub dhcp_client: Arc<Mutex<DhcpClient>>,
    pub context: Arc<Mutex<Context>>,
}

impl Receiver {
    pub fn receive(&self, data: &[u8]) -> Result<()> {
        let (eh, data) = self.ether_client.receive(data)?;
        match u16::from_be(eh.ether_type) {
            ETH_P_ARP => self.receive_arp(&eh, data),
            ETH_P_IP => self.receive_ip(data),
            _ => {
                bail!("unknown protocol");
            }
        }
    }

    fn receive_dhcp(&self, data: &[u8]) -> Result<()> {
        self.dhcp_client.lock().unwrap().receive(data)?;
        Ok(())
    }

    fn receive_udp(&self, ip: &IpHeader, data: &[u8]) -> Result<()> {
        match self.udp_client.receive(ip, data) {
            Ok((udp, data)) if u16::from_be(udp.uh_dport) == DHCP_CLIENT_PORT => {
                self.receive_dhcp(data)
            }
            Ok(_) => Ok(()),
            Err(e) if e.to_string() == "other" => {
                let dst_ip = Ipv4Addr::from(u32::from_be(ip.ip_src));
                self.icmp_client
                    .send_destination_unreachable(ip, &dst_ip, data)
            }
            Err(e) => Err(e),
        }
    }

    fn receive_icmp(&self, ip: &IpHeader, data: &[u8]) -> Result<()> {
        self.icmp_client.receive(ip, data)?;
        Ok(())
    }

    fn receive_ip(&self, data: &[u8]) -> Result<()> {
        let (ip, data) = self.ip_client.receive(data)?;
        match (ip.ip_p, data) {
            (IPPROTO_ICMP, Some(data)) => self.receive_icmp(&ip, &data)?,
            (IPPROTO_UDP, Some(data)) => self.receive_udp(&ip, &data)?,
            (_, None) => {
                log::trace!("Receive fragment");
            }
            _ => {
                log::warn!("Unknown protocol: {}", ip.ip_p);
            }
        }
        Ok(())
    }

    fn receive_arp(&self, eh: &EtherHeader, data: &[u8]) -> Result<()> {
        self.arp_client.receive(eh, data)?;
        Ok(())
    }
}

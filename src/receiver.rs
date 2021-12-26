use std::mem::size_of;

use anyhow::Result;
use libc::ARPOP_REQUEST;

use crate::{
    arp::ArpClient,
    constants::*,
    ether::{EtherClient, EtherData},
    icmp::{IcmpClient, IcmpHeader},
    ip::{IpClient, IpHeader},
    params::Params,
};

#[derive(Debug, Clone)]
pub struct Receiver {
    pub ether_client: EtherClient,
    pub arp_client: ArpClient,
    pub ip_client: IpClient,
    pub icmp_client: IcmpClient,
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
                        if let (
                            IpHeader {
                                ip_p: IPPROTO_ICMP, ..
                            },
                            Some(data),
                        ) = (ip, data)
                        {
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
                    }
                }
                Ok(())
            })
    }
}

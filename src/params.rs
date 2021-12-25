use crate::mac_addr::MacAddr;

use std::net::Ipv4Addr;

#[derive(serde::Deserialize, Debug)]
struct RawParams {
    device: String,
    virtual_mac: String,
    virtual_ip: String,
    virtual_mask: String,
    ip_ttl: u8,
    mtu: i32,
    gateway: String,
}

#[derive(Clone, Debug)]
pub struct Params {
    pub device: String,
    pub my_mac: MacAddr,
    pub my_ip: Ipv4Addr,
    pub virtual_mac: MacAddr,
    pub virtual_ip: Ipv4Addr,
    pub virtual_mask: Ipv4Addr,
    pub ip_ttl: u8,
    pub mtu: i32,
    pub gateway: Ipv4Addr,
}

impl Params {
    pub fn from_str(str: &str) -> anyhow::Result<Params> {
        let config: RawParams = toml::from_str(str)?;

        Ok(Params {
            device: config.device,
            my_mac: MacAddr::ZERO,
            my_ip: Ipv4Addr::from(0),
            virtual_mac: config.virtual_mac.parse()?,
            virtual_ip: config.virtual_ip.parse()?,
            virtual_mask: config.virtual_mask.parse()?,
            ip_ttl: config.ip_ttl,
            mtu: config.mtu,
            gateway: config.gateway.parse()?,
        })
    }

    pub fn is_target_ip_addr(&self, addr: &Ipv4Addr) -> bool {
        addr == &self.virtual_ip
    }

    pub fn has_same_subnet(&self, addr: &Ipv4Addr) -> bool {
        u32::from(*addr) & u32::from(self.virtual_mask)
            == u32::from(self.virtual_ip) & u32::from(self.virtual_mask)
    }

    pub fn print(&self) {
        println!("device = {}", self.device);
        println!("virtual_mac = {}", self.virtual_mac);
        println!("virtual_ip = {}", self.virtual_ip);
        println!("virtual_mask = {}", self.virtual_mask);
        println!("gateway = {}", self.gateway);
        println!("ip_ttl = {}, mtu = {}", self.ip_ttl, self.mtu);
    }
}

use std::{
    collections::HashSet,
    fmt::Debug,
    intrinsics::copy_nonoverlapping,
    mem::{size_of, zeroed},
    net::Ipv4Addr,
    sync::{Arc, Mutex},
};

use anyhow::{bail, Result};

use crate::{
    constants::*,
    ip::{IpClient, IpHeader},
    mac_addr::MacAddr,
    params::Params,
    utils::{check_sum2, hex_dump},
};

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct PseudoIp {
    ip_src: u32,
    ip_dst: u32,
    dummy: u8,
    ip_p: u8,
    ip_len: u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct UdpHeader {
    pub uh_sport: u16,
    pub uh_dport: u16,
    pub uh_ulen: u16,
    pub uh_sum: u16,
}

impl Debug for UdpHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UdpHeader")
            .field("uh_sport", &u16::from_be(self.uh_sport))
            .field("uh_dport", &u16::from_be(self.uh_dport))
            .field("uh_ulen", &u16::from_be(self.uh_ulen))
            .field("uh_sum", &format_args!("{:04x}", u16::from_be(self.uh_sum)))
            .finish()
    }
}

#[derive(Debug, Clone)]
pub struct UdpClient {
    ip_client: IpClient,
    table: Arc<Mutex<HashSet<u16>>>,
}

impl UdpClient {
    pub fn new(ip_client: IpClient) -> Self {
        UdpClient {
            ip_client,
            table: Arc::new(Mutex::new(HashSet::default())),
        }
    }

    pub fn receive(&self, ip: &IpHeader, data: &[u8]) -> Result<UdpHeader> {
        let sum = Self::check_sum(
            &u32::from_be(ip.ip_src).into(),
            &u32::from_be(ip.ip_dst).into(),
            ip.ip_p,
            data,
        );
        if sum != 0 && sum != 0xFFFF {
            bail!(
                "UdpClient(receive): Bad UDP checksum: {:04x}, len: {}",
                sum,
                data.len()
            );
        }
        let udp = unsafe { *(data.as_ptr() as *const UdpHeader) };
        if !self.search_table(u16::from_be(udp.uh_dport)) {
            bail!("other");
        }
        log::debug!("RECV <<< {:#?}", udp);
        Ok(udp)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn send_link(
        &self,
        params: &Params,
        src_mac: &MacAddr,
        dst_mac: &MacAddr,
        src_ip: &Ipv4Addr,
        dst_ip: &Ipv4Addr,
        src_port: u16,
        dst_port: u16,
        no_fragment: bool,
        data: &[u8],
    ) -> Result<()> {
        let mut send_buf = [0u8; 64 * 1024];
        let mut ptr = send_buf.as_mut_ptr();
        let mut udp = unsafe { &mut *(ptr as *mut UdpHeader) };
        udp.uh_sport = src_port.to_be();
        udp.uh_dport = dst_port.to_be();
        udp.uh_ulen = ((size_of::<UdpHeader>() + data.len()) as u16).to_be();
        udp.uh_sum = 0;
        unsafe {
            ptr = ptr.add(size_of::<UdpHeader>());
            copy_nonoverlapping(data.as_ptr(), ptr, data.len());
        }
        let send_len = size_of::<UdpHeader>() + data.len();
        udp.uh_sum = Self::check_sum(src_ip, dst_ip, IPPROTO_UDP, &send_buf[..send_len]);
        self.ip_client.send_link(
            params,
            src_mac,
            dst_mac,
            src_ip,
            dst_ip,
            IPPROTO_UDP,
            no_fragment,
            params.ip_ttl,
            &send_buf[..send_len],
        )?;
        log::debug!("SENT >>> {:#?}", udp);
        log::trace!("{}", hex_dump(data));
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn send(
        &self,
        params: &Params,
        src_ip: &Ipv4Addr,
        dst_ip: &Ipv4Addr,
        src_port: u16,
        dst_port: u16,
        no_fragment: bool,
        data: &[u8],
    ) -> Result<()> {
        let mut send_buf = [0u8; 64 * 1024];
        let mut ptr = send_buf.as_mut_ptr();
        let mut udp = unsafe { &mut *(ptr as *mut UdpHeader) };
        udp.uh_sport = src_port.to_be();
        udp.uh_dport = dst_port.to_be();
        udp.uh_ulen = ((size_of::<UdpHeader>() + data.len()) as u16).to_be();
        udp.uh_sum = 0;
        unsafe {
            ptr = ptr.add(size_of::<UdpHeader>());
            copy_nonoverlapping(data.as_ptr(), ptr, data.len());
        }
        let send_len = size_of::<UdpHeader>() + data.len();
        udp.uh_sum = Self::check_sum(src_ip, dst_ip, IPPROTO_UDP, &send_buf[..send_len]);
        self.ip_client.send(
            params,
            src_ip,
            dst_ip,
            IPPROTO_UDP,
            no_fragment,
            params.ip_ttl,
            &send_buf[..send_len],
        )?;
        log::debug!("SENT >>> {:#?}", udp);
        log::trace!("{}", hex_dump(data));
        Ok(())
    }

    pub fn open(&self, port: u16) -> Result<u16> {
        if port == DHCP_CLIENT_PORT {
            bail!("UdpClient: port {} cannot be used.", port);
        }

        let port = if port == 0 {
            if let Some(port) = self.search_port() {
                port
            } else {
                bail!("UdpClient: no free port");
            }
        } else {
            port
        };

        self.add_to_table(port);
        Ok(port)
    }

    pub fn close(&self, port: u16) {
        if !self.search_table(port) {
            log::warn!("UdpClient: port {} was not used", port);
            return;
        }
        self.remove_from_table(port);
    }

    fn add_to_table(&self, port: u16) {
        let mut table = self.table.lock().unwrap();
        if !table.insert(port) {
            log::warn!("UdpClient: port {} already used.", port);
        }
    }

    fn remove_from_table(&self, port: u16) {
        let mut table = self.table.lock().unwrap();
        if !table.remove(&port) {
            log::warn!("UdpClient: port {} was not used", port);
        }
    }

    fn search_table(&self, port: u16) -> bool {
        let table = self.table.lock().unwrap();
        table.contains(&port)
    }

    pub fn show_table(&self) {
        let table = self.table.lock().unwrap();
        for port in table.iter() {
            println!("UDP: {}", port);
        }
    }

    fn search_port(&self) -> Option<u16> {
        (32768u16..61000).find(|port| self.search_table(*port))
    }

    fn check_sum(src_ip: &Ipv4Addr, dst_ip: &Ipv4Addr, protocol: u8, data: &[u8]) -> u16 {
        let mut pseudo_ip: PseudoIp = unsafe { zeroed() };
        pseudo_ip.ip_src = u32::from_be_bytes(src_ip.octets()).to_be();
        pseudo_ip.ip_dst = u32::from_be_bytes(dst_ip.octets()).to_be();
        pseudo_ip.ip_p = protocol;
        pseudo_ip.ip_len = (data.len() as u16).to_be();

        let sum = check_sum2(
            unsafe {
                std::slice::from_raw_parts(
                    &pseudo_ip as *const _ as *const u8,
                    size_of::<PseudoIp>(),
                )
            },
            data,
        );

        if sum == 0x0000 {
            0xFFFF
        } else {
            sum
        }
    }
}

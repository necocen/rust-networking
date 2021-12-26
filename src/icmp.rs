use std::{fmt::Debug, intrinsics::copy_nonoverlapping, mem::size_of, net::Ipv4Addr};

use anyhow::{bail, Result};

use crate::{
    constants::*,
    ip::{IpClient, IpHeader},
    params::Params,
    utils::check_sum,
};

#[repr(C)]
#[derive(Clone, Copy)]
pub struct IcmpHeader {
    pub icmp_type: u8,
    pub icmp_code: u8,
    pub icmp_cksum: u16,
    pub icmp_id: u16,
    pub icmp_seq: u16,
}

impl Debug for IcmpHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let icmp_type = *ICMP_TYPES
            .get(self.icmp_type as usize)
            .unwrap_or(&"undefined");
        if matches!(self.icmp_type, ICMP_ECHOREPLY | ICMP_ECHO) {
            f.debug_struct("IcmpHeader")
                .field(
                    "icmp_type",
                    &format_args!("{} ({})", self.icmp_type, icmp_type),
                )
                .field("icmp_code", &self.icmp_code)
                .field(
                    "icmp_cksum",
                    &format_args!("0x{:04x}", u16::from_be(self.icmp_cksum)),
                )
                .field("icmp_id", &u16::from_be(self.icmp_id))
                .field("icmp_seq", &u16::from_be(self.icmp_seq))
                .finish()
        } else {
            f.debug_struct("IcmpHeader")
                .field(
                    "icmp_type",
                    &format_args!("{} ({})", self.icmp_type, icmp_type),
                )
                .field("icmp_code", &self.icmp_code)
                .field(
                    "icmp_cksum",
                    &format_args!("0x{:04x}", u16::from_be(self.icmp_cksum)),
                )
                .finish()
        }
    }
}

#[derive(Debug, Clone)]
pub struct IcmpClient {
    ip_client: IpClient,
}

impl IcmpClient {
    pub fn new(ip_client: IpClient) -> IcmpClient {
        IcmpClient { ip_client }
    }

    pub fn send_echo(
        &self,
        params: &Params,
        dst_ip: &Ipv4Addr,
        seq: u16,
        size: usize,
    ) -> Result<()> {
        let mut send_buf = [0u8; 64 * 1024];
        let mut ptr = send_buf.as_mut_ptr();

        let icmp = unsafe { &mut *(ptr as *mut IcmpHeader) };
        icmp.icmp_type = ICMP_ECHO;
        icmp.icmp_code = 0;
        icmp.icmp_id = (std::process::id() as u16).to_be();
        icmp.icmp_seq = seq.to_be();
        icmp.icmp_cksum = 0;
        unsafe {
            ptr = ptr.add(size_of::<IcmpHeader>());
        }

        for i in 0..(size - size_of::<IcmpHeader>()) {
            unsafe {
                *(ptr.add(i)) = (i & 0xFF) as u8;
            }
        }

        icmp.icmp_cksum = check_sum(&send_buf[..size]);

        self.ip_client.send(
            params,
            &params.virtual_ip,
            dst_ip,
            IPPROTO_ICMP,
            false,
            params.ip_ttl,
            &send_buf[..size],
        )?;
        log::info!("SENT >>> {:#?}", icmp);
        // TODO: gettimeofday
        // 単にタイムスタンプを記録すればよい
        Ok(())
    }

    pub fn send_echo_reply(
        &self,
        params: &Params,
        r_ip: &IpHeader,
        r_icmp: &IcmpHeader,
        data: &[u8],
        ip_ttl: u8,
    ) -> Result<()> {
        let mut send_buf = [0u8; 64 * 1024];
        let ptr = send_buf.as_mut_ptr();

        let icmp = unsafe { &mut *(ptr as *mut IcmpHeader) };
        icmp.icmp_type = ICMP_ECHOREPLY;
        icmp.icmp_code = 0;
        icmp.icmp_id = r_icmp.icmp_id;
        icmp.icmp_seq = r_icmp.icmp_seq;
        icmp.icmp_cksum = 0;

        unsafe {
            copy_nonoverlapping(data.as_ptr(), ptr.add(size_of::<IcmpHeader>()), data.len());
        }

        let send_len = size_of::<IcmpHeader>() + data.len();
        icmp.icmp_cksum = check_sum(&send_buf[..send_len]);

        self.ip_client.send(
            params,
            &u32::from_be(r_ip.ip_dst).into(),
            &u32::from_be(r_ip.ip_src).into(),
            IPPROTO_ICMP,
            false,
            ip_ttl,
            &send_buf[..send_len],
        )?;
        log::info!("SENT >>> {:#?}", icmp);
        Ok(())
    }

    pub fn receive(&self, ip: &IpHeader, data: &[u8]) -> Result<IcmpHeader> {
        let icmp = unsafe { *(data.as_ptr() as *const IcmpHeader) };
        let sum = check_sum(data);
        if sum != 0 && sum != 0xFFFF {
            bail!("bad icmp checksum ({:04x}, {:04x})", sum, icmp.icmp_cksum);
        }
        log::info!("RECV <<< {:#?}", icmp);
        if icmp.icmp_type == ICMP_ECHOREPLY {
            self.check_ping(ip, &icmp);
        }
        Ok(icmp)
    }

    fn check_ping(&self, ip: &IpHeader, icmp: &IcmpHeader) {
        if u16::from_be(icmp.icmp_id) == std::process::id() as u16 {
            let seq = u16::from_be(icmp.icmp_seq);
            if seq > 0 && seq <= 4 {
                //Local::now().timestamp_nanos();
                println!(
                    "{} bytes from {}: icmp_seq = {}, ttl = {}",
                    u16::from_be(ip.ip_len),
                    Ipv4Addr::from(u32::from_be(ip.ip_src)),
                    u16::from_be(icmp.icmp_seq),
                    ip.ip_ttl
                );
            }
        }
    }
}

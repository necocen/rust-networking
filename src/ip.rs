use std::{
    collections::{
        hash_map::Entry::{Occupied, Vacant},
        HashMap,
    },
    fmt::Debug,
    intrinsics::copy_nonoverlapping,
    mem::size_of,
    net::Ipv4Addr,
    sync::{Arc, Mutex},
};

use anyhow::{bail, Result};
use chrono::Local;
use rand::Rng;

use crate::{
    arp::ArpClient,
    constants::*,
    context::Context,
    ether::{EtherClient, EtherHeader},
    mac_addr::MacAddr,
    utils::{check_sum2, check_sum_struct},
};

#[derive(Debug, Clone)]
pub struct IpRecvBufferEntry {
    pub timestamp: i64,
    pub id: u16,
    pub data: [u8; 64 * 1024],
    pub len: usize,
}

#[derive(Debug, Clone)]
pub struct IpRecvBuffer(HashMap<u16, IpRecvBufferEntry>);

impl IpRecvBuffer {
    pub fn new() -> IpRecvBuffer {
        IpRecvBuffer(HashMap::new())
    }
    pub fn add(&mut self, id: u16) {
        // 本当は多くなりすぎたら消去するとかすべき
        match self.0.entry(id) {
            Occupied(mut o) => {
                let mut entry = o.get_mut();
                entry.id = id;
                entry.timestamp = Local::now().timestamp();
                entry.len = 0;
            }
            Vacant(v) => {
                v.insert(IpRecvBufferEntry {
                    timestamp: Local::now().timestamp(),
                    id,
                    data: [0; 64 * 1024],
                    len: 0,
                });
            }
        }
    }

    pub fn remove(&mut self, id: &u16) -> Option<[u8; 64 * 1024]> {
        self.0.remove(id).map(|entry| entry.data)
    }

    pub fn search(&mut self, id: &u16) -> Option<&mut IpRecvBufferEntry> {
        self.0.get_mut(id)
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct IpHeader {
    pub ip_v_hl: u8,
    pub ip_tos: u8,
    pub ip_len: u16,
    pub ip_id: u16,
    pub ip_off: u16,
    pub ip_ttl: u8,
    pub ip_p: u8,
    pub ip_sum: u16,
    pub ip_src: u32,
    pub ip_dst: u32,
}

impl IpHeader {
    pub fn ip_v(&self) -> u8 {
        self.ip_v_hl >> 4
    }

    pub fn ip_hl(&self) -> u8 {
        self.ip_v_hl & 0x0F
    }

    pub fn set_ip_v(&mut self, ip_v: u8) {
        self.ip_v_hl = self.ip_v_hl & 0x0F | ip_v << 4;
    }

    pub fn set_ip_hl(&mut self, ip_hl: u8) {
        self.ip_v_hl = self.ip_v_hl & 0xF0 | ip_hl & 0x0F;
    }
}

impl Debug for IpHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let protocol = *IP_PROTOCOLS.get(self.ip_p as usize).unwrap_or(&"undefined");
        f.debug_struct("IpHeader")
            .field("ip_v", &self.ip_v())
            .field("ip_hl", &self.ip_hl())
            .field("ip_tos", &format_args!("0x{:02x}", &self.ip_tos))
            .field("ip_len", &u16::from_be(self.ip_len))
            .field("ip_id", &u16::from_be(self.ip_id))
            .field(
                "ip_off",
                &format_args!(
                    "{:02x}, {}",
                    u16::from_be(self.ip_off) >> 13 & 0x07,
                    u16::from_be(self.ip_off) & IP_OFFMASK
                ),
            )
            .field("ip_ttl", &self.ip_ttl)
            .field("ip_p", &format_args!("{} ({})", self.ip_p, protocol))
            .field(
                "ip_sum",
                &format_args!("0x{:04x}", u16::from_be(self.ip_sum)),
            )
            .field("ip_src", &Ipv4Addr::from(u32::from_be(self.ip_src)))
            .field("ip_dst", &Ipv4Addr::from(u32::from_be(self.ip_dst)))
            .finish()
    }
}

#[derive(Debug, Clone)]
pub struct IpClient {
    context: Arc<Mutex<Context>>,
    ether_client: EtherClient,
    arp_client: ArpClient,
    buffer: Arc<Mutex<IpRecvBuffer>>,
}

impl IpClient {
    pub fn new(
        context: &Arc<Mutex<Context>>,
        ether_client: EtherClient,
        arp_client: ArpClient,
    ) -> IpClient {
        IpClient {
            context: Arc::clone(context),
            ether_client,
            arp_client,
            buffer: Arc::new(Mutex::new(IpRecvBuffer::new())),
        }
    }
    pub fn receive(&self, eh: &EtherHeader, data: &[u8]) -> Result<(IpHeader, Option<Vec<u8>>)> {
        let mut ptr = data.as_ptr();
        if data.len() < size_of::<IpHeader>() {
            bail!("len({}) < sizeof(struct ip)", data.len());
        }
        let ip = unsafe { *(ptr as *const IpHeader) };
        unsafe {
            ptr = ptr.add(size_of::<IpHeader>());
        }

        let option_len = (ip.ip_hl() * 4) as usize - size_of::<IpHeader>();
        let sum = match option_len {
            0 => unsafe { check_sum_struct(&ip) },
            1..=1499 => {
                let options = unsafe { std::slice::from_raw_parts(ptr, option_len) };
                unsafe {
                    ptr = ptr.add(option_len);
                }
                check_sum2(
                    unsafe {
                        std::slice::from_raw_parts(
                            &ip as *const _ as *const u8,
                            size_of::<IpHeader>(),
                        )
                    },
                    options,
                )
            }
            _ => {
                bail!("IP optionLen({}) too big", option_len);
            }
        };

        if sum != 0 && sum != 0xFFFF {
            bail!("bad ip checksum");
        }

        // FIXME: SYNを受信した時点でARPテーブルに登録がないとSYN-ACKが送れない問題へのworkaround
        // 本当はちゃんとARPを投げられるような設計が望ましいが……。
        self.arp_client.add_ip(
            &Ipv4Addr::from(u32::from_be(ip.ip_src)),
            &MacAddr::from(eh.ether_shost),
        );

        let plen = (u16::from_be(ip.ip_len) - (ip.ip_hl() * 4) as u16) as usize;
        let offset = ((u16::from_be(ip.ip_off) & IP_OFFMASK) * 8) as usize; // IP_OFFMASK
        let mut buffer = self.buffer.lock().unwrap();
        buffer.add(u16::from_be(ip.ip_id));
        let entry = buffer.search(&u16::from_be(ip.ip_id)).unwrap();
        entry.data[offset..(offset + plen)]
            .copy_from_slice(unsafe { std::slice::from_raw_parts(ptr, plen) });

        if (u16::from_be(ip.ip_off) & IP_MF) == 0 {
            // データ全部届いた
            entry.len = offset + plen;
            log::debug!("RECV <<< {:#?}", ip);
            let data = buffer.remove(&u16::from_be(ip.ip_id)).unwrap()[..(offset + plen)].to_vec();
            Ok((ip, Some(data)))
        } else {
            log::debug!("RECV(fragment) <<< {:#?}", ip);
            Ok((ip, None))
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn send_link(
        &self,
        src_mac: &MacAddr,
        dst_mac: &MacAddr,
        src_ip: &Ipv4Addr,
        dst_ip: &Ipv4Addr,
        protocol: u8,
        no_fragment: bool,
        ttl: u8,
        data: &[u8],
    ) -> anyhow::Result<()> {
        let context = self.context.lock().unwrap().clone();
        let max_len = context.mtu as usize - size_of::<IpHeader>();

        if no_fragment && data.len() > max_len {
            bail!("ip_send_link: too large data: {}", data.len());
        }

        let mut send_buf = [0u8; ETHERMTU];
        let mut rng = rand::thread_rng();
        let id: u16 = rng.gen();
        let mut rest = data.len();
        let mut data_ptr = data.as_ptr();

        while rest > 0 {
            let fragment = rest > max_len;
            let send_len = if fragment { max_len / 8 * 8 } else { rest };
            let ptr = send_buf.as_mut_ptr();

            let mut ip = unsafe { &mut *(ptr as *mut IpHeader) };
            ip.set_ip_v(4);
            ip.set_ip_hl(5);
            ip.ip_len = ((size_of::<IpHeader>() + send_len) as u16).to_be();
            ip.ip_id = id.to_be();
            let offset = unsafe { data_ptr.offset_from(data.as_ptr()) } as u16 / 8;
            if no_fragment {
                ip.ip_off = IP_DF.to_be();
            } else if fragment {
                ip.ip_off = (IP_MF | (offset & IP_OFFMASK)).to_be();
            } else {
                ip.ip_off = (offset & IP_OFFMASK).to_be();
            }
            ip.ip_ttl = ttl;
            ip.ip_p = protocol;
            ip.ip_src = u32::from_be_bytes(src_ip.octets()).to_be();
            ip.ip_dst = u32::from_be_bytes(dst_ip.octets()).to_be();
            ip.ip_sum = 0;
            ip.ip_sum = unsafe { check_sum_struct(ip) };

            unsafe {
                copy_nonoverlapping(data.as_ptr(), ptr.add(size_of::<IpHeader>()), send_len);
            }

            self.ether_client.send(
                src_mac,
                dst_mac,
                ETH_P_IP,
                &send_buf[..(send_len + size_of::<IpHeader>())],
            )?;
            log::debug!("SENT >>> {:#?}", ip);

            unsafe {
                data_ptr = data_ptr.add(send_len);
                rest -= send_len;
            }
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn send(
        &self,
        src_ip: &Ipv4Addr,
        dst_ip: &Ipv4Addr,
        protocol: u8,
        no_fragment: bool,
        ttl: u8,
        data: &[u8],
    ) -> Result<()> {
        let context = self.context.lock().unwrap().clone();
        if let Some(dst_mac) = self.arp_client.get_target_mac(dst_ip, false) {
            self.send_link(
                &context.virtual_mac,
                &dst_mac,
                src_ip,
                dst_ip,
                protocol,
                no_fragment,
                ttl,
                data,
            )
        } else {
            bail!("ip_send: {} Destination Host Unreachable", dst_ip)
        }
    }
}

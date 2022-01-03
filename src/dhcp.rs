use std::{
    ffi::CStr,
    fmt::{Debug, Write},
    intrinsics::copy_nonoverlapping,
    mem::zeroed,
    net::Ipv4Addr,
    sync::{Arc, Mutex},
};

use anyhow::{bail, Context as C, Result};
use chrono::{Duration, Local};

use crate::{constants::*, context::Context, mac_addr::MacAddr, udp::UdpClient};

#[repr(C)]
#[derive(Clone)]
pub struct DhcpPacket {
    /// Message opcode/type
    pub op: u8,
    /// Hardware addr type
    pub htype: u8,
    /// Hardware addr length
    pub hlen: u8,
    /// Number of relay agent hops from client
    pub hops: u8,
    /// Transaction ID
    pub xid: u32,
    /// Seconds since client started looking
    pub secs: u16,
    /// Flag bits
    pub flags: u16,
    /// Client IP address (if already in use)
    pub ciaddr: u32,
    /// Client IP address
    pub yiaddr: u32,
    /// IP address of next server to talk to
    pub siaddr: u32,
    /// DHCP relay agent IP address
    pub giaddr: u32,
    /// Client hardware address
    pub chaddr: [u8; 16],
    /// Server name
    pub sname: [u8; DHCP_SNAME_LEN],
    /// Boot filename
    pub file: [u8; DHCP_FILE_LEN],
    /// Optional parameters
    pub options: [u8; DHCP_OPTION_LEN],
}

impl DhcpPacket {
    pub fn new_request(
        context: &Context,
        ty: u8,
        ciaddr: Option<&Ipv4Addr>,
        req_ip: Option<&Ipv4Addr>,
        server: Option<&Ipv4Addr>,
    ) -> (Self, usize) {
        let mut packet: DhcpPacket = unsafe { zeroed() };
        packet.op = DHCP_BOOTREQUEST;
        packet.htype = DHCP_HTYPE_ETHER;
        packet.hlen = 6;
        packet.hops = 0;
        packet.xid = (std::process::id() & 0xFFFF).to_be();
        packet.secs = 0;
        packet.flags = 0x8000u16.to_be();
        if let Some(ciaddr) = ciaddr {
            packet.ciaddr = u32::from_be_bytes(ciaddr.octets()).to_be();
        } else {
            packet.ciaddr = 0;
        }
        packet.yiaddr = 0;
        packet.siaddr = 0;
        packet.giaddr = 0;
        unsafe {
            copy_nonoverlapping(
                <[u8; 6]>::from(context.virtual_mac).as_ptr(),
                packet.chaddr.as_mut_ptr(),
                6,
            );
            copy_nonoverlapping(DHCP_COOKIE.as_ptr(), packet.options.as_mut_ptr(), 4);
        }
        let mut offset = 4;
        offset = packet.set_option(offset, 53, &[ty]);
        offset = packet.set_option(offset, 51, &context.dhcp_request_lease_time.to_be_bytes());
        if let Some(req_ip) = req_ip {
            offset = packet.set_option(offset, 50, &req_ip.octets());
        }
        if let Some(server) = server {
            offset = packet.set_option(offset, 50, &server.octets());
        }
        offset = packet.set_option(offset, 55, &[1, 3]);
        offset = packet.set_option(offset, 255, &[]);

        let size = unsafe {
            packet
                .options
                .as_ptr()
                .offset_from(&packet as *const _ as *const u8)
        } as usize
            + offset;
        (packet, size)
    }

    pub fn set_option(&mut self, offset: usize, tag: u8, data: &[u8]) -> usize {
        let size = if data.len() > 255 {
            log::warn!("too long data");
            255
        } else {
            data.len()
        };
        unsafe {
            let mut ptr = self.options.as_mut_ptr().add(offset);
            *ptr = tag;
            if matches!(tag, 0 | 255) {
                return offset + 1;
            }
            ptr = ptr.add(1);
            *ptr = size as u8;
            ptr = ptr.add(1);
            copy_nonoverlapping(data.as_ptr(), ptr, size);
        }
        offset + 2 + size
    }

    pub fn get_option(&self, tag: u8) -> Option<&[u8]> {
        let mut ptr = self.options.as_ptr();
        if self.options[0..4] != DHCP_COOKIE {
            log::warn!("cookie: error");
        }
        unsafe {
            let ptr_end = ptr.add(self.options.len());
            ptr = ptr.add(4); // COOKIE
            while ptr < ptr_end {
                match *ptr {
                    0 => {
                        ptr = ptr.add(1);
                        continue;
                    }
                    255 => {
                        return None;
                    }
                    n if n == tag => {
                        ptr = ptr.add(1);
                        return Some(std::slice::from_raw_parts(ptr.add(1), *ptr as usize));
                    }
                    _ => {
                        ptr = ptr.add(1);
                        ptr = ptr.add(1 + *ptr as usize);
                    }
                }
            }
        }
        None
    }
}

impl Debug for DhcpPacket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let op = match self.op {
            DHCP_BOOTREQUEST => "BOOTREQUEST",
            DHCP_BOOTREPLY => "BOOTREPLY",
            _ => "UNDEFINED",
        };
        let htype = match self.htype {
            DHCP_HTYPE_ETHER => "HTYPE_ETHER",
            DHCP_HTYPE_IEEE802 => "HTYPE_IEEE802",
            DHCP_HTYPE_FDDI => "HTYPE_FDDI",
            _ => "UNDEFINED",
        };
        let chaddr: [u8; 6] = self.chaddr[0..6].try_into().unwrap();
        // FIXME: これ0終端とは限らないはず
        let sname = unsafe { CStr::from_ptr(&self.sname as *const _) };
        let file = unsafe { CStr::from_ptr(&self.file as *const _) };

        if self.options[0..4] != DHCP_COOKIE {
            log::warn!("cookie: error");
        }
        let mut options = String::new();
        writeln!(options).unwrap();
        unsafe fn get_ip(options: &mut String, ptr: &mut *const u8) {
            let n = **ptr;
            write!(options, "{}: ", n).unwrap();
            *ptr = ptr.add(1);
            for i in 0..(n / 4) {
                if i > 0 {
                    write!(options, ", ").unwrap();
                }
                let p = *ptr;
                let addr = Ipv4Addr::from([*p, *p.add(1), *p.add(2), *p.add(3)]);
                *ptr = p.add(4);
                write!(options, "{}", addr).unwrap();
            }
            writeln!(options).unwrap();
        }
        unsafe fn get_u8(options: &mut String, ptr: &mut *const u8) {
            let n = **ptr;
            write!(options, "{}: ", n).unwrap();
            *ptr = ptr.add(1);
            for i in 0..n {
                if i > 0 {
                    write!(options, ", ").unwrap();
                }
                let v = **ptr;
                *ptr = ptr.add(1);
                write!(options, "{}", v).unwrap();
            }
            writeln!(options).unwrap();
        }
        unsafe fn get_hex(options: &mut String, ptr: &mut *const u8) {
            let n = **ptr;
            write!(options, "{}: ", n).unwrap();
            *ptr = ptr.add(1);
            for i in 0..n {
                if i > 0 {
                    write!(options, ":").unwrap();
                }
                let v = **ptr;
                *ptr = ptr.add(1);
                write!(options, "{:02x}", v).unwrap();
            }
            writeln!(options).unwrap();
        }
        unsafe fn get_u16(options: &mut String, ptr: &mut *const u8) {
            let n = **ptr;
            write!(options, "{}: ", n).unwrap();
            *ptr = ptr.add(1);
            for i in 0..(n / 2) {
                if i > 0 {
                    write!(options, ", ").unwrap();
                }
                let p = *ptr;
                let v = u16::from_be_bytes([*p, *p.add(1)]);
                *ptr = p.add(2);
                write!(options, "{}", v).unwrap();
            }
            writeln!(options).unwrap();
        }
        unsafe fn get_u32(options: &mut String, ptr: &mut *const u8) {
            let n = **ptr;
            write!(options, "{}: ", n).unwrap();
            *ptr = ptr.add(1);
            for i in 0..(n / 4) {
                if i > 0 {
                    write!(options, ", ").unwrap();
                }
                let p = *ptr;
                let v = u32::from_be_bytes([*p, *p.add(1), *p.add(2), *p.add(3)]);
                *ptr = p.add(4);
                write!(options, "{}", v).unwrap();
            }
            writeln!(options).unwrap();
        }
        unsafe fn get_str(options: &mut String, ptr: &mut *const u8) {
            let n = **ptr as usize;
            write!(options, "{}: ", n).unwrap();
            *ptr = ptr.add(1);
            let mut buf = [0u8; 257];
            copy_nonoverlapping(*ptr, buf.as_mut_ptr(), n);
            buf[n] = 0;
            let str = CStr::from_ptr(buf.as_ptr());
            *ptr = ptr.add(n);
            writeln!(options, "\"{}\"", str.to_str().unwrap()).unwrap();
        }
        unsafe fn get_message_type(options: &mut String, ptr: &mut *const u8) {
            let n = **ptr as usize;
            write!(options, "{}: ", n).unwrap();
            *ptr = ptr.add(1);
            let ty = **ptr as usize;
            let ty_name = if ty < DHCP_MESSAGE_TYPES.len() {
                DHCP_MESSAGE_TYPES[ty]
            } else {
                "UNDEFINED"
            };
            *ptr = ptr.add(n);
            writeln!(options, "{} ({})", ty, ty_name).unwrap();
        }
        unsafe {
            let mut ptr = self.options.as_ptr();
            let ptr_end = ptr.add(self.options.len());
            ptr = ptr.add(4); // COOKIE
            while ptr < ptr_end {
                let code = *ptr as usize;
                ptr = ptr.add(1);
                write!(&mut options, "{}", code).unwrap();
                if code == 0 {
                    writeln!(&mut options, "(pad)").unwrap();
                    continue;
                } else if code == 255 {
                    writeln!(&mut options, "(end)").unwrap();
                    break;
                }
                let code_name = if code >= 128 {
                    "reserved fields"
                } else if code >= DHCP_CODES.len() {
                    "undefined"
                } else {
                    DHCP_CODES[code]
                };

                write!(&mut options, "({}):", code_name).unwrap();

                match code {
                    0 | 255 => {}
                    1 | 3..=11 | 16 | 21 | 28 | 32 | 33 | 41 | 42 | 44 | 45 | 48 | 49 | 50 | 54 => {
                        get_ip(&mut options, &mut ptr);
                    }
                    12 | 14 | 15 | 17 | 18 | 25 | 40 | 47 | 56 | 60 => {
                        get_str(&mut options, &mut ptr);
                    }
                    2 | 24 | 35 | 38 | 51 | 58 | 59 => {
                        get_u32(&mut options, &mut ptr);
                    }
                    13 | 22 | 26 | 57 => {
                        get_u16(&mut options, &mut ptr);
                    }
                    19 | 20 | 23 | 27 | 29 | 30 | 31 | 34 | 36 | 37 | 39 | 52 | 55 => {
                        get_u8(&mut options, &mut ptr);
                    }
                    53 => {
                        get_message_type(&mut options, &mut ptr);
                    }
                    _ => {
                        get_hex(&mut options, &mut ptr);
                    }
                }
            }
        }
        f.debug_struct("DhcpPacket")
            .field("op", &format_args!("{} ({})", &self.op, op))
            .field("htype", &format_args!("{} ({})", &self.htype, htype))
            .field("hlen", &self.hlen)
            .field("hops", &self.hops)
            .field("xid", &self.xid)
            .field("secs", &self.secs)
            .field("flags", &self.flags)
            .field("ciaddr", &Ipv4Addr::from(u32::from_be(self.ciaddr)))
            .field("yiaddr", &Ipv4Addr::from(u32::from_be(self.yiaddr)))
            .field("siaddr", &Ipv4Addr::from(u32::from_be(self.siaddr)))
            .field("giaddr", &Ipv4Addr::from(u32::from_be(self.giaddr)))
            .field("chaddr", &MacAddr::from(chaddr))
            .field("sname", &sname)
            .field("file", &file)
            .field("options", &format_args!("{}", options))
            .finish()
    }
}

#[repr(C)]
#[derive(Clone)]
pub struct DhcpOption {
    pub kind: u8,
}
// TODO: ↑これはわからん

#[derive(Debug, Clone)]
pub struct DhcpClient {
    context: Arc<Mutex<Context>>,
    udp_client: UdpClient,
}

impl DhcpClient {
    pub fn new(context: &Arc<Mutex<Context>>, udp_client: UdpClient) -> DhcpClient {
        DhcpClient {
            context: Arc::clone(context),
            udp_client,
        }
    }
    pub fn receive(&self, data: &[u8]) -> Result<DhcpPacket> {
        let context = self.context.lock().unwrap().clone();
        let packet = unsafe { &*(data.as_ptr() as *const DhcpPacket) };
        if MacAddr::from(<[u8; 6]>::try_from(&packet.chaddr[..6]).unwrap()) != context.virtual_mac {
            bail!("other");
        }
        if u32::from_be(packet.xid) != (std::process::id() & 0xFFFF) {
            bail!(
                "DhcpClient: xid did not match: {} != {}",
                u32::from_be(packet.xid),
                std::process::id() & 0xFFFF
            );
        }

        log::debug!("RECV <<< {:#?}", packet);

        if packet.op == DHCP_BOOTREPLY {
            if let Some(ty) = packet.get_option(53) {
                match ty[0] {
                    DHCP_OFFER => {
                        let ip = packet
                            .get_option(54)
                            .map(|ip| Ipv4Addr::from([ip[0], ip[1], ip[2], ip[3]]))
                            .context("Dhcp: invalid server ip")?;
                        self.send_request(&Ipv4Addr::from(u32::from_be(packet.yiaddr)), &ip)?;
                    }
                    DHCP_ACK => {
                        let mut context = self.context.lock().unwrap();
                        context.virtual_ip = Ipv4Addr::from(u32::from_be(packet.yiaddr));
                        context.dhcp_server = packet
                            .get_option(54)
                            .map(|ip| Ipv4Addr::from([ip[0], ip[1], ip[2], ip[3]]))
                            .context("Dhcp: invalid dhcp server ip")?;
                        context.virtual_mask = packet
                            .get_option(1)
                            .map(|ip| Ipv4Addr::from([ip[0], ip[1], ip[2], ip[3]]))
                            .context("Dhcp: invalid netmask")?;
                        context.gateway = packet
                            .get_option(3)
                            .map(|ip| Ipv4Addr::from([ip[0], ip[1], ip[2], ip[3]]))
                            .context("Dhcp: invalid gateway")?;
                        context.dhcp_lease_time = Some(
                            packet
                                .get_option(51)
                                .map(|data| {
                                    u32::from_be_bytes([data[0], data[1], data[2], data[3]])
                                })
                                .context("Dhcp: invalid lease time")?,
                        );
                        context.dhcp_start_date = Some(Local::now());
                        log::info!("ip = {}", context.virtual_ip);
                        log::info!("mask = {}", context.virtual_mask);
                        log::info!("gateway = {}", context.gateway);
                        log::info!("DHCP server = {}", context.dhcp_server);
                        log::info!("DHCP start time = {}", context.dhcp_start_date.unwrap(),);
                        log::info!("DHCP lease time = {}", context.dhcp_lease_time.unwrap());
                    }
                    DHCP_NAK => {
                        let mut context = self.context.lock().unwrap();
                        context.virtual_ip = Ipv4Addr::UNSPECIFIED;
                        context.virtual_mask = Ipv4Addr::UNSPECIFIED;
                        context.gateway = Ipv4Addr::UNSPECIFIED;
                        context.dhcp_server = Ipv4Addr::UNSPECIFIED;
                        context.dhcp_start_date = None;
                        context.dhcp_lease_time = None;
                        self.send_discover()?;
                    }
                    _ => {}
                }
            }
        }

        Ok(packet.clone())
    }

    pub fn check(&self) -> Result<()> {
        let context = self.context.lock().unwrap().clone();
        if context.dhcp_start_date.is_none()
            || Local::now() - context.dhcp_start_date.unwrap()
                >= Duration::seconds(context.dhcp_lease_time.unwrap() as i64)
        {
            log::info!("Dhcp: lease timeout");
            let mut context = self.context.lock().unwrap();
            context.virtual_ip = Ipv4Addr::UNSPECIFIED;
            context.virtual_mask = Ipv4Addr::UNSPECIFIED;
            context.gateway = Ipv4Addr::UNSPECIFIED;
            context.dhcp_server = Ipv4Addr::UNSPECIFIED;
            context.dhcp_start_date = None;
            context.dhcp_lease_time = None;
            self.send_discover()?;
        } else if Local::now() - context.dhcp_start_date.unwrap()
            >= Duration::seconds(context.dhcp_lease_time.unwrap() as i64 / 2)
            && self.send_request_uni().is_err()
        {
            let mut context = self.context.lock().unwrap();
            context.virtual_ip = Ipv4Addr::UNSPECIFIED;
            context.virtual_mask = Ipv4Addr::UNSPECIFIED;
            context.gateway = Ipv4Addr::UNSPECIFIED;
            context.dhcp_server = Ipv4Addr::UNSPECIFIED;
            context.dhcp_start_date = None;
            context.dhcp_lease_time = None;
            self.send_discover()?;
        }
        Ok(())
    }

    pub fn send_discover(&self) -> Result<()> {
        let context = self.context.lock().unwrap().clone();
        let (packet, size) = DhcpPacket::new_request(&context, DHCP_DISCOVER, None, None, None);
        self.udp_send_link(&packet, size)?;
        Ok(())
    }

    pub fn send_request(&self, yiaddr: &Ipv4Addr, server: &Ipv4Addr) -> Result<()> {
        let context = self.context.lock().unwrap().clone();
        let (packet, size) =
            DhcpPacket::new_request(&context, DHCP_REQUEST, None, Some(yiaddr), Some(server));
        self.udp_send_link(&packet, size)?;
        Ok(())
    }

    pub fn send_request_uni(&self) -> Result<()> {
        let context = self.context.lock().unwrap().clone();
        let (packet, size) = DhcpPacket::new_request(
            &context,
            DHCP_REQUEST,
            Some(&context.virtual_ip),
            Some(&context.virtual_ip),
            Some(&context.dhcp_server),
        );
        self.udp_send(&context.virtual_ip, &context.dhcp_server, &packet, size)?;
        Ok(())
    }

    pub fn send_release(&self) -> Result<()> {
        let context = self.context.lock().unwrap().clone();
        let (packet, size) = DhcpPacket::new_request(
            &context,
            DHCP_RELEASE,
            Some(&context.virtual_ip),
            None,
            Some(&context.dhcp_server),
        );
        self.udp_send(&context.virtual_ip, &context.dhcp_server, &packet, size)?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn udp_send_link(&self, dhcp: &DhcpPacket, size: usize) -> Result<()> {
        let context = self.context.lock().unwrap().clone();
        let data = unsafe { std::slice::from_raw_parts(dhcp as *const _ as *const u8, size) };
        self.udp_client.send_link(
            &context.virtual_mac,
            &MacAddr::BROADCAST,
            &Ipv4Addr::UNSPECIFIED,
            &Ipv4Addr::BROADCAST,
            DHCP_CLIENT_PORT,
            DHCP_SERVER_PORT,
            true,
            data,
        )?;
        log::debug!("SENT >>> {:#?}", dhcp);
        Ok(())
    }

    fn udp_send(
        &self,
        src_ip: &Ipv4Addr,
        dst_ip: &Ipv4Addr,
        dhcp: &DhcpPacket,
        size: usize,
    ) -> Result<()> {
        let data = unsafe { std::slice::from_raw_parts(dhcp as *const _ as *const u8, size) };
        self.udp_client.send(
            src_ip,
            dst_ip,
            DHCP_CLIENT_PORT,
            DHCP_SERVER_PORT,
            true,
            data,
        )?;
        log::debug!("SENT >>> {:#?}", dhcp);
        Ok(())
    }
}

impl Drop for DhcpClient {
    fn drop(&mut self) {
        if let Err(e) = self.send_release() {
            log::warn!("DhcpClient: {}", e);
        }
    }
}

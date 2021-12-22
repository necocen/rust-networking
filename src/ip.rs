use std::{
    collections::{
        hash_map::Entry::{Occupied, Vacant},
        HashMap,
    },
    net::Ipv4Addr,
};

use chrono::Local;

#[derive(Debug, Clone)]
pub struct IpRecvBufferEntry {
    pub timestamp: i64,
    pub id: u16,
    pub data: [u8; 64 * 1024],
    pub len: usize,
}

#[derive(Debug, Clone)]
pub struct IpRecvBuffer {
    entries: HashMap<u16, IpRecvBufferEntry>,
}

impl IpRecvBuffer {
    pub fn new() -> IpRecvBuffer {
        IpRecvBuffer {
            entries: HashMap::new(),
        }
    }
    pub fn add(&mut self, id: u16) {
        // 本当は多くなりすぎたら消去するとかすべき
        match self.entries.entry(id) {
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

    pub fn remove(&mut self, id: &u16) {
        self.entries.remove(id);
    }

    pub fn search(&mut self, id: &u16) -> Option<&mut IpRecvBufferEntry> {
        self.entries.get_mut(id)
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
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

    pub fn print(&self) {
        let protocols = [
            "undefined",
            "ICMP",
            "IGMP",
            "undefined",
            "IPIP",
            "undefined",
            "TCP",
            "undefined",
            "EGP",
            "undefined",
            "undefined",
            "undefined",
            "PUP",
            "undefined",
            "undefined",
            "undefined",
            "undefined",
            "UDP",
        ];

        println!("ip-----------------");
        print!("ip_v = {}, ip_hl = {}, ", self.ip_v(), self.ip_hl());
        print!(
            "ip_tos = {:02x}, ip_len = {}, ip_id = {}, ",
            self.ip_tos,
            u16::from_be(self.ip_len),
            u16::from_be(self.ip_id)
        );
        print!(
            "ip_off = {:02x}, {}, ",
            u16::from_be(self.ip_off) >> 13 & 0x07,
            u16::from_be(self.ip_off) & 0x1FFF // IP_OFFMASK
        );
        print!("ip_ttl = {}, ip_p = {}", self.ip_ttl, self.ip_p);
        if (self.ip_p as usize) < protocols.len() {
            print!("({}), ", protocols[self.ip_p as usize]);
        } else {
            print!("(undefined), ");
        }
        println!("ip_sum = {:04x}", u16::from_be(self.ip_sum));
        println!("ip_src = {}", Ipv4Addr::from(u32::from_be(self.ip_src)));
        println!("ip_dst = {}", Ipv4Addr::from(u32::from_be(self.ip_dst)));
    }
}

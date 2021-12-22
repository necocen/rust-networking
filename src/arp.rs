use chrono::Local;
use std::{
    collections::{hash_map::Entry, HashMap},
    net::Ipv4Addr,
};

use crate::utils::mac_to_str;

#[repr(C)]
#[repr(packed)]
#[derive(Clone, Copy, Debug)]
pub struct EtherArp {
    pub arp_hrd: u16,
    pub arp_pro: u16,
    pub arp_hln: u8,
    pub arp_pln: u8,
    pub arp_op: u16,
    pub arp_sha: [u8; libc::ETH_ALEN as usize],
    pub arp_spa: [u8; 4],
    pub arp_tha: [u8; libc::ETH_ALEN as usize],
    pub arp_tpa: [u8; 4],
}

impl EtherArp {
    pub fn print(&self) {
        let hrd: [&str; 24] = [
            "FromKA9Q:NET/ROMpseudo.",
            "Ethernet10/100Mbps.",
            "ExperimentalEthernet.",
            "AX.25Level2.",
            "PROnettokenring.",
            "Chaosnet.",
            "IEEE802.2 Ethernet/TR/TB.",
            "ARCnet.",
            "APPLEtalk.",
            "undefined",
            "undefined",
            "undefined",
            "undefined",
            "undefined",
            "undefined",
            "Frame Relay DLCI.",
            "undefined",
            "undefined",
            "undefined",
            "ATM.",
            "undefined",
            "undefined",
            "undefined",
            "MetricomSTRIP(newIANAid).",
        ];
        let op: [&str; 11] = [
            "undefined",
            "ARPrequest.",
            "ARPreply.",
            "RARPrequest.",
            "RARPreply.",
            "undefined",
            "undefined",
            "undefined",
            "InARPrequest.",
            "InARPreply.",
            "(ATM)ARPNAK.",
        ];

        println!("---ether_arp---");
        print!("arp_hrd = {}", &u16::from_be(self.arp_hrd));
        if u16::from_be(self.arp_hrd) < 24 {
            println!("({})", hrd[u16::from_be(self.arp_hrd) as usize]);
        } else {
            println!("(undefined),");
        }
        print!("arp_pro = {}", u16::from_be(self.arp_pro));
        match u16::from_be(self.arp_pro) as i32 {
            libc::ETH_P_PUP => println!("(Xerox POP)"),
            libc::ETH_P_IP => println!("(IP)"),
            libc::ETH_P_ARP => println!("(Address resolution)"),
            libc::ETH_P_RARP => println!("(Reverse ARP)"),
            _ => println!("(unknown)"),
        }
        print!(
            "arp_hln = {}, arp_pln = {}, arp_op = {}",
            self.arp_hln,
            self.arp_pln,
            u16::from_be(self.arp_op)
        );

        if u16::from_be(self.arp_op) < 11 {
            println!("({})", op[u16::from_be(self.arp_op) as usize]);
        } else {
            println!("(undefined)");
        }

        println!("arp_sha = {}", mac_to_str(self.arp_sha));
        println!("arp_spa = {}", ip_to_string(self.arp_spa));
        println!("arp_tha = {}", mac_to_str(self.arp_tha));
        println!("arp_tpa = {}", ip_to_string(self.arp_tpa));
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ArpRecord {
    pub timestamp: i64,
    pub mac: [u8; 6],
    pub ip_addr: Ipv4Addr,
}

#[derive(Debug, Clone, Default)]
pub struct ArpTable {
    table: HashMap<Ipv4Addr, ArpRecord>,
}

impl ArpTable {
    pub fn add(&mut self, ip_addr: Ipv4Addr, mac: [u8; 6]) {
        match self.table.entry(ip_addr) {
            Entry::Occupied(mut o) => {
                if o.get().mac != mac {
                    println!(
                        "ArpAddTable:{}:Receive different mac: ({}):({})",
                        ip_addr,
                        mac_to_str(o.get().mac),
                        mac_to_str(mac)
                    );
                }
                let record = o.get_mut();
                record.mac = mac;
                record.timestamp = Local::now().timestamp();
            }
            Entry::Vacant(v) => {
                v.insert(ArpRecord {
                    timestamp: Local::now().timestamp(),
                    mac,
                    ip_addr,
                });
            }
        }
    }

    pub fn remove(&mut self, ip_addr: &Ipv4Addr) {
        self.table.remove(ip_addr);
    }

    pub fn search(&self, ip_addr: &Ipv4Addr) -> Option<[u8; 6]> {
        self.table.get(ip_addr).map(|record| record.mac)
    }

    pub fn print(&self) {
        for record in self.table.values() {
            println!("({}) at {}", record.ip_addr, mac_to_str(record.mac));
        }
    }
}

fn ip_to_string(ip: [u8; 4]) -> String {
    Ipv4Addr::from(ip).to_string()
}

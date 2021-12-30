use std::{
    collections::{hash_map::Entry, HashMap},
    mem::{size_of, zeroed},
    net::Ipv4Addr,
    sync::{Arc, Mutex},
    thread::sleep,
    time::Duration,
};

use anyhow::Result;
use chrono::Local;
use libc::{ARPHRD_ETHER, ARPOP_REPLY, ARPOP_REQUEST, ETH_ALEN};

use crate::{
    constants::*,
    context::Context,
    ether::{EtherClient, EtherHeader},
    mac_addr::MacAddr,
};
#[repr(C)]
#[repr(packed)]
#[derive(Clone, Copy)]
pub struct ArpHeader {
    pub arp_hrd: u16,
    pub arp_pro: u16,
    pub arp_hln: u8,
    pub arp_pln: u8,
    pub arp_op: u16,
    pub arp_sha: [u8; ETH_ALEN as usize],
    pub arp_spa: [u8; 4],
    pub arp_tha: [u8; ETH_ALEN as usize],
    pub arp_tpa: [u8; 4],
}

impl std::fmt::Debug for ArpHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let hrd = *ARP_HARDWARE
            .get(u16::from_be(self.arp_hrd) as usize)
            .unwrap_or(&"unknown");
        let pro = match u16::from_be(self.arp_pro) {
            ETH_P_PUP => "Xerox PUP",
            ETH_P_IP => "IP",
            ETH_P_ARP => "Address resolution",
            ETH_P_RARP => "Reverse ARP",
            _ => "unknown",
        };
        let op = *ARP_OP
            .get(u16::from_be(self.arp_op) as usize)
            .unwrap_or(&"undefined");
        f.debug_struct("ArpHeader")
            .field(
                "arp_hrd",
                &format_args!("{} ({})", u16::from_be(self.arp_hrd), hrd),
            )
            .field(
                "arp_pro",
                &format_args!("{} ({})", u16::from_be(self.arp_pro), pro),
            )
            .field("arp_hln", &self.arp_hln)
            .field("arp_pln", &self.arp_pln)
            .field(
                "arp_op",
                &format_args!("{} ({})", u16::from_be(self.arp_op), op),
            )
            .field("arp_sha", &MacAddr::from(self.arp_sha))
            .field("arp_spa", &Ipv4Addr::from(self.arp_spa))
            .field("arp_tha", &MacAddr::from(self.arp_tha))
            .field("arp_tpa", &Ipv4Addr::from(self.arp_tpa))
            .finish()
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ArpRecord {
    pub timestamp: i64,
    pub mac: MacAddr,
    pub ip_addr: Ipv4Addr,
}

#[derive(Debug, Clone, Default)]
pub struct ArpTable(HashMap<Ipv4Addr, ArpRecord>);

impl ArpTable {
    pub fn add(&mut self, ip_addr: Ipv4Addr, mac: MacAddr) {
        match self.0.entry(ip_addr) {
            Entry::Occupied(mut o) => {
                if o.get().mac != mac {
                    println!(
                        "ArpAddTable:{}:Receive different mac: ({}):({})",
                        ip_addr,
                        o.get().mac,
                        mac
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
        self.0.remove(ip_addr);
    }

    pub fn search(&self, ip_addr: &Ipv4Addr) -> Option<MacAddr> {
        self.0.get(ip_addr).map(|record| record.mac)
    }

    pub fn print(&self) {
        for record in self.0.values() {
            println!("({}) at {}", record.ip_addr, record.mac);
        }
    }
}

#[derive(Debug, Clone)]
pub struct ArpClient {
    context: Arc<Mutex<Context>>,
    ether_client: EtherClient,
    table: Arc<Mutex<ArpTable>>,
}

impl ArpClient {
    pub fn new(context: &Arc<Mutex<Context>>, ether_client: EtherClient) -> ArpClient {
        ArpClient {
            context: Arc::clone(context),
            ether_client,
            table: Arc::new(Mutex::new(ArpTable::default())),
        }
    }

    pub fn receive(&self, data: &[u8]) -> Result<ArpHeader> {
        let context = self.context.lock().unwrap().clone();
        let arp = unsafe { *(data.as_ptr() as *const ArpHeader) };
        match u16::from_be(arp.arp_op) {
            ARPOP_REQUEST => {
                let addr = Ipv4Addr::from(arp.arp_tpa);
                if context.is_target_ip_addr(&addr) {
                    self.table
                        .lock()
                        .unwrap()
                        .add(Ipv4Addr::from(arp.arp_spa), arp.arp_sha.into());
                }
            }
            ARPOP_REPLY => {
                let addr = Ipv4Addr::from(arp.arp_tpa);
                if addr == Ipv4Addr::from(0) || context.is_target_ip_addr(&addr) {
                    self.table
                        .lock()
                        .unwrap()
                        .add(Ipv4Addr::from(arp.arp_spa), arp.arp_sha.into());
                }
            }
            _ => {}
        }
        log::debug!("RECV <<< {:#?}", arp);
        Ok(arp)
    }

    #[allow(clippy::too_many_arguments)]
    fn send(
        &self,
        op: u16,
        ether_src_mac: &MacAddr,
        ether_dst_mac: &MacAddr,
        src_mac: &MacAddr,
        dst_mac: &MacAddr,
        src_ip: &Ipv4Addr,
        dst_ip: &Ipv4Addr,
    ) -> Result<()> {
        const HEAD_LEN: usize = size_of::<ArpHeader>();
        let mut arp: ArpHeader = unsafe { zeroed() };
        arp.arp_hrd = ARPHRD_ETHER.to_be();
        arp.arp_pro = ETH_P_IP.to_be();
        arp.arp_hln = 6;
        arp.arp_pln = 4;
        arp.arp_op = op.to_be();
        arp.arp_sha = (*src_mac).into();
        arp.arp_tha = (*dst_mac).into();
        arp.arp_spa = src_ip.octets();
        arp.arp_tpa = dst_ip.octets();
        let data = unsafe { std::slice::from_raw_parts(&arp as *const _ as *const u8, HEAD_LEN) };
        self.ether_client
            .send(ether_src_mac, ether_dst_mac, ETH_P_ARP, data)?;
        log::debug!("SENT >>> {:#?}", arp);
        Ok(())
    }

    pub fn send_reply(&self, eh: &EtherHeader, arp: &ArpHeader) -> Result<()> {
        let context = self.context.lock().unwrap().clone();
        self.send(
            ARPOP_REPLY,
            &context.virtual_mac,
            &eh.ether_shost.into(),
            &context.virtual_mac,
            &arp.arp_sha.into(),
            &Ipv4Addr::from(arp.arp_tpa),
            &Ipv4Addr::from(arp.arp_spa),
        )
    }

    pub fn send_request(&self, target_ip: &Ipv4Addr) -> Result<()> {
        let context = self.context.lock().unwrap().clone();
        self.send(
            ARPOP_REQUEST,
            &context.virtual_mac,
            &MacAddr::BROADCAST,
            &context.virtual_mac,
            &MacAddr::ZERO,
            &context.virtual_ip,
            target_ip,
        )
    }

    pub fn send_gratuitous_request(&self, target_ip: &Ipv4Addr) -> Result<()> {
        let context = self.context.lock().unwrap().clone();
        self.send(
            ARPOP_REQUEST,
            &context.virtual_mac,
            &MacAddr::BROADCAST,
            &context.virtual_mac,
            &MacAddr::ZERO,
            &Ipv4Addr::from(0),
            target_ip,
        )
    }

    fn search_mac(&self, ip_addr: &Ipv4Addr) -> Option<MacAddr> {
        self.table
            .lock()
            .ok()
            .and_then(|table| table.search(ip_addr))
    }

    pub fn get_target_mac(&self, target_ip: &Ipv4Addr, gratuitous: bool) -> Option<MacAddr> {
        let context = self.context.lock().unwrap().clone();
        let target_ip = if context.has_same_subnet(target_ip) {
            target_ip
        } else {
            &context.gateway
        };

        for count in 0..3 {
            sleep(Duration::from_millis(100 * count as u64));
            if let Some(mac) = self.search_mac(target_ip) {
                return Some(mac);
            }
            log::info!("Send ARP request for {}", target_ip);
            let result = if gratuitous {
                self.send_gratuitous_request(target_ip)
            } else {
                self.send_request(target_ip)
            };
            if let Err(e) = result {
                eprintln!("{}", e);
            }
        }
        self.search_mac(target_ip)
    }

    pub fn check_ip_unique(&self) -> bool {
        let context = self.context.lock().unwrap().clone();
        if let Some(mac) = self.get_target_mac(&context.virtual_ip, true) {
            eprintln!(
                "IP Address {} is already used by {}",
                context.virtual_ip, mac
            );
            false
        } else {
            true
        }
    }

    pub fn remove_ip(&self, ip: &Ipv4Addr) {
        let mut table = self.table.lock().unwrap();
        table.remove(ip)
    }

    pub fn print_table(&self) {
        let table = self.table.lock().unwrap();
        table.print();
    }
}

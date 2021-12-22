use crate::utils::mac_to_str;
use anyhow::{bail, Context};
use arp::{ArpTable, EtherArp};
use core::slice;
use icmp::IcmpHeader;
use ifstructs::ifreq;
use ip::{IpHeader, IpRecvBuffer};
use libc::{
    __errno_location, bind, c_char, c_void, close, fgets, ioctl, kill, poll, pollfd, read, signal,
    sockaddr_in, sockaddr_ll, socket, write, AF_INET, AF_PACKET, ARPHRD_ETHER, ARPOP_REPLY,
    ARPOP_REQUEST, EINTR, ETH_ALEN, ETH_DATA_LEN, ETH_P_ALL, ETH_P_ARP, ETH_P_IP, ETH_P_PUP,
    ETH_P_RARP, ETH_ZLEN, IFF_BROADCAST, IFF_LOOPBACK, IFF_MULTICAST, IFF_POINTOPOINT, IFF_PROMISC,
    IFF_UP, IPPROTO_ICMP, PF_PACKET, POLLERR, POLLIN, SIGINT, SIGPIPE, SIGQUIT, SIGTERM, SIG_IGN,
    SIOCGIFADDR, SIOCGIFFLAGS, SIOCGIFHWADDR, SIOCGIFMTU, SOCK_DGRAM, SOCK_RAW, STDIN_FILENO,
};
use params::Params;
use rand::Rng;
use std::{
    ffi::CStr,
    intrinsics::{copy_nonoverlapping, write_bytes},
    mem::{size_of, transmute, zeroed},
    net::Ipv4Addr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread::{sleep, spawn},
    time::Duration,
};
use utils::{check_sum, check_sum2, check_sum_struct, hex_dump};

mod arp;
mod icmp;
mod ip;
mod params;
mod utils;

type MacAddr = [u8; 6];

extern "C" {
    pub static stdin: *mut libc::FILE;
}

#[repr(packed)]
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct EtherHeader {
    ether_dhost: [u8; ETH_ALEN as usize],
    ether_shost: [u8; ETH_ALEN as usize],
    ether_type: u16,
}

impl EtherHeader {
    fn print(&self) {
        println!("---ether_header---");
        println!("ether_dhost = {}", mac_to_str(self.ether_dhost));
        println!("ether_shost = {}", mac_to_str(self.ether_shost));

        print!("ether_type = {:02X}", u16::from_be(self.ether_type));
        match u16::from_be(self.ether_type) as i32 {
            ETH_P_PUP => println!("(Xerox PUP)"),
            ETH_P_IP => println!("(IP)"),
            ETH_P_ARP => println!("(Address resolution)"),
            ETH_P_RARP => println!("(Reverse ARP)"),
            _ => println!("(unknown)"),
        }
    }
}

fn ether_send(
    soc: i32,
    smac: MacAddr,
    dmac: MacAddr,
    r#type: u16,
    data: &[u8],
) -> anyhow::Result<()> {
    let len = data.len();
    if len > ETH_DATA_LEN as usize {
        bail!("ether_send:data too long: {}", len);
    }

    let mut sbuf = [0u8; size_of::<EtherHeader>() + ETH_DATA_LEN as usize];
    let mut ptr = sbuf.as_mut_ptr();
    let eh = unsafe { &mut *(ptr as *mut EtherHeader) };

    (*eh) = unsafe { zeroed() };
    (*eh).ether_dhost = dmac;
    (*eh).ether_shost = smac;
    (*eh).ether_type = r#type.to_be();
    unsafe {
        ptr = ptr.add(size_of::<EtherHeader>());

        copy_nonoverlapping(data.as_ptr(), ptr, len);
        ptr = ptr.add(len);

        if ptr.offset_from(sbuf.as_ptr()) < ETH_ZLEN as isize {
            let pad_len = (ETH_ZLEN as isize - ptr.offset_from(sbuf.as_ptr())) as usize;
            write_bytes(ptr, 0, pad_len);
            ptr = ptr.add(pad_len);
        }
        write(
            soc,
            sbuf.as_ptr() as *const c_void,
            ptr.offset_from(sbuf.as_ptr()) as usize,
        );
    }
    (*eh).print();
    Ok(())
}

fn ether_recv(
    soc: i32,
    params: &Params,
    arp_table: &mut ArpTable,
    ip_buffer: &mut IpRecvBuffer,
    data: &[u8],
) -> anyhow::Result<()> {
    static BROADCAST: MacAddr = [0xFF; 6];
    let eh = unsafe { *(data.as_ptr() as *const EtherHeader) };

    if eh.ether_dhost != BROADCAST && eh.ether_dhost != params.virtual_mac {
        bail!("???");
    }

    match u16::from_be(eh.ether_type) as i32 {
        ETH_P_ARP => {
            arp_receive(
                soc,
                params,
                arp_table,
                &eh,
                &data[size_of::<EtherHeader>()..],
            );
        }
        ETH_P_IP => {
            ip_receive(
                soc,
                params,
                arp_table,
                ip_buffer,
                data,
                &eh,
                &data[size_of::<EtherHeader>()..],
            );
        }
        _ => {}
    }
    Ok(())
}

fn get_target_mac(
    soc: i32,
    ip_addr: &Ipv4Addr,
    gratuitous: bool,
    params: &Params,
    table: &ArpTable,
) -> Option<MacAddr> {
    let ip_addr = if params.has_same_subnet(ip_addr) {
        ip_addr
    } else {
        &params.gateway
    };

    for count in 0..3 {
        // RETRY_COUNT
        if let Some(mac) = table.search(ip_addr) {
            return Some(mac);
        }
        sleep(Duration::from_millis(100 * count as u64));
        if gratuitous {
            arp_send_gratuitous_request(soc, ip_addr, params);
        } else {
            arp_send_request(soc, ip_addr, params);
        }
    }

    None
}

#[allow(clippy::too_many_arguments)]
fn arp_send(
    soc: i32,
    op: u16,
    e_smac: MacAddr,
    e_dmac: MacAddr,
    src_mac: MacAddr,
    dest_mac: MacAddr,
    src_ip: &Ipv4Addr,
    dest_ip: &Ipv4Addr,
) {
    let mut arp: EtherArp = unsafe { zeroed() };
    arp.arp_hrd = ARPHRD_ETHER.to_be();
    arp.arp_pro = (ETH_P_IP as u16).to_be();
    arp.arp_hln = 6;
    arp.arp_pln = 4;
    arp.arp_op = op.to_be();
    arp.arp_sha = src_mac;
    arp.arp_tha = dest_mac;
    arp.arp_spa = src_ip.octets();
    arp.arp_tpa = dest_ip.octets();

    println!("=== ARP ===[");
    let data = unsafe {
        std::slice::from_raw_parts(
            &arp as *const _ as *const u8,
            std::mem::size_of::<EtherArp>(),
        )
    };
    let _ = ether_send(soc, e_smac, e_dmac, ETH_P_ARP as u16, data);
    arp.print();
    println!("]");
}

fn arp_send_gratuitous_request(soc: i32, target_ip: &Ipv4Addr, params: &Params) {
    arp_send(
        soc,
        ARPOP_REQUEST,
        params.virtual_mac,
        [0xFF; 6],
        params.virtual_mac,
        [0x00; 6],
        &Ipv4Addr::from(0),
        target_ip,
    );
}

fn arp_send_request(soc: i32, target_ip: &Ipv4Addr, params: &Params) {
    arp_send(
        soc,
        ARPOP_REQUEST,
        params.virtual_mac,
        [0xFF; 6],
        params.virtual_mac,
        [0x00; 6],
        &params.virtual_ip,
        target_ip,
    );
}

fn arp_check_ip_dup(soc: i32, params: &Params, table: &ArpTable) -> bool {
    if let Some(mac) = get_target_mac(soc, &params.virtual_ip, true, params, table) {
        println!(
            "IP Address {} is already used by {}",
            params.virtual_ip,
            mac_to_str(mac)
        );
        false
    } else {
        true
    }
}

fn arp_receive(soc: i32, params: &Params, table: &mut ArpTable, eh: &EtherHeader, data: &[u8]) {
    let arp = unsafe { *(data.as_ptr() as *const EtherArp) };

    match u16::from_be(arp.arp_op) {
        ARPOP_REQUEST => {
            let mut addr = Ipv4Addr::from(arp.arp_tpa);
            if params.is_target_ip_addr(&addr) {
                println!("--- recv --- [");
                eh.print();
                arp.print();
                println!("]");
                addr = Ipv4Addr::from(arp.arp_spa);
                table.add(addr, arp.arp_sha);
                arp_send(
                    soc,
                    ARPOP_REPLY,
                    params.virtual_mac,
                    eh.ether_shost,
                    params.virtual_mac,
                    arp.arp_sha,
                    &Ipv4Addr::from(arp.arp_tpa),
                    &addr,
                );
            }
        }
        ARPOP_REPLY => {
            let mut addr = Ipv4Addr::from(arp.arp_tpa);
            if addr == Ipv4Addr::from(0) || params.is_target_ip_addr(&addr) {
                println!("--- recv --- [");
                eh.print();
                arp.print();
                println!("]");
                addr = Ipv4Addr::from(arp.arp_spa); // 同上
                table.add(addr, arp.arp_sha);
            }
        }
        _ => {}
    }
}

fn ip_receive(
    soc: i32,
    params: &Params,
    arp_table: &ArpTable,
    ip_buffer: &mut IpRecvBuffer,
    raw: &[u8],
    eh: &EtherHeader,
    data: &[u8],
) {
    let mut ptr = data.as_ptr();
    if data.len() < size_of::<IpHeader>() {
        eprintln!("len({}) < sizeof(struct ip)", data.len());
        return;
    }
    let ip = unsafe { *(ptr as *const IpHeader) };
    unsafe {
        ptr = ptr.add(size_of::<IpHeader>());
    }

    let option_len = (ip.ip_hl() * 4) as usize - size_of::<IpHeader>();
    let sum = match option_len {
        0 => unsafe { check_sum_struct(&ip) },
        1..=1499 => {
            let options = unsafe { slice::from_raw_parts(ptr, option_len) };
            unsafe {
                ptr = ptr.add(option_len);
            }
            check_sum2(
                unsafe {
                    slice::from_raw_parts(&ip as *const _ as *const u8, size_of::<IpHeader>())
                },
                options,
            )
        }
        _ => {
            eprintln!("IP optionLen({}) too big", option_len);
            return;
        }
    };

    if sum != 0 && sum != 0xFFFF {
        eprintln!("bad ip checksum");
        return;
    }

    let plen = (u16::from_be(ip.ip_len) - (ip.ip_hl() * 4) as u16) as usize;
    let offset = ((u16::from_be(ip.ip_off) & 0x1FFF) * 8) as usize; // IP_OFFMASK
    ip_buffer.add(u16::from_be(ip.ip_id));
    let entry = ip_buffer.search(&u16::from_be(ip.ip_id)).unwrap();
    entry.data[offset..(offset + plen)]
        .copy_from_slice(unsafe { slice::from_raw_parts(ptr, plen) });

    if (u16::from_be(ip.ip_off) & 0x2000) == 0 {
        // IP_MF
        // データ全部届いた
        entry.len = offset + plen;
        // ICMPならICMPとして受信する
        if ip.ip_p == IPPROTO_ICMP as u8 {
            icmp_receive(
                soc,
                params,
                arp_table,
                raw,
                eh,
                &ip,
                &data[size_of::<IpHeader>()..],
            )
        }
        ip_buffer.remove(&u16::from_be(ip.ip_id));
    }
}

fn ip_send_link(
    soc: i32,
    params: &Params,
    smac: MacAddr,
    dmac: MacAddr,
    saddr: &Ipv4Addr,
    daddr: &Ipv4Addr,
    protocol: u8,
    no_fragment: bool,
    ttl: u8,
    data: &[u8],
) {
    let max_len = params.mtu as usize - size_of::<IpHeader>();

    if no_fragment && data.len() > max_len {
        eprintln!("ip_send_link: too large data: {}", data.len());
        return;
    }

    let mut send_buf = [0u8; 1500]; // ETHERMTU
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
            ip.ip_off = 0x4000u16.to_be(); // IP_DF
        } else if fragment {
            ip.ip_off = (0x2000 | (offset & 0x1FFF)).to_be();
        } else {
            ip.ip_off = (offset & 0x1FFF).to_be();
        }
        ip.ip_ttl = ttl;
        ip.ip_p = protocol;

        ip.ip_src = u32::from_be_bytes(saddr.octets()).to_be();
        ip.ip_dst = u32::from_be_bytes(daddr.octets()).to_be();
        ip.ip_sum = 0;
        ip.ip_sum = unsafe { check_sum_struct(ip) };

        unsafe {
            copy_nonoverlapping(data.as_ptr(), ptr.add(size_of::<IpHeader>()), send_len);
        }

        let _ = ether_send(
            soc,
            smac,
            dmac,
            ETH_P_IP as u16,
            &send_buf[..(send_len + size_of::<IpHeader>())],
        );
        ip.print();

        unsafe {
            data_ptr = data_ptr.add(send_len);
            rest -= send_len;
        }
    }
}

fn ip_send(
    soc: i32,
    params: &Params,
    arp_table: &ArpTable,
    saddr: &Ipv4Addr,
    daddr: &Ipv4Addr,
    protocol: u8,
    no_fragment: bool,
    ttl: u8,
    data: &[u8],
) {
    if let Some(dmac) = get_target_mac(soc, daddr, false, params, arp_table) {
        ip_send_link(
            soc,
            params,
            params.virtual_mac,
            dmac,
            saddr,
            daddr,
            protocol,
            no_fragment,
            ttl,
            data,
        );
    } else {
        eprintln!("ip_send: {} Destination Host Unreachable", daddr);
    }
}

fn icmp_send_echo_reply(
    soc: i32,
    params: &Params,
    arp_table: &ArpTable,
    r_ip: &IpHeader,
    r_icmp: &IcmpHeader,
    data: &[u8],
    ip_ttl: u8,
) {
    let mut send_buf = [0u8; 64 * 1024];
    let ptr = send_buf.as_mut_ptr();

    let icmp = unsafe { &mut *(ptr as *mut IcmpHeader) };
    icmp.icmp_type = 0; // ICMP_ECHOREPLY
    icmp.icmp_code = 0;
    icmp.icmp_id = r_icmp.icmp_id;
    icmp.icmp_seq = r_icmp.icmp_seq;
    icmp.icmp_cksum = 0;

    unsafe {
        copy_nonoverlapping(data.as_ptr(), ptr.add(size_of::<IcmpHeader>()), data.len());
    }

    let send_len = size_of::<IcmpHeader>() + data.len();
    icmp.icmp_cksum = check_sum(&send_buf[..send_len]);

    println!("=== ICMP Reply === [");
    ip_send(
        soc,
        params,
        arp_table,
        &u32::from_be(r_ip.ip_dst).into(),
        &u32::from_be(r_ip.ip_src).into(),
        IPPROTO_ICMP as u8,
        false,
        ip_ttl,
        &send_buf[..send_len],
    );
    icmp.print();
    println!("]");
}

fn icmp_send_echo(
    soc: i32,
    params: &Params,
    arp_table: &ArpTable,
    daddr: &Ipv4Addr,
    seq: u16,
    size: usize,
) {
    let mut send_buf = [0u8; 64 * 1024];
    let mut ptr = send_buf.as_mut_ptr();

    let icmp = unsafe { &mut *(ptr as *mut IcmpHeader) };
    icmp.icmp_type = 8; // ICMP_ECHO
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

    println!("=== ICMP Echo === [");
    ip_send(
        soc,
        params,
        arp_table,
        &params.virtual_ip,
        daddr,
        IPPROTO_ICMP as u8,
        false,
        params.ip_ttl,
        &send_buf[..size],
    );
    icmp.print();
    println!("]");

    // TODO: gettimeofday
    // 単にタイムスタンプを記録すればよい
}

fn icmp_ping_send(soc: i32, params: &Params, arp_table: &ArpTable, daddr: &Ipv4Addr, size: usize) {
    for i in 0..4 {
        // PING_SEND_NO
        icmp_send_echo(soc, params, arp_table, daddr, i + 1, size);
        sleep(Duration::from_secs(1));
    }
}

fn icmp_receive(
    soc: i32,
    params: &Params,
    arp_table: &ArpTable,
    raw: &[u8],
    eh: &EtherHeader,
    ip: &IpHeader,
    data: &[u8],
) {
    let icmp = unsafe { *(data.as_ptr() as *const IcmpHeader) };
    let sum = check_sum(data);
    if sum != 0 && sum != 0xFFFF {
        eprintln!("bad icmp checksum ({:04x}, {:04x})", sum, icmp.icmp_cksum);
        return;
    }

    if params.is_target_ip_addr(&u32::from_be(ip.ip_dst).into()) {
        println!("--- recv ---[");
        eh.print();
        ip.print();
        icmp.print();
        println!("]");
        if icmp.icmp_type == 8 {
            // ICMP_ECHO
            icmp_send_echo_reply(
                soc,
                params,
                arp_table,
                ip,
                &icmp,
                &data[size_of::<IcmpHeader>()..],
                params.ip_ttl,
            );
        } else if icmp.icmp_type == 0 {
            // ICMP_ECHOREPLY
            icmp_ping_check(ip, &icmp);
        }
    }
}

fn icmp_ping_check(ip: &IpHeader, icmp: &IcmpHeader) {
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

fn do_cmd_arp<'a>(
    args: &mut impl Iterator<Item = &'a str>,
    arp_table: &mut ArpTable,
) -> anyhow::Result<()> {
    let arg = args.next().context("do_cmd_arp: no args")?;
    match arg {
        "-a" => {
            arp_table.print();
        }
        "-d" => {
            let arg = args.next().context("do_cmd_arp: -d has no args")?;
            let addr: Ipv4Addr = arg.parse()?;
            arp_table.remove(&addr);
            println!("deleted / not exists");
        }
        _ => {
            eprintln!("do_cmd_arp: unknown arg: {}", arg);
        }
    }

    Ok(())
}

fn do_cmd_ping<'a>(
    args: &mut impl Iterator<Item = &'a str>,
    soc: i32,
    params: &Params,
    arp_table: &ArpTable,
) -> anyhow::Result<()> {
    let arg = args.next().context("do_cmd_ping: no args")?;
    let daddr: Ipv4Addr = arg.parse()?;
    let size: usize = if let Some(arg) = args.next() {
        arg.parse()?
    } else {
        64 // DEFAULT_PING_SIZE
    };
    icmp_ping_send(soc, params, arp_table, &daddr, size);
    Ok(())
}

fn do_cmd(soc: i32, params: &Params, arp_table: &mut ArpTable, cmd: &str) -> anyhow::Result<()> {
    let mut args = cmd.split_ascii_whitespace().peekable();
    if args.peek() == None {
        println!("do_cmd: no cmd");
        println!("----------------------------------------");
        println!("arp -a : show arp table");
        println!("arp -d <addr> : remove <addr> from arp table");
        println!("ping addr <size> : send ping");
        println!("ifconfig : show interface configuration");
        println!("end : end program");
        println!("----------------------------------------");
        return Ok(());
    }

    let cmd = args.next().unwrap();

    match cmd {
        "arp" => do_cmd_arp(&mut args, arp_table),
        "ping" => do_cmd_ping(&mut args, soc, params, arp_table),
        "ifconfig" => {
            params.print();
            Ok(())
        }
        "end" => {
            unsafe { kill(std::process::id() as i32, SIGTERM) };
            Ok(())
        }
        _ => {
            println!("err {}", cmd);
            bail!("do_cmd: unknown cmd : {}", cmd);
        }
    }
}

fn init_socket(device: &str) -> anyhow::Result<i32> {
    const SIOCGIFINDEX: libc::c_ulong = 0x8933; // cf. https://github.com/thombles/ax25-rs/blob/master/src/linux.rs#L108
    let mut if_req: ifreq = unsafe { zeroed() };
    let mut sockaddr: sockaddr_ll = unsafe { zeroed() };
    let soc = unsafe { socket(AF_PACKET, SOCK_RAW, ETH_P_ALL.to_be()) };
    if soc < 0 {
        bail!("socket");
    }

    if_req.set_name(device)?;
    if unsafe { ioctl(soc, SIOCGIFINDEX, &if_req) } < 0 {
        unsafe {
            close(soc);
        }
        bail!("ioctl");
    }

    sockaddr.sll_family = PF_PACKET as u16;
    sockaddr.sll_protocol = (ETH_P_ALL as u16).to_be();
    sockaddr.sll_ifindex = unsafe { if_req.ifr_ifru.ifr_ifindex };
    if unsafe { bind(soc, transmute(&sockaddr), size_of::<sockaddr_ll>() as u32) } < 0 {
        unsafe {
            close(soc);
        }
        bail!("bind");
    }

    if unsafe { ioctl(soc, SIOCGIFFLAGS, &if_req) } < 0 {
        unsafe {
            close(soc);
        }
        bail!("ioctl");
    }

    unsafe { if_req.ifr_ifru.ifr_flags |= (IFF_PROMISC | IFF_UP) as i16 };
    if unsafe { ioctl(soc, SIOCGIFFLAGS, &if_req) } < 0 {
        unsafe {
            close(soc);
        }
        bail!("ioctl");
    }
    Ok(soc)
}

fn show_if_req(params: &mut Params) -> anyhow::Result<()> {
    let soc = unsafe { socket(AF_INET, SOCK_DGRAM, 0) };
    let mut if_req: ifreq = unsafe { zeroed() };
    if soc == -1 {
        bail!("socket");
    }

    if_req.set_name(&params.device)?;
    if unsafe { ioctl(soc, SIOCGIFFLAGS, &if_req) } == -1 {
        unsafe {
            close(soc);
        }
        bail!("ioctl:flags");
    }

    unsafe {
        if if_req.ifr_ifru.ifr_flags & IFF_UP as i16 != 0 {
            print!("UP ");
        }
        if if_req.ifr_ifru.ifr_flags & IFF_BROADCAST as i16 != 0 {
            print!("BROADCAST ");
        }
        if if_req.ifr_ifru.ifr_flags & IFF_PROMISC as i16 != 0 {
            print!("PROMISC ");
        }
        if if_req.ifr_ifru.ifr_flags & IFF_MULTICAST as i16 != 0 {
            print!("MULTICAST ");
        }
        if if_req.ifr_ifru.ifr_flags & IFF_LOOPBACK as i16 != 0 {
            print!("LOOPBACK ");
        }
        if if_req.ifr_ifru.ifr_flags & IFF_POINTOPOINT as i16 != 0 {
            print!("P2P ");
        }
        println!();
    }

    if unsafe { ioctl(soc, SIOCGIFMTU, &if_req) } == -1 {
        eprintln!("ioctl:mtu");
    } else {
        unsafe { println!("mtu = {:}", if_req.ifr_ifru.ifr_mtu) };
    }

    if unsafe { ioctl(soc, SIOCGIFADDR, &if_req) } == -1 {
        eprintln!("ioctl:addr");
    } else if unsafe { if_req.ifr_ifru.ifr_addr.sa_family } != AF_INET as u16 {
        println!("not AF_INET");
    } else {
        let addr: sockaddr_in = unsafe { transmute(if_req.ifr_ifru.ifr_addr) };
        let my_ip = Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr));
        println!("my_ip = {:}", my_ip.to_string());
        params.my_ip = my_ip;
    }

    unsafe {
        close(soc);
    }

    let my_mac = get_mac_address(&params.device)?;
    println!("my_mac = {:}", mac_to_str(my_mac));
    params.my_mac = my_mac;

    Ok(())
}

fn get_mac_address(device: &str) -> anyhow::Result<MacAddr> {
    let mut if_req: ifreq = unsafe { zeroed() };
    let soc = unsafe { socket(AF_INET, SOCK_DGRAM, 0) };
    if soc < 0 {
        bail!("socket");
    }

    if_req.set_name(device)?;
    if unsafe { ioctl(soc, SIOCGIFHWADDR, &if_req) } == -1 {
        unsafe {
            close(soc);
        }
        bail!("ioctl:hwaddr");
    }

    let mut hwaddr = [0; 6];
    hwaddr.copy_from_slice(&unsafe { if_req.ifr_ifru.ifr_hwaddr.sa_data }[..6]);

    unsafe {
        close(soc);
    }
    Ok(hwaddr)
}

fn main() -> anyhow::Result<()> {
    env_logger::init();

    let file = std::fs::read_to_string("./config.toml")?;
    let mut params = params::Params::from_str(&file)?;

    println!("IP-TTL = {}", params.ip_ttl);
    println!("MTU = {}", params.mtu);

    let soc = init_socket(&params.device)?;
    println!("device = {:}", params.device);
    println!("+++++++++++++++++++++++++++++++++++++++++++++");
    show_if_req(&mut params)?;
    println!("+++++++++++++++++++++++++++++++++++++++++++++");
    println!("virtual_mac = {:}", mac_to_str(params.virtual_mac));
    println!("virtual_ip = {:}", params.virtual_ip);
    println!("virtual_mask = {:}", params.virtual_mask);
    println!("gateway = {:}", params.gateway);

    /// スレッド停止フラグ
    static RUNNING: AtomicBool = AtomicBool::new(true);
    extern "C" fn sig_term(sig: libc::c_int) {
        RUNNING.store(false, Ordering::Relaxed);
        eprintln!("SIGNAL: {:}", sig);
    }

    unsafe {
        signal(SIGINT, sig_term as libc::sighandler_t);
        signal(SIGTERM, sig_term as libc::sighandler_t);
        signal(SIGQUIT, sig_term as libc::sighandler_t);
        signal(SIGPIPE, SIG_IGN);
    }

    let arp_table = Arc::new(Mutex::new(ArpTable::default())); // TODO: ほんとにこんなんでいいんだっけ

    let p = params.clone();
    let t = arp_table.clone();
    let cmd_thread_handler = spawn(move || {
        let mut targets: [pollfd; 1] = unsafe { zeroed() };
        let mut buf: [u8; 2048] = unsafe { zeroed() };
        targets[0].fd = STDIN_FILENO;
        targets[0].events = POLLIN | POLLERR;
        while RUNNING.load(Ordering::Relaxed) {
            let ready = unsafe { poll(&mut targets as *mut pollfd, 1, 1000) };
            match ready {
                -1 => {
                    let errno = unsafe { __errno_location().read() };
                    if errno != EINTR {
                        eprintln!("poll");
                    }
                }
                0 => {} // noop
                _ => {
                    if targets[0].revents & (POLLIN | POLLERR) != 0 {
                        unsafe {
                            fgets(&mut buf as *mut c_char, buf.len() as i32, stdin);
                        }
                        let mut arp_table = t.lock().unwrap();
                        let cmd = unsafe { CStr::from_ptr(buf.as_ptr()) }.to_str().unwrap();
                        if let Err(e) = do_cmd(soc, &p, &mut arp_table, cmd) {
                            eprintln!("{:?}", e);
                        }
                    }
                }
            }
        }
    });

    let p = params.clone();
    let t = arp_table.clone();
    let eth_thread_handler = spawn(move || {
        let mut ip_buf = IpRecvBuffer::new();
        let mut targets: [pollfd; 1] = unsafe { zeroed() };
        let mut buf: [u8; 2048] = unsafe { zeroed() };
        targets[0].fd = soc;
        targets[0].events = POLLIN | POLLERR;
        while RUNNING.load(Ordering::Relaxed) {
            let ready = unsafe { poll(&mut targets as *mut pollfd, 1, 1000) };
            match ready {
                -1 => {
                    let errno = unsafe { __errno_location().read() };
                    if errno != EINTR {
                        eprintln!("poll");
                    }
                }
                0 => {} // noop
                _ => {
                    if targets[0].revents & (POLLIN | POLLERR) != 0 {
                        let len =
                            unsafe { read(soc, &mut buf as *mut _ as *mut c_void, buf.len()) };
                        if len <= 0 {
                            eprintln!("read");
                        } else {
                            // TODO: 何かしらハンドルすべき？
                            let mut arp_table = t.lock().unwrap();
                            let _ = ether_recv(
                                soc,
                                &p,
                                &mut arp_table,
                                &mut ip_buf,
                                &buf[..len as usize],
                            );
                        }
                    }
                }
            }
        }
    });

    if !arp_check_ip_dup(soc, &params, &*arp_table.lock().unwrap()) {
        bail!("GArp check fail");
    }

    let _ = eth_thread_handler.join();
    let _ = cmd_thread_handler.join();

    println!("Ending");

    let mut if_req: ifreq = unsafe { zeroed() };
    if_req.set_name(&params.device)?;
    if unsafe { ioctl(soc, SIOCGIFFLAGS, &if_req) } < 0 {
        eprintln!("ioctl");
    }

    unsafe {
        if_req.ifr_ifru.ifr_flags &= !IFF_PROMISC as i16;
    }
    if unsafe { ioctl(soc, SIOCGIFFLAGS, &if_req) } < 0 {
        eprintln!("ioctl");
    }

    unsafe {
        close(soc);
    }

    Ok(())
}

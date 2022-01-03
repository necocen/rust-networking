use std::{
    collections::HashMap,
    fmt::{Debug, Write},
    intrinsics::copy_nonoverlapping,
    mem::{size_of, zeroed},
    net::Ipv4Addr,
    sync::{Arc, Mutex},
    thread::sleep,
    time::Duration,
};

use anyhow::{bail, Context as C, Result};
use chrono::Local;
use rand::{thread_rng, Rng};

use crate::{
    constants::*,
    context::Context,
    ip::{IpClient, IpHeader},
    utils::{check_sum2, hex_dump},
};

#[repr(C)]
#[derive(Clone, Copy)]
pub struct TcpHeader {
    source: u16,
    dest: u16,
    seq: u32,
    ack_seq: u32,
    res1_doff: u8,
    flags: u8,
    window: u16,
    check: u16,
    urg_ptr: u16,
}

impl TcpHeader {
    fn doff(&self) -> u8 {
        self.res1_doff >> 4
    }

    fn fin(&self) -> bool {
        self.flags & (1 << 0) != 0
    }

    fn syn(&self) -> bool {
        self.flags & (1 << 1) != 0
    }
    fn rst(&self) -> bool {
        self.flags & (1 << 2) != 0
    }
    fn psh(&self) -> bool {
        self.flags & (1 << 3) != 0
    }
    fn ack(&self) -> bool {
        self.flags & (1 << 4) != 0
    }
    fn urg(&self) -> bool {
        self.flags & (1 << 5) != 0
    }

    fn set_fin(&mut self, fin: bool) {
        self.flags = self.flags & 0b1111_1110 | (fin as u8);
    }

    fn set_syn(&mut self, syn: bool) {
        self.flags = self.flags & 0b1111_1101 | (syn as u8) << 1;
    }
    fn set_rst(&mut self, rst: bool) {
        self.flags = self.flags & 0b1111_1011 | (rst as u8) << 2;
    }
    fn set_psh(&mut self, psh: bool) {
        self.flags = self.flags & 0b1111_0111 | (psh as u8) << 3;
    }
    fn set_ack(&mut self, ack: bool) {
        self.flags = self.flags & 0b1110_1111 | (ack as u8) << 4;
    }
    fn set_urg(&mut self, urg: bool) {
        self.flags = self.flags & 0b1101_1111 | (urg as u8) << 5;
    }

    fn set_doff(&mut self, doff: u8) {
        self.res1_doff = self.res1_doff & 0x0F | (doff & 0x0F) << 4;
    }
}

impl Debug for TcpHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut flags = String::new();
        write!(&mut flags, "{}", if self.urg() {"U"} else {"."}).unwrap();
        write!(&mut flags, "{}", if self.ack() {"A"} else {"."}).unwrap();
        write!(&mut flags, "{}", if self.psh() {"P"} else {"."}).unwrap();
        write!(&mut flags, "{}", if self.rst() {"R"} else {"."}).unwrap();
        write!(&mut flags, "{}", if self.syn() {"S"} else {"."}).unwrap();
        write!(&mut flags, "{}", if self.fin() {"F"} else {"."}).unwrap();
        f.debug_struct("TcpHeader")
            .field("source", &u16::from_be(self.source))
            .field("dest", &u16::from_be(self.dest))
            .field("seq", &u32::from_be(self.seq))
            .field("ack_seq", &u32::from_be(self.ack_seq))
            .field("doff", &self.doff())
            .field("flags", &format_args!("{}", &flags))
            .field("window", &u16::from_be(self.window))
            .field("check", &format_args!("0x{:04x}", u16::from_be(self.check)))
            .field("urg_ptr", &u16::from_be(self.urg_ptr))
            .finish()
    }
}

#[derive(Debug, Clone, Copy)]
struct TcpConnection {
    my_port: u16,
    dst_port: u16,
    dst_ip: Ipv4Addr,
    snd: TcpConnectionSnd,
    rcv: TcpConnectionRcv,
    status: TcpState,
}

#[derive(Debug, Clone, Copy)]
struct TcpConnectionSnd {
    /// 未確認の送信
    una: u32,
    /// 次の送信
    nxt: u32,
    /// 送信ウィンドウ
    wnd: u32,
    /// 初期送信シーケンス番号
    iss: u32,
}

#[derive(Debug, Clone, Copy)]
struct TcpConnectionRcv {
    /// 次の受信
    nxt: u32,
    /// 受信ウィンドウ
    wnd: u32,
    /// 初期受信シーケンス番号
    irs: u32,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TcpState {
    #[allow(dead_code)]
    Invalid = 0,
    Established,
    SynSent,
    SynRecv,
    FinWait1,
    FinWait2,
    TimeWait,
    Close,
    CloseWait,
    #[allow(dead_code)]
    LastAck,
    Listen,
    Closing,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct PseudoIp {
    ip_src: u32,
    ip_dst: u32,
    dummy: u8,
    ip_p: u8,
    ip_len: u16,
}

#[derive(Debug, Clone)]
pub struct TcpClient {
    context: Arc<Mutex<Context>>,
    table: Arc<Mutex<HashMap<u16, TcpConnection>>>,
    ip_client: IpClient,
}

impl TcpClient {
    pub fn new(context: &Arc<Mutex<Context>>, ip_client: IpClient) -> Self {
        TcpClient {
            context: Arc::clone(context),
            table: Arc::new(Mutex::new(HashMap::default())),
            ip_client,
        }
    }
    pub fn listen(&self, port: u16) -> Result<()> {
        let port = if port == 0 {
            self.search_port()
                .context("TcpClient: could not find free ports")?
        } else {
            port
        };
        self.add_table(port)?;
        let mut table = self.table.lock().unwrap();
        let conn = table.get_mut(&port).unwrap();
        conn.status = TcpState::Listen;
        Ok(())
    }

    pub fn connect(&self, src_port: u16, dst_ip: &Ipv4Addr, dst_port: u16) -> Result<()> {
        let mut conn = self.add_table(src_port)?;
        conn.dst_port = dst_port;
        conn.dst_ip = *dst_ip;
        conn.status = TcpState::SynSent;
        self.table.lock().unwrap().insert(src_port, conn);
        for c in 0..3 {
            self.send_syn(src_port, false)?;

            sleep(Duration::from_millis(100 * (c + 1)));

            let conn = self.get_conn(src_port)?;
            log::info!("TcpClient connect: {:?}", conn.status);
            if conn.status == TcpState::Established {
                log::info!("TcpClient connect success");
                return Ok(());
            }
        }
        self.socket_close(src_port);
        bail!("TcpClient connect retry over");
    }

    pub fn close(&self, src_port: u16) -> Result<()> {
        // Established -> FinWait1 -> TimeWait | Close
        let mut conn = self.get_conn(src_port)?;
        if conn.status == TcpState::Established {
            conn.status = TcpState::FinWait1;
            self.set_conn(conn);
            for c in 0..3 {
                self.send_fin(src_port)?;

                sleep(Duration::from_millis(100 * (c + 1)));

                let conn = self.get_conn(src_port)?;
                log::info!("TcpClient close: {:?}", conn.status);

                if conn.status != TcpState::FinWait1 {
                    break;
                }
                if c == 2 {
                    self.socket_close(src_port);
                    bail!("TcpClient close retry over");
                }
            }

            for c in 0..3 {
                if matches!(
                    self.get_conn(src_port)?.status,
                    TcpState::TimeWait | TcpState::Close
                ) {
                    break;
                }

                sleep(Duration::from_millis(100 * (c + 1)));

                let conn = self.get_conn(src_port)?;
                log::info!("TcpClient close: {:?}", conn.status);

                if c == 2 {
                    self.socket_close(src_port);
                    bail!("TcpClient close retry over");
                }
            }

            let conn = self.get_conn(src_port)?;
            if conn.status != TcpState::Close {
                //  => conn.status == TimeWaitのはず
                let now = Local::now();
                while Local::now() - now < chrono::Duration::seconds(TCP_FIN_TIMEOUT as i64) {
                    let conn = self.get_conn(src_port)?;
                    log::info!("TcpClient close {:?}", conn.status);
                    sleep(Duration::from_secs(1));
                }
                let mut conn = self.get_conn(src_port)?;
                conn.status = TcpState::Close;
                self.set_conn(conn);
            }
        }

        self.socket_close(src_port);
        log::info!("TcpClient close success");
        Ok(())
    }

    pub fn reset(&self, src_port: u16) -> Result<()> {
        if !self.search_table(src_port) {
            bail!("TcpClient reset: specified port {} was not used", src_port);
        }
        self.send_rst(src_port)?;
        self.socket_close(src_port);
        Ok(())
    }

    pub fn send(&self, src_port: u16, data: &[u8]) -> Result<()> {
        let context = self.context.lock().unwrap().clone();

        let mut rest = data.len();
        let mut offset: usize = 0;
        while rest > 0 {
            let conn = self.get_conn(src_port)?;
            let send_len = if rest >= conn.rcv.wnd as usize {
                conn.rcv.wnd as usize
            } else if rest >= context.mss {
                context.mss
            } else {
                rest
            };
            log::info!(
                "TcpClient: send offset: {}, len: {}, rest: {}",
                offset,
                send_len,
                rest
            );

            for c in 0..3 {
                self.send_data(src_port, &data[offset..(offset + send_len)])?;
                sleep(Duration::from_millis(100 * (c + 1)));
                let conn = self.get_conn(src_port)?;
                log::info!(
                    "TcpClient: send: una = {}, next_seq = {}",
                    conn.snd.una - conn.snd.iss,
                    conn.snd.nxt - conn.snd.iss
                );
                if conn.snd.una == conn.snd.nxt {
                    break;
                }
                if c == 2 {
                    bail!("TcpClient: send: retry over");
                }
            }
            offset += send_len;
            rest -= send_len;
        }

        let conn = self.get_conn(src_port)?;
        log::info!(
            "TcpClient: send: una = {}, next_seq = {}, success",
            conn.snd.una - conn.snd.iss,
            conn.snd.nxt - conn.snd.iss
        );

        Ok(())
    }

    pub fn receive(&self, ip: &IpHeader, data: &[u8]) -> Result<TcpHeader> {
        let sum = Self::check_sum(
            &Ipv4Addr::from(u32::from_be(ip.ip_src)),
            &Ipv4Addr::from(u32::from_be(ip.ip_dst)),
            ip.ip_p,
            data,
        );

        if sum != 0 && sum != 0xFFFF {
            bail!("TcpClient: receive: bad tcp checksum: {:04x}", sum);
        }

        let tcp = unsafe { *(data.as_ptr() as *const TcpHeader) };
        log::debug!("RECV <<< {:#?}", tcp);
        let rest = tcp.doff() as usize * 4 - size_of::<TcpHeader>();
        let mut tcp_len = data.len() - size_of::<TcpHeader>();

        if rest > 0 {
            let opt_pad = &data[size_of::<TcpHeader>()..(size_of::<TcpHeader>() + rest)];
            let opt_pad_str = opt_pad
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<Vec<_>>()
                .join(",");
            log::debug!("TcpClient: receive: option, pad: {}", opt_pad_str);
            tcp_len -= rest
        }

        if tcp_len > 0 {
            log::trace!(
                "{}",
                hex_dump(
                    &data[(size_of::<TcpHeader>() + rest.max(0))
                        ..(size_of::<TcpHeader>() + rest.max(0) + tcp_len)]
                )
            );
        }

        if !self.search_table(u16::from_be(tcp.dest)) {
            log::warn!("TcpClient: receive: no target: {}", u16::from_be(tcp.dest));
            self.send_rst_direct(ip, &tcp)?;
            bail!("other");
        }

        let mut conn = self.get_conn(u16::from_be(tcp.dest))?;

        if conn.rcv.nxt != 0 && conn.rcv.nxt != u32::from_be(tcp.seq) {
            log::info!(
                "TcpClient:{}:receive: seq({}) != rcv.nxt({})",
                u16::from_be(tcp.dest),
                u32::from_be(tcp.seq),
                conn.rcv.nxt
            );
        } else {
            match conn.status {
                TcpState::SynSent => {
                    if tcp.rst() {
                        log::info!("TcpClient:{}:SYN_SENT: rst", u16::from_be(tcp.dest));
                        conn.status = TcpState::Close;
                        conn.rcv.nxt = u32::from_be(tcp.seq);
                        conn.snd.una = u32::from_be(tcp.ack_seq);
                        self.set_conn(conn);
                        self.socket_close(u16::from_be(tcp.dest));
                    } else if tcp.syn() {
                        if tcp.ack() {
                            log::info!("TcpClient:{}:SYN_SENT: syn-ack", u16::from_be(tcp.dest));
                            conn.status = TcpState::Established;
                        } else {
                            log::info!("TcpClient:{}:SYN_SENT: syn", u16::from_be(tcp.dest));
                            conn.status = TcpState::SynRecv;
                        }
                        conn.rcv.irs = u32::from_be(tcp.seq);
                        conn.rcv.nxt = u32::from_be(tcp.seq) + 1;
                        conn.snd.una = u32::from_be(tcp.ack_seq);
                        self.set_conn(conn);
                        self.send_ack(u16::from_be(tcp.dest))?;
                    }
                }
                TcpState::SynRecv => {
                    if tcp.rst() {
                        log::info!("TcpClient:{}:SYN_RECV: rst", u16::from_be(tcp.dest));
                        conn.status = TcpState::Close;
                        conn.rcv.nxt = u32::from_be(tcp.seq);
                        conn.snd.una = u32::from_be(tcp.ack_seq);
                        self.set_conn(conn);
                        self.socket_close(tcp.dest);
                    } else if tcp.ack() {
                        log::info!("TcpClient:{}:SYN_RECV: ack", u16::from_be(tcp.dest));
                        conn.status = TcpState::Established;
                        conn.rcv.nxt = u32::from_be(tcp.seq);
                        conn.snd.una = u32::from_be(tcp.ack_seq);
                        self.set_conn(conn);
                    }
                }
                TcpState::Listen => {
                    if tcp.syn() {
                        log::info!("TcpClient:{}:LISTEN: syn", u16::from_be(tcp.dest));
                        conn.status = TcpState::SynRecv;
                        conn.dst_ip = Ipv4Addr::from(u32::from_be(ip.ip_src));
                        conn.dst_port = u16::from_be(tcp.source);
                        conn.rcv.irs = u32::from_be(tcp.seq) + 1;
                        conn.rcv.nxt = u32::from_be(tcp.seq) + 1;
                        self.set_conn(conn);
                        self.send_syn(u16::from_be(tcp.dest), true)?;
                    }
                }
                TcpState::FinWait1 => {
                    if tcp.rst() {
                        log::info!("TcpClient:{}:FIN_WAIT1: rst", u16::from_be(tcp.dest));
                        conn.status = TcpState::Close;
                        conn.rcv.nxt = u32::from_be(tcp.seq);
                        conn.snd.una = u32::from_be(tcp.ack_seq);
                        self.set_conn(conn);
                        self.socket_close(u16::from_be(tcp.dest));
                    } else if tcp.fin() {
                        if tcp.ack() {
                            log::info!("TcpClient:{}:FIN_WAIT1: fin-ack", u16::from_be(tcp.dest));
                            conn.status = TcpState::TimeWait;
                        } else {
                            log::info!("TcpClient:{}:FIN_WAIT1: fin", u16::from_be(tcp.dest));
                            conn.status = TcpState::Closing;
                        }
                        conn.rcv.nxt = u32::from_be(tcp.seq) + tcp_len as u32 + 1;
                        conn.snd.una = u32::from_be(tcp.ack_seq);
                        self.set_conn(conn);
                        self.send_ack(u16::from_be(tcp.dest))?;
                    } else if tcp.ack() {
                        log::info!("TcpClient:{}:FIN_WAIT1: ack", u16::from_be(tcp.dest));
                        conn.status = TcpState::FinWait2;
                        conn.rcv.nxt = u32::from_be(tcp.seq);
                        conn.snd.una = u32::from_be(tcp.ack_seq);
                        self.set_conn(conn);
                    }
                }
                TcpState::FinWait2 => {
                    if tcp.rst() {
                        log::info!("TcpClient:{}:FIN_WAIT2: rst", u16::from_be(tcp.dest));
                        conn.status = TcpState::Close;
                        conn.rcv.nxt = u32::from_be(tcp.seq);
                        conn.snd.una = u32::from_be(tcp.ack_seq);
                        self.set_conn(conn);
                        self.socket_close(u16::from_be(tcp.dest));
                    } else if tcp.fin() {
                        log::info!("TcpClient:{}:FIN_WAIT2: fin", u16::from_be(tcp.dest));
                        conn.status = TcpState::TimeWait;
                        conn.rcv.nxt = u32::from_be(tcp.seq) + tcp_len as u32 + 1;
                        conn.snd.una = u32::from_be(tcp.ack_seq);
                        self.set_conn(conn);
                        self.send_ack(u16::from_be(tcp.dest))?;
                    }
                }
                TcpState::Closing => {
                    if tcp.rst() {
                        log::info!("TcpClient:{}:CLOSING: rst", u16::from_be(tcp.dest));
                        conn.status = TcpState::Close;
                        conn.rcv.nxt = u32::from_be(tcp.seq);
                        conn.snd.una = u32::from_be(tcp.ack_seq);
                        self.set_conn(conn);
                        self.socket_close(u16::from_be(tcp.dest));
                    } else if tcp.ack() {
                        log::info!("TcpClient:{}:CLOSING: ack", u16::from_be(tcp.dest));
                        conn.status = TcpState::TimeWait;
                        conn.rcv.nxt = u32::from_be(tcp.seq);
                        conn.snd.una = u32::from_be(tcp.ack_seq);
                        self.set_conn(conn);
                        self.socket_close(u16::from_be(tcp.dest));
                    }
                }
                TcpState::CloseWait => {
                    if tcp.rst() {
                        log::info!("TcpClient:{}:CLOSE_WAIT: rst", u16::from_be(tcp.dest));
                        conn.status = TcpState::Close;
                        conn.rcv.nxt = u32::from_be(tcp.seq);
                        conn.snd.una = u32::from_be(tcp.ack_seq);
                        self.set_conn(conn);
                        self.socket_close(u16::from_be(tcp.dest));
                    } else if tcp.ack() {
                        log::info!("TcpClient:{}:CLOSE_WAIT: ack", u16::from_be(tcp.dest));
                        conn.status = TcpState::Close;
                        conn.rcv.nxt = u32::from_be(tcp.seq);
                        conn.snd.una = u32::from_be(tcp.ack_seq);
                        self.set_conn(conn);
                        self.socket_close(u16::from_be(tcp.dest));
                    }
                }
                TcpState::Established => {
                    if tcp.rst() {
                        log::info!("TcpClient:{}:ESTABLISHED: rst", u16::from_be(tcp.dest));
                        conn.status = TcpState::Close;
                        conn.rcv.nxt = u32::from_be(tcp.seq);
                        conn.snd.una = u32::from_be(tcp.ack_seq);
                        self.set_conn(conn);
                        self.socket_close(u16::from_be(tcp.dest));
                    } else if tcp.fin() {
                        log::info!("TcpClient:{}:ESTABLISHED: fin", u16::from_be(tcp.dest));
                        conn.status = TcpState::CloseWait;
                        conn.rcv.nxt = u32::from_be(tcp.seq) + tcp_len as u32 + 1;
                        conn.snd.una = u32::from_be(tcp.ack_seq);
                        self.set_conn(conn);
                        self.send_fin(u16::from_be(tcp.dest))?;
                    } else if tcp_len > 0 {
                        conn.rcv.nxt = u32::from_be(tcp.seq) + tcp_len as u32;
                        conn.snd.una = u32::from_be(tcp.ack_seq);
                        self.set_conn(conn);
                        self.send_ack(u16::from_be(tcp.dest))?;
                    } else {
                        conn.rcv.nxt = u32::from_be(tcp.seq);
                        conn.snd.una = u32::from_be(tcp.ack_seq);
                        self.set_conn(conn);
                    }
                }
                _ => {}
            }

            // closeしてる場合はここで取れないので
            if let Ok(mut conn) = self.get_conn(u16::from_be(tcp.dest)) {
                conn.rcv.wnd = u16::from_be(tcp.window) as u32;
                self.set_conn(conn);
            }
        }

        log::info!(
            "TcpClient: receive: {}:{:?}:S[{}, {}, {}, {}]:R[{}, {}, {}]",
            u16::from_be(tcp.dest),
            conn.status,
            conn.snd.una - conn.snd.iss,
            conn.snd.nxt - conn.snd.iss,
            conn.snd.wnd,
            conn.snd.iss,
            conn.rcv.nxt - conn.rcv.irs,
            conn.rcv.wnd,
            conn.rcv.irs
        );

        Ok(tcp)
    }

    pub fn close_all(&self) {
        let ports = self
            .table
            .lock()
            .unwrap()
            .keys()
            .copied()
            .collect::<Vec<_>>();
        for port in ports {
            if let Err(e) = self.close(port) {
                eprintln!("{}", e);
            }
        }
    }

    fn socket_close(&self, port: u16) {
        let mut table = self.table.lock().unwrap();
        if table.remove(&port).is_none() {
            log::warn!("TcpClient: specified port {} was not used", port);
        }
    }

    fn send_syn(&self, port: u16, ack: bool) -> Result<()> {
        let mut conn = self.get_conn(port)?;
        let context = self.context.lock().unwrap().clone();

        let mut send_buf = [0u8; ETHERMTU - size_of::<IpHeader>()];
        let tcp = unsafe { &mut *(send_buf.as_mut_ptr() as *mut TcpHeader) };
        tcp.seq = conn.snd.una.to_be();
        tcp.ack_seq = conn.rcv.nxt.to_be();
        tcp.source = conn.my_port.to_be();
        tcp.dest = conn.dst_port.to_be();
        tcp.set_doff(5);
        tcp.set_urg(false);
        tcp.set_ack(ack);
        tcp.set_psh(false);
        tcp.set_rst(false);
        tcp.set_syn(true);
        tcp.set_fin(false);
        tcp.window = (conn.snd.wnd as u16).to_be();
        tcp.check = 0u16.to_be();
        tcp.urg_ptr = 0u16.to_be();
        tcp.check = Self::check_sum(
            &context.virtual_ip,
            &conn.dst_ip,
            IPPROTO_TCP,
            &send_buf[..size_of::<TcpHeader>()],
        );

        self.ip_client.send(
            &context.virtual_ip,
            &conn.dst_ip,
            IPPROTO_TCP,
            true,
            context.ip_ttl,
            &send_buf[..size_of::<TcpHeader>()],
        )?;
        log::debug!("SENT >>> {:#?}", tcp);

        conn.snd.nxt = conn.snd.una;
        self.set_conn(conn);
        Ok(())
    }

    fn send_fin(&self, port: u16) -> Result<()> {
        let mut conn = self.get_conn(port)?;
        let context = self.context.lock().unwrap().clone();

        let mut send_buf = [0u8; ETHERMTU - size_of::<IpHeader>()];
        let tcp = unsafe { &mut *(send_buf.as_mut_ptr() as *mut TcpHeader) };
        tcp.seq = conn.snd.una.to_be();
        tcp.ack_seq = conn.rcv.nxt.to_be();
        tcp.source = conn.my_port.to_be();
        tcp.dest = conn.dst_port.to_be();
        tcp.set_doff(5);
        tcp.set_urg(false);
        tcp.set_ack(true);
        tcp.set_psh(false);
        tcp.set_rst(false);
        tcp.set_syn(false);
        tcp.set_fin(true);
        tcp.window = (conn.snd.wnd as u16).to_be();
        tcp.check = 0u16.to_be();
        tcp.urg_ptr = 0u16.to_be();
        tcp.check = Self::check_sum(
            &context.virtual_ip,
            &conn.dst_ip,
            IPPROTO_TCP,
            &send_buf[..size_of::<TcpHeader>()],
        );

        self.ip_client.send(
            &context.virtual_ip,
            &conn.dst_ip,
            IPPROTO_TCP,
            true,
            context.ip_ttl,
            &send_buf[..size_of::<TcpHeader>()],
        )?;
        log::debug!("SENT >>> {:#?}", tcp);

        conn.snd.nxt = conn.snd.una;
        self.set_conn(conn);
        Ok(())
    }

    fn send_rst(&self, port: u16) -> Result<()> {
        let mut conn = self.get_conn(port)?;
        let context = self.context.lock().unwrap().clone();

        let mut send_buf = [0u8; ETHERMTU - size_of::<IpHeader>()];
        let tcp = unsafe { &mut *(send_buf.as_mut_ptr() as *mut TcpHeader) };
        tcp.seq = conn.snd.una.to_be();
        tcp.ack_seq = conn.rcv.nxt.to_be();
        tcp.source = conn.my_port.to_be();
        tcp.dest = conn.dst_port.to_be();
        tcp.set_doff(5);
        tcp.set_urg(false);
        tcp.set_ack(true);
        tcp.set_psh(false);
        tcp.set_rst(true);
        tcp.set_syn(false);
        tcp.set_fin(false);
        tcp.window = (conn.snd.wnd as u16).to_be();
        tcp.check = 0u16.to_be();
        tcp.urg_ptr = 0u16.to_be();
        tcp.check = Self::check_sum(
            &context.virtual_ip,
            &conn.dst_ip,
            IPPROTO_TCP,
            &send_buf[..size_of::<TcpHeader>()],
        );

        self.ip_client.send(
            &context.virtual_ip,
            &conn.dst_ip,
            IPPROTO_TCP,
            true,
            context.ip_ttl,
            &send_buf[..size_of::<TcpHeader>()],
        )?;
        log::debug!("SENT >>> {:#?}", tcp);

        conn.snd.nxt = conn.snd.una;
        self.set_conn(conn);
        Ok(())
    }

    fn send_ack(&self, port: u16) -> Result<()> {
        let mut conn = self.get_conn(port)?;
        let context = self.context.lock().unwrap().clone();

        let mut send_buf = [0u8; ETHERMTU - size_of::<IpHeader>()];
        let tcp = unsafe { &mut *(send_buf.as_mut_ptr() as *mut TcpHeader) };
        tcp.seq = conn.snd.una.to_be();
        tcp.ack_seq = conn.rcv.nxt.to_be();
        tcp.source = conn.my_port.to_be();
        tcp.dest = conn.dst_port.to_be();
        tcp.set_doff(5);
        tcp.set_urg(false);
        tcp.set_ack(true);
        tcp.set_psh(false);
        tcp.set_rst(false);
        tcp.set_syn(false);
        tcp.set_fin(false);
        tcp.window = (conn.snd.wnd as u16).to_be();
        tcp.check = 0u16.to_be();
        tcp.urg_ptr = 0u16.to_be();
        tcp.check = Self::check_sum(
            &context.virtual_ip,
            &conn.dst_ip,
            IPPROTO_TCP,
            &send_buf[..size_of::<TcpHeader>()],
        );

        self.ip_client.send(
            &context.virtual_ip,
            &conn.dst_ip,
            IPPROTO_TCP,
            true,
            context.ip_ttl,
            &send_buf[..size_of::<TcpHeader>()],
        )?;
        log::debug!("SENT >>> {:#?}", tcp);

        conn.snd.nxt = conn.snd.una;
        self.set_conn(conn);
        Ok(())
    }

    fn send_rst_direct(&self, r_ip: &IpHeader, r_tcp: &TcpHeader) -> Result<()> {
        let context = self.context.lock().unwrap().clone();
        let mut send_buf = [0u8; ETHERMTU - size_of::<IpHeader>()];
        let tcp = unsafe { &mut *(send_buf.as_mut_ptr() as *mut TcpHeader) };
        tcp.seq = r_tcp.ack_seq;
        tcp.ack_seq = (u32::from_be(r_tcp.seq) + 1).to_be();
        tcp.source = r_tcp.dest;
        tcp.dest = r_tcp.source;
        tcp.set_doff(5);
        tcp.set_urg(false);
        tcp.set_ack(true);
        tcp.set_psh(false);
        tcp.set_rst(true);
        tcp.set_syn(false);
        tcp.set_fin(false);
        tcp.window = 0u16.to_be();
        tcp.check = 0u16.to_be();
        tcp.urg_ptr = 0u16.to_be();
        tcp.check = Self::check_sum(
            &context.virtual_ip,
            &Ipv4Addr::from(u32::from_be(r_ip.ip_src)),
            IPPROTO_TCP,
            &send_buf[..size_of::<TcpHeader>()],
        );

        self.ip_client.send(
            &context.virtual_ip,
            &Ipv4Addr::from(u32::from_be(r_ip.ip_src)),
            IPPROTO_TCP,
            true,
            context.ip_ttl,
            &send_buf[..size_of::<TcpHeader>()],
        )?;
        log::debug!("SENT >>> {:#?}", tcp);

        Ok(())
    }

    fn send_data(&self, src_port: u16, data: &[u8]) -> Result<()> {
        let mut conn = self.get_conn(src_port)?;
        let context = self.context.lock().unwrap().clone();
        if conn.status != TcpState::Established {
            bail!("TcpClient: not established");
        }

        let mut send_buf = [0u8; ETHERMTU - size_of::<IpHeader>()];
        let tcp = unsafe { &mut *(send_buf.as_mut_ptr() as *mut TcpHeader) };
        tcp.seq = conn.snd.una.to_be();
        tcp.ack_seq = conn.rcv.nxt.to_be();
        tcp.source = conn.my_port.to_be();
        tcp.dest = conn.dst_port.to_be();
        tcp.set_doff(5);
        tcp.set_urg(false);
        tcp.set_ack(true);
        tcp.set_psh(false);
        tcp.set_rst(false);
        tcp.set_syn(false);
        tcp.set_fin(false);
        tcp.window = (conn.snd.wnd as u16).to_be();
        tcp.check = 0u16.to_be();
        tcp.urg_ptr = 0u16.to_be();

        unsafe {
            copy_nonoverlapping(
                data.as_ptr(),
                send_buf.as_mut_ptr().add(size_of::<TcpHeader>()),
                data.len(),
            );
        }

        tcp.check = Self::check_sum(
            &context.virtual_ip,
            &conn.dst_ip,
            IPPROTO_TCP,
            &send_buf[..(size_of::<TcpHeader>() + data.len())],
        );

        self.ip_client.send(
            &context.virtual_ip,
            &conn.dst_ip,
            IPPROTO_TCP,
            true,
            context.ip_ttl,
            &send_buf[..(size_of::<TcpHeader>() + data.len())],
        )?;
        log::debug!("SENT >>> {:#?}", tcp);
        log::trace!("{}", hex_dump(data));

        conn.snd.nxt = conn.snd.una + data.len() as u32;
        self.set_conn(conn);
        Ok(())
    }

    fn add_table(&self, port: u16) -> Result<TcpConnection> {
        let mut table = self.table.lock().unwrap();
        if table.contains_key(&port) {
            bail!("TcpClient: port {} already used", port);
        }

        let mut rng = thread_rng();
        let id: u32 = rng.gen();
        let mut conn: TcpConnection = unsafe { zeroed() };
        conn.my_port = port;
        conn.snd.iss = id;
        conn.snd.una = id;
        conn.snd.nxt = id;
        conn.snd.wnd = TCP_INIT_WINDOW;
        conn.status = TcpState::Close;
        table.insert(port, conn);
        Ok(conn)
    }

    fn search_table(&self, port: u16) -> bool {
        self.table.lock().unwrap().contains_key(&port)
    }

    fn get_conn(&self, port: u16) -> Result<TcpConnection> {
        Ok(*self
            .table
            .lock()
            .unwrap()
            .get(&port)
            .context("TcpClient: specified port was not open")?)
    }

    fn set_conn(&self, conn: TcpConnection) {
        self.table.lock().unwrap().insert(conn.my_port, conn);
    }

    pub fn show_table(&self) {
        let table = self.table.lock().unwrap();
        for (_, conn) in table.iter() {
            if conn.status == TcpState::Established {
                println!(
                    "TCP: {}={}:{}-{}:{}:{:?}",
                    conn.my_port,
                    &self.context.lock().unwrap().virtual_ip,
                    conn.my_port,
                    conn.dst_ip,
                    conn.dst_port,
                    conn.status,
                );
            } else {
                println!(
                    "TCP: {}={}:{}:{:?}",
                    conn.my_port,
                    &self.context.lock().unwrap().virtual_ip,
                    conn.my_port,
                    conn.status,
                );
            }
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
        pseudo_ip.dummy = 0;
        pseudo_ip.ip_len = (data.len() as u16).to_be();

        check_sum2(
            unsafe {
                std::slice::from_raw_parts(
                    &pseudo_ip as *const _ as *const u8,
                    size_of::<PseudoIp>(),
                )
            },
            data,
        )
    }
}

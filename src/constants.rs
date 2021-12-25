pub const IFF_UP: i16 = libc::IFF_UP as i16;
pub const IFF_BROADCAST: i16 = libc::IFF_BROADCAST as i16;
pub const IFF_PROMISC: i16 = libc::IFF_PROMISC as i16;
pub const IFF_MULTICAST: i16 = libc::IFF_MULTICAST as i16;
pub const IFF_LOOPBACK: i16 = libc::IFF_LOOPBACK as i16;
pub const IFF_POINTOPOINT: i16 = libc::IFF_POINTOPOINT as i16;

pub const SIOCGIFINDEX: libc::c_ulong = 0x8933;

pub const ETH_P_IP: u16 = libc::ETH_P_IP as u16;
pub const ETH_P_ARP: u16 = libc::ETH_P_ARP as u16;
pub const ETH_P_PUP: u16 = libc::ETH_P_PUP as u16;
pub const ETH_P_RARP: u16 = libc::ETH_P_RARP as u16;

pub const ETHERMTU: usize = 1500;
pub const ETH_ZLEN: usize = libc::ETH_ZLEN as usize;
pub const ETH_DATA_LEN: usize = libc::ETH_DATA_LEN as usize;
pub const ETH_ALEN: usize = libc::ETH_ALEN as usize;

pub const IPPROTO_ICMP: u8 = libc::IPPROTO_ICMP as u8;

pub const IP_OFFMASK: u16 = 0x1FFF;
pub const IP_DF: u16 = 0x4000;
pub const IP_MF: u16 = 0x2000;

pub const ICMP_ECHOREPLY: u8 = 0;
pub const ICMP_ECHO: u8 = 8;

pub const ARP_HARDWARE: [&str; 24] = [
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
pub const ARP_OP: [&str; 11] = [
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

pub const IP_PROTOCOLS: [&str; 18] = [
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

pub const ICMP_TYPES: [&str; 19] = [
    "Echo Reply",
    "undefined",
    "undefined",
    "Destination Unreachable",
    "Source Quench",
    "Redirect",
    "undefined",
    "undefined",
    "Echo Request",
    "Router Advertisement",
    "RouterSelection",
    "Time Exceeded for Datagram",
    "Parameter Problem on Datagram",
    "Timestamp Request",
    "Timestamp Reply",
    "Information Request",
    "Information Reply",
    "Address Mask Request",
    "Address Mask Reply",
];
pub const DEFAULT_PING_SIZE: usize = 64;

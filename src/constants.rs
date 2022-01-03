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
pub const IPPROTO_UDP: u8 = libc::IPPROTO_UDP as u8;
pub const IPPROTO_TCP: u8 = libc::IPPROTO_TCP as u8;

pub const IP_OFFMASK: u16 = 0x1FFF;
pub const IP_DF: u16 = 0x4000;
pub const IP_MF: u16 = 0x2000;

pub const ICMP_ECHOREPLY: u8 = 0;
pub const ICMP_ECHO: u8 = 8;
pub const ICMP_DEST_UNREACH: u8 = 3;
pub const ICMP_PORT_UNREACH: u8 = 3;

pub const DHCP_SERVER_PORT: u16 = 67;
pub const DHCP_CLIENT_PORT: u16 = 68;
pub const DHCP_SNAME_LEN: usize = 64;
pub const DHCP_FILE_LEN: usize = 128;
pub const DHCP_FIXED_NON_UDP: usize = 236;
pub const DHCP_UDP_OVERHEAD: usize = 14 /* Ethernet */ + 20 /* IP */ + 8 /* UDP */;
pub const DHCP_FIXED_LEN: usize = DHCP_FIXED_NON_UDP + DHCP_UDP_OVERHEAD;
pub const DHCP_MTU_MAX: usize = 1500;
pub const DHCP_OPTION_LEN: usize = DHCP_MTU_MAX - DHCP_FIXED_LEN;
pub const DHCP_BOOTREQUEST: u8 = 1;
pub const DHCP_BOOTREPLY: u8 = 2;
/// Ethernet 10Mbps
pub const DHCP_HTYPE_ETHER: u8 = 1;
/// IEEE 802.2 Token Ring...
pub const DHCP_HTYPE_IEEE802: u8 = 6;
/// FDDI...
pub const DHCP_HTYPE_FDDI: u8 = 8;
pub const DHCP_DISCOVER: u8 = 1;
pub const DHCP_OFFER: u8 = 2;
pub const DHCP_REQUEST: u8 = 3;
// pub const DHCP_DECLINE: u8 = 4;
pub const DHCP_ACK: u8 = 5;
pub const DHCP_NAK: u8 = 6;
pub const DHCP_RELEASE: u8 = 7;
// pub const DHCP_INFORM: u8 = 8;

pub const TCP_INIT_WINDOW: u32 = 1460;
pub const TCP_FIN_TIMEOUT: u8 = 3;

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

pub const DHCP_COOKIE: [u8; 4] = [0x63, 0x82, 0x53, 0x63];

pub const DHCP_CODES: [&str; 62] = [
    "pad",
    "subnet mask",
    "time offset",
    "router(gateway)",
    "time server",
    "IEN-116 name server",
    "domain name server",
    "log name server",
    "cookie/quote name server",
    "ipr name server",
    "impress name server",
    "rlp name server",
    "hostname",
    "boot file size",
    "merit dump file",
    "domain name",
    "swap server",
    "root path",
    "extensions path",
    "ip forwarding",
    "non-local source routing",
    "policy filter",
    "maximum datagram reassembly size",
    "default ip time-to-live",
    "path MTU aging timeout",
    "path MTU plateau table",
    "interface MTU",
    "all subnets are local",
    "broadcast address",
    "perform mask discovery",
    "mask supplier",
    "perform router discovery",
    "router solicitation address",
    "static route",
    "trailer encapsulation",
    "ARP cache timeout",
    "ethernet encapsulation",
    "TCP default TTL",
    "TCP keepalive interval",
    "TCP keepalive garbage",
    "network information service domain",
    "network information servers",
    "network time protocol servers",
    "vendor specific information",
    "NetBIOS over TCP/IP name server",
    "NetBIOS over TCP/IP datagram distribution server",
    "NetBIOS over ICP/IP node type",
    "NetBIOS over TCP/IP scope",
    "X Window system font server",
    "X Window system display manager",
    "requested IP address",
    "IP address lease time",
    "option overload",
    "DHCP message type",
    "server identifier",
    "parameter request list",
    "message",
    "maximum DHCP message size",
    "renewal (T1) time value",
    "rebinding (T1) time value",
    "class-identifier",
    "client-identifier",
];

pub const DHCP_MESSAGE_TYPES: [&str; 9] = [
    "undefined",
    "DHCPDISCOVER",
    "DHCPOFFER",
    "DHCPREQUEST",
    "DHCPDECLINE",
    "DHCPACK",
    "DHCPNAK",
    "DHCPRELEASE",
    "DHCPINFORM",
];
pub const DEFAULT_PING_SIZE: usize = 64;

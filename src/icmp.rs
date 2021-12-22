#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct IcmpHeader {
    pub icmp_type: u8,
    pub icmp_code: u8,
    pub icmp_cksum: u16,
    pub icmp_id: u16,
    pub icmp_seq: u16,
}

impl IcmpHeader {
    pub fn print(&self) {
        let icmp_types = [
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

        println!("icmp------------------------------");

        print!("icmp_type = {}", self.icmp_type);
        if self.icmp_type < 19 {
            print!("({}), ", icmp_types[self.icmp_type as usize]);
        } else {
            print!("(undefined), ");
        }
        println!(
            "icmp_code = {}, icmp_cksum = {}",
            self.icmp_code,
            u16::from_be(self.icmp_cksum)
        );

        if self.icmp_type == 0 || self.icmp_type == 8 {
            println!(
                "icmp_id = {}, icmp_seq = {}",
                u16::from_be(self.icmp_id),
                u16::from_be(self.icmp_seq)
            );
        }

        println!("icmp------------------------------");
    }
}

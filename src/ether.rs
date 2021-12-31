use crate::{constants::*, context::Context, mac_addr::MacAddr, socket::Socket};
use anyhow::{bail, Result};
use std::{
    fmt::Debug,
    intrinsics::{copy_nonoverlapping, write_bytes},
    mem::{size_of, zeroed},
    sync::{Arc, Mutex},
};

#[repr(packed)]
#[repr(C)]
#[derive(Clone, Copy)]
pub struct EtherHeader {
    pub ether_dhost: [u8; ETH_ALEN],
    pub ether_shost: [u8; ETH_ALEN],
    pub ether_type: u16,
}

impl Debug for EtherHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let typ = match u16::from_be(self.ether_type) {
            ETH_P_PUP => "Xerox PUP",
            ETH_P_IP => "IP",
            ETH_P_ARP => "Address resolution",
            ETH_P_RARP => "Reverse ARP",
            _ => "unknown",
        };
        f.debug_struct("EtherHeader")
            .field("ether_dhost", &MacAddr::from(self.ether_dhost))
            .field("ether_shost", &MacAddr::from(self.ether_shost))
            .field(
                "ether_type",
                &format_args!("{:02X} ({})", u16::from_be(self.ether_type), typ),
            )
            .finish()
    }
}

#[derive(Debug, Clone)]
pub struct EtherClient {
    context: Arc<Mutex<Context>>,
    socket: Socket,
}

impl EtherClient {
    pub fn new(context: &Arc<Mutex<Context>>, socket: Socket) -> EtherClient {
        EtherClient {
            context: Arc::clone(context),
            socket,
        }
    }
    pub fn receive<'a>(&self, data: &'a [u8]) -> Result<(EtherHeader, &'a [u8])> {
        let context = self.context.lock().unwrap().clone();
        let eh = unsafe { *(data.as_ptr() as *const EtherHeader) };
        let destination = MacAddr::from(eh.ether_dhost);
        if destination != MacAddr::BROADCAST && destination != context.virtual_mac {
            bail!("other");
        }
        log::debug!("RECV <<< {:#?}", eh);
        Ok((eh, &data[size_of::<EtherHeader>()..]))
    }

    pub fn send(
        &self,
        src_mac: &MacAddr,
        dst_mac: &MacAddr,
        r#type: u16,
        data: &[u8],
    ) -> Result<()> {
        let data_len = data.len();
        if data_len > ETH_DATA_LEN {
            bail!("ether_send:data too long: {}", data_len);
        }
        const HEAD_LEN: usize = size_of::<EtherHeader>();
        let mut sbuf = [0u8; HEAD_LEN + ETH_DATA_LEN];
        let mut ptr = sbuf.as_mut_ptr();
        let eh = unsafe { &mut *(ptr as *mut EtherHeader) };

        (*eh) = unsafe { zeroed() };
        (*eh).ether_dhost = (*dst_mac).into();
        (*eh).ether_shost = (*src_mac).into();
        (*eh).ether_type = r#type.to_be();
        unsafe {
            ptr = ptr.add(HEAD_LEN);
            copy_nonoverlapping(data.as_ptr(), ptr, data_len);
            ptr = ptr.add(data_len);

            if HEAD_LEN + data_len < ETH_ZLEN as usize {
                let pad_len = ETH_ZLEN as usize - (HEAD_LEN + data_len);
                write_bytes(ptr, 0, pad_len);
            }
        }
        let send_len = (HEAD_LEN + data_len).max(ETH_ZLEN);
        self.socket.write(&sbuf[..send_len]);
        log::debug!("SENT >>> {:#?}", eh);
        Ok(())
    }
}

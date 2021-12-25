use anyhow::Result;
use core::fmt;
use std::{
    fmt::{Debug, Display},
    str::FromStr,
};

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct MacAddr([u8; 6]);

impl MacAddr {
    pub const BROADCAST: MacAddr = MacAddr([0xFF; 6]);
    pub const ZERO: MacAddr = MacAddr([0; 6]);
}

impl From<[u8; 6]> for MacAddr {
    fn from(value: [u8; 6]) -> Self {
        MacAddr(value)
    }
}

impl From<MacAddr> for [u8; 6] {
    fn from(value: MacAddr) -> Self {
        value.0
    }
}

impl FromStr for MacAddr {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        Ok(MacAddr(
            s.split(':')
                .map(|digit| u8::from_str_radix(digit, 16))
                .collect::<Result<Vec<_>, _>>()?
                .as_slice()
                .try_into()?,
        ))
    }
}

impl Display for MacAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }
}

impl Debug for MacAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_str_to_mac() -> anyhow::Result<()> {
        assert_eq!(
            MacAddr::from_str("12:34:56:78:9A:BC")?,
            MacAddr([18, 52, 86, 120, 154, 188])
        );
        Ok(())
    }

    #[test]
    fn test_mac_to_str() {
        assert_eq!(
            MacAddr([18, 52, 86, 120, 154, 188]).to_string(),
            "12:34:56:78:9a:bc"
        );
    }
}

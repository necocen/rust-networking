use std::fmt::Write;

pub fn hex_dump(data: &[u8]) -> String {
    let mut i = 0usize;
    let mut string = String::new();
    writeln!(&mut string, "DUMP {} BYTES:", data.len()).unwrap();
    while i < data.len() {
        for j in 0..16usize {
            if j != 0 {
                write!(&mut string, " ").unwrap();
            }
            if i + j < data.len() {
                write!(&mut string, "{:02x}", data[i + j]).unwrap();
            } else {
                write!(&mut string, "  ").unwrap();
            }
        }
        write!(&mut string, "    ").unwrap();
        for _ in 0..16 {
            if i < data.len() {
                let c = data[i] as char;
                if c.is_ascii() && !c.is_control() {
                    write!(&mut string, "{:}", c).unwrap();
                } else {
                    write!(&mut string, ".").unwrap();
                }
                i += 1;
            } else {
                write!(&mut string, " ").unwrap();
            }
        }
        writeln!(&mut string).unwrap();
    }
    string
}

pub fn unescape(str: &str) -> String {
    let mut previous: Option<char> = None;
    let mut chars: Vec<char> = vec![];
    for char in str.chars() {
        if previous != Some('\\') {
            if char != '\\' {
                chars.push(char);
            }
            previous = Some(char);
            continue;
        }
        match char {
            'n' => chars.push('\n'),
            'r' => chars.push('\r'),
            't' => chars.push('\t'),
            '\\' => chars.push('\\'),
            _ => {
                log::warn!("Unknown escape sequence: \\{}", char);
                chars.push('\\');
                chars.push(char);
            }
        }
        previous = None;
    }
    if previous == Some('\\') {
        chars.push('\\');
    }
    chars.into_iter().collect::<String>()
}

pub fn check_sum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut ptr = data.as_ptr() as *const u16;

    let mut c = data.len();
    while c > 1 {
        sum += unsafe { *ptr as u32 };
        if sum & 0x80000000 != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        unsafe {
            ptr = ptr.add(1);
        }
        c -= 2;
    }

    if c == 1 {
        sum += unsafe { *ptr as u32 };
    }

    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !sum as u16
}

pub unsafe fn check_sum_struct<T>(s: &T) -> u16 {
    check_sum(std::slice::from_raw_parts(
        s as *const _ as *const u8,
        std::mem::size_of::<T>(),
    ))
}

pub fn check_sum2(data1: &[u8], data2: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut ptr = data1.as_ptr() as *const u16;

    let mut c = data1.len();
    while c > 1 {
        sum += unsafe { *ptr as u32 };
        if sum & 0x80000000 != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        unsafe {
            ptr = ptr.add(1);
        }
        c -= 2;
    }

    if c == 1 {
        sum += unsafe { ((*ptr as u32) << 8) + *data2.as_ptr() as u32 };
        if sum & 0x80000000 != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        ptr = unsafe { (data2.as_ptr() as *const u16).add(1) };
        c = data2.len() - 1;
    } else {
        ptr = data2.as_ptr() as *const u16;
        c = data2.len();
    }

    while c > 1 {
        sum += unsafe { *ptr as u32 };
        if sum & 0x80000000 != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        unsafe {
            ptr = ptr.add(1);
        }
        c -= 2;
    }

    if c == 1 {
        sum += unsafe { *ptr as u32 };
    }

    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !sum as u16
}

#[cfg(test)]
mod tests {

    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_unescape() {
        assert_eq!(unescape("ABCDE"), "ABCDE");
        assert_eq!(unescape("日本語"), "日本語");
        assert_eq!(unescape("escape\\nescape"), "escape\nescape");
        assert_eq!(unescape("escape\\rescape"), "escape\rescape");
        assert_eq!(unescape("escape\\tescape"), "escape\tescape");
        assert_eq!(unescape("escape\\\\escape"), "escape\\escape");
        assert_eq!(unescape("escape\\\\nescape"), "escape\\nescape");
        assert_eq!(unescape("escape\\"), "escape\\");
    }
}

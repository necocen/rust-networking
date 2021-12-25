pub fn hex_dump(data: &[u8], size: usize) {
    let mut i = 0usize;
    while i < size {
        for j in 0..16usize {
            if j != 0 {
                print!(" ");
            }
            if i + j < size {
                print!("{:02x}", data[i + j]);
            } else {
                print!(" ");
            }
        }
        print!("    ");
        for _ in 0..16 {
            if i < size {
                let c = data[i] as char;
                if c.is_ascii() && !c.is_control() {
                    print!("{:}", c);
                } else {
                    print!(".");
                }
                i += 1;
            } else {
                print!(" ");
            }
        }
        println!();
    }
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

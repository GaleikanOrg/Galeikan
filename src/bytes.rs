use std::fmt::Write as _;

pub const MAX_BYTES_VALUE: usize = 1024 * 1024;

pub fn crc32(bytes: &[u8]) -> u32 {
    crc32_update(bytes, 0)
}

pub fn crc32_update(bytes: &[u8], previous: u32) -> u32 {
    let mut crc = !previous;
    for &byte in bytes {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xedb8_8320 & 0_u32.wrapping_sub(crc & 1));
        }
    }
    !crc
}

pub fn hex_dump(bytes: &[u8], start: usize) -> String {
    let mut output = String::new();
    for (row_index, row) in bytes.chunks(16).enumerate() {
        if row_index > 0 {
            output.push('\n');
        }
        let offset = start + row_index * 16;
        write!(&mut output, "{offset:08x}  ").expect("writing to String cannot fail");
        for column in 0..16 {
            if let Some(byte) = row.get(column) {
                write!(&mut output, "{byte:02x} ").expect("writing to String cannot fail");
            } else {
                output.push_str("   ");
            }
            if column == 7 {
                output.push(' ');
            }
        }
        output.push('|');
        for byte in row {
            output.push(if (0x20..=0x7e).contains(byte) {
                char::from(*byte)
            } else {
                '.'
            });
        }
        output.push('|');
    }
    output
}

fn bounded(length: usize) -> Result<(), String> {
    if length > MAX_BYTES_VALUE {
        Err(format!(
            "LimitExceeded: bytes result exceeds {MAX_BYTES_VALUE} bytes"
        ))
    } else {
        Ok(())
    }
}

pub fn concat(left: &[u8], right: &[u8]) -> Result<Vec<u8>, String> {
    let length = left
        .len()
        .checked_add(right.len())
        .ok_or("bytes length overflow")?;
    bounded(length)?;
    let mut result = Vec::with_capacity(length);
    result.extend_from_slice(left);
    result.extend_from_slice(right);
    Ok(result)
}

pub fn repeat(data: &[u8], count: i64) -> Result<Vec<u8>, String> {
    let count = usize::try_from(count).map_err(|_| "repeat count must not be negative")?;
    if count > MAX_BYTES_VALUE {
        return Err(format!("repeat count exceeds {MAX_BYTES_VALUE}"));
    }
    let length = data
        .len()
        .checked_mul(count)
        .ok_or("bytes length overflow")?;
    bounded(length)?;
    if data.is_empty() {
        return Ok(Vec::new());
    }
    let mut result = Vec::with_capacity(length);
    for _ in 0..count {
        result.extend_from_slice(data);
    }
    Ok(result)
}

pub fn xor(data: &[u8], key: &[u8]) -> Result<Vec<u8>, String> {
    if key.is_empty() {
        return Err("xor key must not be empty".into());
    }
    bounded(data.len())?;
    bounded(key.len())?;
    Ok(data
        .iter()
        .enumerate()
        .map(|(index, byte)| byte ^ key[index % key.len()])
        .collect())
}

pub fn find(data: &[u8], needle: &[u8]) -> Result<i64, String> {
    if needle.is_empty() {
        return Ok(0);
    }
    if needle.len() > data.len() {
        return Ok(-1);
    }
    let mut failure = Vec::new();
    failure
        .try_reserve_exact(needle.len())
        .map_err(|_| "bytes search allocation failed")?;
    failure.push(0usize);
    let mut matched = 0usize;
    for index in 1..needle.len() {
        while matched > 0 && needle[index] != needle[matched] {
            matched = failure[matched - 1];
        }
        if needle[index] == needle[matched] {
            matched += 1;
        }
        failure.push(matched);
    }
    matched = 0;
    for (index, byte) in data.iter().enumerate() {
        while matched > 0 && *byte != needle[matched] {
            matched = failure[matched - 1];
        }
        if *byte == needle[matched] {
            matched += 1;
        }
        if matched == needle.len() {
            return Ok((index + 1 - needle.len()) as i64);
        }
    }
    Ok(-1)
}

pub fn hex_bytes(data: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(data.len() * 2);
    for byte in data {
        result.push(HEX[(byte >> 4) as usize] as char);
        result.push(HEX[(byte & 0x0f) as usize] as char);
    }
    result
}

pub fn to_hex(data: &[u8]) -> Result<String, String> {
    bounded(data.len())?;
    Ok(hex_bytes(data))
}

pub fn pack(value: i64, encoding: &str) -> Result<Vec<u8>, String> {
    if matches!(
        encoding,
        "i8" | "i16le" | "i16be" | "i32le" | "i32be" | "i64le" | "i64be" | "sleb128"
    ) {
        return pack_signed(value, encoding);
    }
    let unsigned = u64::try_from(value).map_err(|_| "pack expects a nonnegative value")?;
    pack_unsigned(unsigned, encoding)
}

pub fn pack_unsigned(unsigned: u64, encoding: &str) -> Result<Vec<u8>, String> {
    if matches!(
        encoding,
        "i8" | "i16le" | "i16be" | "i32le" | "i32be" | "i64le" | "i64be" | "sleb128"
    ) {
        let signed = i64::try_from(unsigned)
            .map_err(|_| format!("pack value out of range for {encoding}"))?;
        return pack_signed(signed, encoding);
    }
    let out = match encoding {
        "u8" => vec![u8::try_from(unsigned).map_err(|_| "pack value out of range for u8")?],
        "u16le" => u16::try_from(unsigned)
            .map_err(|_| "pack value out of range for u16le")?
            .to_le_bytes()
            .to_vec(),
        "u16be" => u16::try_from(unsigned)
            .map_err(|_| "pack value out of range for u16be")?
            .to_be_bytes()
            .to_vec(),
        "u32le" => u32::try_from(unsigned)
            .map_err(|_| "pack value out of range for u32le")?
            .to_le_bytes()
            .to_vec(),
        "u32be" => u32::try_from(unsigned)
            .map_err(|_| "pack value out of range for u32be")?
            .to_be_bytes()
            .to_vec(),
        "u64le" => unsigned.to_le_bytes().to_vec(),
        "u64be" => unsigned.to_be_bytes().to_vec(),
        "uleb128" => {
            let mut value = unsigned;
            let mut bytes = Vec::with_capacity(10);
            loop {
                let mut byte = (value & 0x7f) as u8;
                value >>= 7;
                if value != 0 {
                    byte |= 0x80;
                }
                bytes.push(byte);
                if value == 0 {
                    break bytes;
                }
            }
        }
        _ => return Err("pack encoding must be u8, i8, u16le/be, i16le/be, u32le/be, i32le/be, u64le/be, i64le/be, uleb128, or sleb128".into()),
    };
    Ok(out)
}

fn pack_signed(value: i64, encoding: &str) -> Result<Vec<u8>, String> {
    let out = match encoding {
        "i8" => i8::try_from(value)
            .map_err(|_| "pack value out of range for i8")?
            .to_le_bytes()
            .to_vec(),
        "i16le" => i16::try_from(value)
            .map_err(|_| "pack value out of range for i16le")?
            .to_le_bytes()
            .to_vec(),
        "i16be" => i16::try_from(value)
            .map_err(|_| "pack value out of range for i16be")?
            .to_be_bytes()
            .to_vec(),
        "i32le" => i32::try_from(value)
            .map_err(|_| "pack value out of range for i32le")?
            .to_le_bytes()
            .to_vec(),
        "i32be" => i32::try_from(value)
            .map_err(|_| "pack value out of range for i32be")?
            .to_be_bytes()
            .to_vec(),
        "i64le" => value.to_le_bytes().to_vec(),
        "i64be" => value.to_be_bytes().to_vec(),
        "sleb128" => {
            let mut value = value;
            let mut bytes = Vec::with_capacity(10);
            loop {
                let mut byte = (value as u8) & 0x7f;
                value >>= 7;
                let done = (value == 0 && byte & 0x40 == 0) || (value == -1 && byte & 0x40 != 0);
                if !done {
                    byte |= 0x80;
                }
                bytes.push(byte);
                if done {
                    break bytes;
                }
            }
        }
        _ => unreachable!("signed encodings are selected before calling pack_signed"),
    };
    Ok(out)
}

pub fn parse_hex(text: &str) -> Result<Vec<u8>, String> {
    let mut result = Vec::new();
    let mut high = None;
    for ch in text.chars() {
        if ch.is_ascii_whitespace() {
            continue;
        }
        let digit = ch
            .to_digit(16)
            .filter(|_| ch.is_ascii())
            .ok_or("invalid hex data")? as u8;
        if let Some(first) = high.take() {
            if result.len() >= MAX_BYTES_VALUE {
                return Err(format!("hex data exceeds {MAX_BYTES_VALUE} bytes"));
            }
            result.push((first << 4) | digit);
        } else {
            high = Some(digit);
        }
    }
    if high.is_some() {
        return Err("hex data needs an even number of digits".into());
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc32_matches_standard_check_value() {
        assert_eq!(crc32(b""), 0);
        assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
        let first = crc32_update(b"1234", 0);
        assert_eq!(crc32_update(b"56789", first), crc32(b"123456789"));
        assert_eq!(crc32_update(b"", first), first);
    }

    #[test]
    fn hex_dump_shows_logical_offsets_and_printable_ascii() {
        assert_eq!(hex_dump(b"", 0), "");
        let row = hex_dump(b"G\0\x7f", 3);
        assert!(row.starts_with("00000003  47 00 7f "));
        assert!(row.ends_with("|G..|"));
        assert_eq!(row.lines().count(), 1);

        let rows = hex_dump(b"ABCDEFGHIJKLMNOPQ", 3);
        assert_eq!(rows.lines().count(), 2);
        assert!(rows.lines().next().unwrap().ends_with("|ABCDEFGHIJKLMNOP|"));
        assert!(rows.lines().nth(1).unwrap().starts_with("00000013  51 "));
        assert!(rows.lines().nth(1).unwrap().ends_with("|Q|"));
    }

    #[test]
    fn transforms_are_bounded_and_reversible() {
        assert_eq!(concat(b"GA", b"K").unwrap(), b"GAK");
        assert_eq!(repeat(b"AB", 3).unwrap(), b"ABABAB");
        assert_eq!(xor(&xor(b"GAK", b"key").unwrap(), b"key").unwrap(), b"GAK");
        assert_eq!(to_hex(b"\0\xff").unwrap(), "00ff");
        assert_eq!(parse_hex("00 ff").unwrap(), b"\0\xff");
        assert_eq!(
            repeat(b"A", -1).unwrap_err(),
            "repeat count must not be negative"
        );
        assert!(repeat(b"AB", MAX_BYTES_VALUE as i64).is_err());
        assert!(concat(&vec![0; MAX_BYTES_VALUE], b"A").is_err());
        assert_eq!(xor(b"A", b"").unwrap_err(), "xor key must not be empty");
    }

    #[test]
    fn pack_checks_width_endianness_and_signed_range() {
        assert_eq!(pack(0xab, "u8").unwrap(), [0xab]);
        assert_eq!(pack(0x1234, "u16le").unwrap(), [0x34, 0x12]);
        assert_eq!(pack(0x1234, "u16be").unwrap(), [0x12, 0x34]);
        assert_eq!(pack(0x12345678, "u32le").unwrap(), [0x78, 0x56, 0x34, 0x12]);
        assert_eq!(pack(0x12345678, "u32be").unwrap(), [0x12, 0x34, 0x56, 0x78]);
        assert_eq!(
            pack(0x123456789abcdef, "u64le").unwrap(),
            [0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01]
        );
        assert_eq!(
            pack(0x123456789abcdef, "u64be").unwrap(),
            [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]
        );
        assert_eq!(pack(-128, "i8").unwrap(), [0x80]);
        assert_eq!(pack(-2, "i16le").unwrap(), [0xfe, 0xff]);
        assert_eq!(pack(-2, "i16be").unwrap(), [0xff, 0xfe]);
        assert_eq!(pack(-2, "i32le").unwrap(), [0xfe, 0xff, 0xff, 0xff]);
        assert_eq!(pack(-2, "i32be").unwrap(), [0xff, 0xff, 0xff, 0xfe]);
        assert_eq!(pack(-2, "i64le").unwrap()[0], 0xfe);
        assert_eq!(pack(-2, "i64be").unwrap()[7], 0xfe);
        assert_eq!(pack_unsigned(127, "i8").unwrap(), [0x7f]);
        assert!(pack(-1, "u8").unwrap_err().contains("nonnegative"));
        assert!(pack(-129, "i8").unwrap_err().contains("out of range"));
        assert!(pack(128, "i8").unwrap_err().contains("out of range"));
        assert!(pack_unsigned(128, "i8")
            .unwrap_err()
            .contains("out of range"));
        assert!(pack_unsigned(u64::MAX, "i64be")
            .unwrap_err()
            .contains("out of range"));
        assert!(pack(256, "u8").unwrap_err().contains("out of range"));
        assert!(pack(65536, "u16le").unwrap_err().contains("out of range"));
        assert!(pack(4294967296, "u32be")
            .unwrap_err()
            .contains("out of range"));
        assert!(pack(1, "u128le").unwrap_err().contains("encoding must"));
    }
}

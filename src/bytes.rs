use std::fmt::Write as _;

pub const MAX_BYTES_VALUE: usize = 1024 * 1024;

pub fn histogram(bytes: &[u8]) -> [u64; 256] {
    let mut counts = [0_u64; 256];
    for &byte in bytes {
        counts[usize::from(byte)] += 1;
    }
    counts
}

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
    apply_key(data, key, "xor", |byte, mask| byte ^ mask)
}

pub fn bit_and(data: &[u8], key: &[u8]) -> Result<Vec<u8>, String> {
    apply_key(data, key, "bitwise", |byte, mask| byte & mask)
}

pub fn bit_or(data: &[u8], key: &[u8]) -> Result<Vec<u8>, String> {
    apply_key(data, key, "bitwise", |byte, mask| byte | mask)
}

pub fn from_base64(text: &str) -> Result<Vec<u8>, String> {
    decode_base64(text, false)
}

pub fn from_base64_url(text: &str) -> Result<Vec<u8>, String> {
    decode_base64(text, true)
}

fn decode_base64(text: &str, url_safe: bool) -> Result<Vec<u8>, String> {
    let mut result = Vec::new();
    let mut quartet = [0_u8; 4];
    let mut count = 0;
    let mut padded = false;
    for byte in text.bytes() {
        if matches!(byte, b' ' | b'\t' | b'\r' | b'\n') {
            continue;
        }
        if padded {
            return Err("invalid base64 data".into());
        }
        quartet[count] = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' if !url_safe => 62,
            b'/' if !url_safe => 63,
            b'-' if url_safe => 62,
            b'_' if url_safe => 63,
            b'=' => 64,
            _ => return Err("invalid base64 data".into()),
        };
        count += 1;
        if count == 4 {
            let [a, b, c, d] = quartet;
            if a == 64 || b == 64 || (c == 64 && (d != 64 || b & 15 != 0))
                || (c != 64 && d == 64 && c & 3 != 0)
            {
                return Err("invalid base64 data".into());
            }
            let width = if c == 64 { 1 } else if d == 64 { 2 } else { 3 };
            bounded(result.len() + width)?;
            result.push((a << 2) | (b >> 4));
            if width > 1 {
                result.push((b << 4) | (c >> 2));
            }
            if width > 2 {
                result.push((c << 6) | d);
            }
            padded = width < 3;
            count = 0;
        }
    }
    if count != 0 {
        if !url_safe
            || count == 1
            || quartet[0] == 64
            || quartet[1] == 64
            || (count == 2 && quartet[1] & 15 != 0)
            || (count == 3 && (quartet[2] == 64 || quartet[2] & 3 != 0))
        {
            return Err("invalid base64 data".into());
        }
        bounded(result.len() + count - 1)?;
        result.push((quartet[0] << 2) | (quartet[1] >> 4));
        if count == 3 {
            result.push((quartet[1] << 4) | (quartet[2] >> 2));
        }
    }
    Ok(result)
}

pub fn to_base64(data: &[u8]) -> Result<String, String> {
    encode_base64(data, false)
}

pub fn to_base64_url(data: &[u8]) -> Result<String, String> {
    encode_base64(data, true)
}

fn encode_base64(data: &[u8], url_safe: bool) -> Result<String, String> {
    const STANDARD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    const URL_SAFE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let digits = if url_safe { URL_SAFE } else { STANDARD };
    bounded(data.len())?;
    let mut result = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let a = chunk[0];
        let b = *chunk.get(1).unwrap_or(&0);
        let c = *chunk.get(2).unwrap_or(&0);
        result.push(char::from(digits[usize::from(a >> 2)]));
        result.push(char::from(digits[usize::from(((a & 3) << 4) | (b >> 4))]));
        if chunk.len() > 1 {
            result.push(char::from(digits[usize::from(((b & 15) << 2) | (c >> 6))]));
        } else if !url_safe {
            result.push('=');
        }
        if chunk.len() > 2 {
            result.push(char::from(digits[usize::from(c & 63)]));
        } else if !url_safe {
            result.push('=');
        }
    }
    Ok(result)
}

fn apply_key(
    data: &[u8],
    key: &[u8],
    operation: &str,
    combine: fn(u8, u8) -> u8,
) -> Result<Vec<u8>, String> {
    if key.is_empty() {
        return Err(format!("{operation} key must not be empty"));
    }
    bounded(data.len())?;
    bounded(key.len())?;
    Ok(data
        .iter()
        .enumerate()
        .map(|(index, byte)| combine(*byte, key[index % key.len()]))
        .collect())
}

pub fn rotate_left(data: &[u8], count: i64) -> Result<Vec<u8>, String> {
    let count = u32::try_from(count)
        .ok()
        .filter(|count| *count < 8)
        .ok_or("rotate count must be in 0..7")?;
    bounded(data.len())?;
    Ok(data.iter().map(|byte| byte.rotate_left(count)).collect())
}

pub fn rotate_right(data: &[u8], count: i64) -> Result<Vec<u8>, String> {
    let count = u32::try_from(count)
        .ok()
        .filter(|count| *count < 8)
        .ok_or("rotate count must be in 0..7")?;
    bounded(data.len())?;
    Ok(data.iter().map(|byte| byte.rotate_right(count)).collect())
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

pub fn from_utf16(text: &str, big_endian: bool) -> Result<Vec<u8>, String> {
    let units = text.encode_utf16().count();
    let length = units.checked_mul(2).ok_or("bytes length overflow")?;
    bounded(length)?;
    let mut result = Vec::with_capacity(length);
    for unit in text.encode_utf16() {
        let encoded = if big_endian {
            unit.to_be_bytes()
        } else {
            unit.to_le_bytes()
        };
        result.extend_from_slice(&encoded);
    }
    Ok(result)
}

pub fn to_utf16(data: &[u8], big_endian: bool) -> Result<String, String> {
    let (chunks, remainder) = data.as_chunks::<2>();
    if !remainder.is_empty() {
        return Err("invalid UTF-16 data".into());
    }
    let units = chunks.iter().map(|chunk| {
        let bytes = [chunk[0], chunk[1]];
        if big_endian {
            u16::from_be_bytes(bytes)
        } else {
            u16::from_le_bytes(bytes)
        }
    });
    std::char::decode_utf16(units)
        .map(|scalar| scalar.map_err(|_| "invalid UTF-16 data".to_owned()))
        .collect()
}

pub fn from_latin1(text: &str) -> Result<Vec<u8>, String> {
    let mut result = Vec::with_capacity(text.len().min(MAX_BYTES_VALUE));
    for scalar in text.chars() {
        let code = u32::from(scalar);
        if code > 255 {
            return Err("character not representable in Latin-1".into());
        }
        if result.len() == MAX_BYTES_VALUE {
            return Err(format!(
                "LimitExceeded: bytes result exceeds {MAX_BYTES_VALUE} bytes"
            ));
        }
        result.push(code as u8);
    }
    Ok(result)
}

pub fn to_latin1(data: &[u8]) -> String {
    data.iter().map(|byte| char::from(*byte)).collect()
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
    fn base64_decoding_checks_padding_and_bounds() {
        assert_eq!(from_base64("").unwrap(), b"");
        assert_eq!(from_base64("T W\nFu").unwrap(), b"Man");
        assert_eq!(from_base64("Zg==").unwrap(), b"f");
        assert_eq!(from_base64("Zm8=").unwrap(), b"fo");
        assert_eq!(from_base64("Zm9v").unwrap(), b"foo");
        for invalid in ["Zg=", "Zg===", "Zh==", "Zm9=", "Zg==A", "Zg==\0"] {
            assert_eq!(from_base64(invalid).unwrap_err(), "invalid base64 data");
        }
        let oversized = "AAAA".repeat(MAX_BYTES_VALUE / 3 + 1);
        assert!(from_base64(&oversized).unwrap_err().starts_with("LimitExceeded:"));
    }

    #[test]
    fn base64_encoding_round_trips_binary() {
        assert_eq!(to_base64(b"").unwrap(), "");
        assert_eq!(to_base64(b"f").unwrap(), "Zg==");
        assert_eq!(to_base64(b"fo").unwrap(), "Zm8=");
        assert_eq!(to_base64(b"foo").unwrap(), "Zm9v");
        let binary = [0, 0xff, 0x7f, 0x80, 0x01];
        let encoded = to_base64(&binary).unwrap();
        assert_eq!(from_base64(&encoded).unwrap(), binary);
        assert_eq!(
            to_base64(&vec![0; MAX_BYTES_VALUE]).unwrap().len(),
            MAX_BYTES_VALUE.div_ceil(3) * 4
        );
        assert!(to_base64(&vec![0; MAX_BYTES_VALUE + 1])
            .unwrap_err()
            .starts_with("LimitExceeded:"));
    }

    #[test]
    fn base64_url_accepts_unpadded_canonical_input() {
        assert_eq!(to_base64_url(b"f").unwrap(), "Zg");
        assert_eq!(to_base64_url(b"fo").unwrap(), "Zm8");
        assert_eq!(to_base64_url(b"foo").unwrap(), "Zm9v");
        assert_eq!(to_base64_url(&[0xfb, 0xef, 0xff]).unwrap(), "--__");
        assert_eq!(from_base64_url("--__").unwrap(), [0xfb, 0xef, 0xff]);
        assert_eq!(from_base64_url("Zg").unwrap(), b"f");
        assert_eq!(from_base64_url("Zm8=").unwrap(), b"fo");
        assert_eq!(from_base64_url("").unwrap(), b"");
        for invalid in [
            "Z", "Zh", "Zm9", "=A", "=AA", "A=", "AA=", "Zg=", "++//", "Zg==A",
        ] {
            assert_eq!(from_base64_url(invalid).unwrap_err(), "invalid base64 data");
        }
        assert_eq!(
            from_base64_url(&to_base64_url(&[0, 0xff, 0x80, 1]).unwrap()).unwrap(),
            [0, 0xff, 0x80, 1]
        );
    }

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
        assert_eq!(rotate_left(&[0x81, 0x0f], 1).unwrap(), [0x03, 0x1e]);
        assert_eq!(rotate_right(&[0x81, 0x0f], 1).unwrap(), [0xc0, 0x87]);
        assert_eq!(rotate_right(&rotate_left(b"GAK", 7).unwrap(), 7).unwrap(), b"GAK");
        assert_eq!(rotate_left(b"", 0).unwrap(), b"");
        assert_eq!(rotate_left(b"A", -1).unwrap_err(), "rotate count must be in 0..7");
        assert_eq!(rotate_right(b"A", 8).unwrap_err(), "rotate count must be in 0..7");
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

// ECMA-335 II.23.2 method signatures. Keep this decoder bounded: metadata is untrusted input.
struct Decoder<'a> {
    data: &'a [u8],
    at: usize,
}

impl Decoder<'_> {
    fn byte(&mut self) -> Result<u8, &'static str> {
        let byte = *self
            .data
            .get(self.at)
            .ok_or("truncated PE CLR method signature")?;
        self.at += 1;
        Ok(byte)
    }

    fn compressed(&mut self, canonical: bool) -> Result<u32, &'static str> {
        let first = self.byte()?;
        let (value, width) = if first & 0x80 == 0 {
            (u32::from(first), 1)
        } else if first & 0xc0 == 0x80 {
            (
                ((u32::from(first & 0x3f)) << 8) | u32::from(self.byte()?),
                2,
            )
        } else if first & 0xe0 == 0xc0 {
            (
                ((u32::from(first & 0x1f)) << 24)
                    | ((u32::from(self.byte()?)) << 16)
                    | ((u32::from(self.byte()?)) << 8)
                    | u32::from(self.byte()?),
                4,
            )
        } else {
            return Err("invalid PE CLR compressed signature integer");
        };
        if canonical && ((width == 2 && value < 128) || (width == 4 && value < 0x4000)) {
            return Err("noncanonical PE CLR compressed signature integer");
        }
        Ok(value)
    }

    fn compressed_signed(&mut self) -> Result<i32, &'static str> {
        let start = self.at;
        let raw = self.compressed(false)?;
        let bits = match self.at - start {
            1 => 6,
            2 => 13,
            4 => 28,
            _ => unreachable!(),
        };
        let value = (raw >> 1) as i32 - if raw & 1 != 0 { 1 << bits } else { 0 };
        if (bits == 13 && (-64..=63).contains(&value))
            || (bits == 28 && (-8192..=8191).contains(&value))
        {
            return Err("noncanonical PE CLR compressed signature integer");
        }
        Ok(value)
    }

    fn token(&mut self, out: &mut String) -> Result<(), &'static str> {
        let coded = self.compressed(true)?;
        let table = match coded & 3 {
            0 => "TypeDef",
            1 => "TypeRef",
            2 => "TypeSpec",
            _ => return Err("invalid PE CLR signature type token"),
        };
        let row = coded >> 2;
        if row == 0 {
            return Err("invalid PE CLR signature type token");
        }
        out.push_str(table);
        out.push('#');
        out.push_str(&row.to_string());
        Ok(())
    }

    fn ty(
        &mut self,
        out: &mut String,
        depth: u8,
        allow_void: bool,
        allow_byref: bool,
    ) -> Result<(), &'static str> {
        if depth > 16 {
            return Err("PE CLR method signature nesting exceeds 16");
        }
        while matches!(self.data.get(self.at), Some(0x1f | 0x20)) {
            let required = self.byte()? == 0x1f;
            out.push_str(if required { "modreq<" } else { "modopt<" });
            self.token(out)?;
            out.push_str("> ");
        }
        match self.byte()? {
            0x01 if allow_void => out.push_str("void"),
            0x02 => out.push_str("bool"),
            0x03 => out.push_str("char"),
            0x04 => out.push_str("i8"),
            0x05 => out.push_str("u8"),
            0x06 => out.push_str("i16"),
            0x07 => out.push_str("u16"),
            0x08 => out.push_str("i32"),
            0x09 => out.push_str("u32"),
            0x0a => out.push_str("i64"),
            0x0b => out.push_str("u64"),
            0x0c => out.push_str("f32"),
            0x0d => out.push_str("f64"),
            0x0e => out.push_str("string"),
            0x0f => {
                out.push_str("ptr<");
                self.ty(out, depth + 1, true, false)?;
                out.push('>');
            }
            0x10 if allow_byref => {
                out.push_str("ref<");
                self.ty(out, depth + 1, false, false)?;
                out.push('>');
            }
            code @ (0x11 | 0x12) => {
                out.push_str(if code == 0x11 { "value<" } else { "class<" });
                self.token(out)?;
                out.push('>');
            }
            code @ (0x13 | 0x1e) => {
                out.push(if code == 0x13 { 'T' } else { 'M' });
                out.push_str(&self.compressed(true)?.to_string());
            }
            0x14 => {
                out.push_str("array<");
                self.ty(out, depth + 1, false, false)?;
                let rank = self.compressed(true)?;
                if !(1..=32).contains(&rank) {
                    return Err("invalid PE CLR signature array rank");
                }
                let sizes = self.compressed(true)?;
                if sizes > rank {
                    return Err("invalid PE CLR signature array shape");
                }
                out.push_str(", sizes=[");
                for i in 0..sizes {
                    if i != 0 {
                        out.push_str(", ");
                    }
                    out.push_str(&self.compressed(true)?.to_string());
                }
                out.push(']');
                let bounds = self.compressed(true)?;
                if bounds > rank {
                    return Err("invalid PE CLR signature array shape");
                }
                out.push_str(", lower=[");
                for i in 0..bounds {
                    if i != 0 {
                        out.push_str(", ");
                    }
                    out.push_str(&self.compressed_signed()?.to_string());
                }
                out.push(']');
                out.push_str(", rank=");
                out.push_str(&rank.to_string());
                out.push('>');
            }
            0x15 => {
                out.push_str(match self.byte()? {
                    0x11 => "value<",
                    0x12 => "class<",
                    _ => return Err("invalid PE CLR generic instance kind"),
                });
                self.token(out)?;
                let count = self.compressed(true)?;
                if count == 0 || count > 64 {
                    return Err("invalid PE CLR generic argument count");
                }
                for _ in 0..count {
                    out.push_str(", ");
                    self.ty(out, depth + 1, false, false)?;
                }
                out.push('>');
            }
            0x16 if allow_byref => out.push_str("typedref"),
            0x18 => out.push_str("isize"),
            0x19 => out.push_str("usize"),
            0x1b => self.method(out, depth + 1, true)?,
            0x1c => out.push_str("object"),
            0x1d => {
                out.push_str("vector<");
                self.ty(out, depth + 1, false, false)?;
                out.push('>');
            }
            _ => return Err("unsupported PE CLR method signature element"),
        }
        Ok(())
    }

    fn method(&mut self, out: &mut String, depth: u8, fnptr: bool) -> Result<(), &'static str> {
        if depth > 16 {
            return Err("PE CLR method signature nesting exceeds 16");
        }
        let flags = self.byte()?;
        if flags & 0x80 != 0
            || !matches!(flags & 0x0f, 0 | 5)
            || (flags & 0x40 != 0 && flags & 0x20 == 0)
        {
            return Err("invalid PE CLR method calling convention");
        }
        let generics = if flags & 0x10 != 0 {
            self.compressed(true)?
        } else {
            0
        };
        if flags & 0x10 != 0 && (generics == 0 || generics > 64) {
            return Err("invalid PE CLR generic parameter count");
        }
        let params = self.compressed(true)?;
        if params > 128 {
            return Err("PE CLR method parameter count exceeds 128");
        }
        let mut result = String::new();
        self.ty(&mut result, depth + 1, true, true)?;
        if flags & 0x40 != 0 {
            out.push_str("explicit ");
        }
        if flags & 0x20 != 0 {
            out.push_str("instance ");
        }
        if flags & 0x0f == 5 {
            out.push_str("vararg ");
        }
        if fnptr {
            out.push_str("fn");
        }
        if generics != 0 {
            out.push_str("generic<M0");
            for n in 1..generics {
                out.push_str(", M");
                out.push_str(&n.to_string());
            }
            out.push('>');
        }
        out.push('(');
        for n in 0..params {
            if n != 0 {
                out.push_str(", ");
            }
            self.ty(out, depth + 1, false, true)?;
        }
        out.push_str(") -> ");
        out.push_str(&result);
        Ok(())
    }
}

pub fn format_method(data: &[u8]) -> Result<String, String> {
    if data.len() > 16 * 1024 {
        return Err("PE CLR method signature exceeds 16 KiB".into());
    }
    let mut decoder = Decoder { data, at: 0 };
    let mut text = String::new();
    decoder
        .method(&mut text, 0, false)
        .map_err(str::to_string)?;
    if decoder.at != data.len() {
        return Err("trailing PE CLR method signature bytes".into());
    }
    if text.len() > 4096 {
        return Err("PE CLR method signature text exceeds 4096 bytes".into());
    }
    Ok(text)
}

#[cfg(test)]
mod tests {
    use super::format_method;

    #[test]
    fn rejects_malformed_and_unbounded_signatures() {
        for data in [
            &[][..],
            &[0, 0x80][..],
            &[0, 0x80, 0, 1][..],
            &[0, 0, 0x12, 3][..],
            &[0, 0, 0x12, 0][..],
            &[0, 0, 0x14, 8, 0, 0, 0][..],
            &[0, 0, 8, 8][..],
        ] {
            assert!(format_method(data).is_err(), "accepted {data:?}");
        }
        let mut nested = vec![0, 0];
        nested.extend([0x1d; 17]);
        nested.push(8);
        assert!(format_method(&nested).is_err());
        assert!(format_method(&vec![0; 16 * 1024 + 1]).is_err());
    }
}

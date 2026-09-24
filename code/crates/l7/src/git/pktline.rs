//! pkt-line framing (gitprotocol-common): four hex digits of total length
//! including themselves, then data. `0000` flush, `0001` delimiter, `0002`
//! response end; `0003` is invalid; the maximum is 65520 bytes. The reader
//! is strict and length-checked; it never guesses.

pub const MAX_PKT: usize = 65520;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pkt<'a> {
    Data(&'a [u8]),
    Flush,
    Delim,
    ResponseEnd,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PktError {
    /// Fewer bytes than the header or declared length.
    Truncated,
    BadLength,
}

fn hex4(b: &[u8]) -> Option<usize> {
    let mut n = 0usize;
    for &c in b {
        let d = match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            _ => return None,
        };
        n = n * 16 + d as usize;
    }
    Some(n)
}

/// Read one pkt-line from the front of `buf`; returns it and the bytes used.
pub fn read(buf: &[u8]) -> Result<(Pkt<'_>, usize), PktError> {
    let hdr = buf.get(..4).ok_or(PktError::Truncated)?;
    let len = hex4(hdr).ok_or(PktError::BadLength)?;
    match len {
        0 => Ok((Pkt::Flush, 4)),
        1 => Ok((Pkt::Delim, 4)),
        2 => Ok((Pkt::ResponseEnd, 4)),
        3 => Err(PktError::BadLength),
        n if n > MAX_PKT => Err(PktError::BadLength),
        n => {
            let data = buf.get(4..n).ok_or(PktError::Truncated)?;
            Ok((Pkt::Data(data), n))
        }
    }
}

/// Append one data pkt-line.
pub fn write(out: &mut Vec<u8>, data: &[u8]) {
    assert!(data.len() + 4 <= MAX_PKT, "pkt-line payload too large");
    out.extend_from_slice(format!("{:04x}", data.len() + 4).as_bytes());
    out.extend_from_slice(data);
}

pub fn flush(out: &mut Vec<u8>) {
    out.extend_from_slice(b"0000");
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn framing() {
        assert_eq!(read(b"0000rest").unwrap(), (Pkt::Flush, 4));
        assert_eq!(read(b"0001").unwrap(), (Pkt::Delim, 4));
        assert_eq!(read(b"0009hello").unwrap(), (Pkt::Data(b"hello"), 9));
        assert_eq!(read(b"0004").unwrap(), (Pkt::Data(b""), 4));
        assert_eq!(read(b"0003"), Err(PktError::BadLength));
        assert_eq!(read(b"000ahello"), Err(PktError::Truncated));
        assert_eq!(read(b"00"), Err(PktError::Truncated));
        assert_eq!(read(b"00g0"), Err(PktError::BadLength));
        assert_eq!(read(b"fff1"), Err(PktError::BadLength));
        assert_eq!(read(b"+004"), Err(PktError::BadLength), "no sign characters");
    }

    proptest! {
        #[test]
        fn write_read_round_trip(data in proptest::collection::vec(any::<u8>(), 0..2000)) {
            let mut out = Vec::new();
            write(&mut out, &data);
            let (p, n) = read(&out).unwrap();
            prop_assert_eq!(p, Pkt::Data(&data));
            prop_assert_eq!(n, out.len());
        }

        #[test]
        fn never_reads_past_the_buffer(b in proptest::collection::vec(any::<u8>(), 0..64)) {
            if let Ok((_, n)) = read(&b) {
                prop_assert!(n <= b.len() && n >= 4);
            }
        }
    }
}

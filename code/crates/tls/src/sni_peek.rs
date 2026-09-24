//! Strict TLS ClientHello parser that extracts the `server_name` (SNI).
//!
//! Used on the L4 path to enforce CONNECT host = SNI (domain fronting,
//! conformance category 7) and to refuse non-TLS tunnels (category 5). The
//! SNI bytes are returned raw; the caller canonicalises them with the single
//! canonicaliser and compares canonical values (I6).
//!
//! Handshake messages may span several TLS records; they are reassembled up
//! to [`MAX_HELLO`] bytes. Duplicate extensions, trailing bytes and malformed
//! lengths are errors, never guesses.

pub const MAX_HELLO: usize = 16 * 1024;
const REC_HANDSHAKE: u8 = 0x16;
const HS_CLIENT_HELLO: u8 = 0x01;
const EXT_SERVER_NAME: u16 = 0x0000;

#[derive(Debug, PartialEq, Eq)]
pub enum Peek {
    /// Not enough bytes yet.
    Incomplete,
    /// The stream does not start with a TLS handshake record.
    NotTls,
    /// A TLS record that is not a well-formed ClientHello.
    Malformed(&'static str),
    /// A complete ClientHello; `sni` is `None` when there is no server_name.
    Hello { sni: Option<Vec<u8>> },
}

struct Reader<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> Reader<'a> {
    fn new(b: &'a [u8]) -> Self {
        Reader { b, i: 0 }
    }
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.i.checked_add(n)?;
        let s = self.b.get(self.i..end)?;
        self.i = end;
        Some(s)
    }
    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|s| s[0])
    }
    fn u16(&mut self) -> Option<u16> {
        self.take(2).map(|s| u16::from_be_bytes([s[0], s[1]]))
    }
    fn rest(&self) -> usize {
        self.b.len() - self.i
    }
}

/// Reassemble the first handshake message from consecutive handshake records.
fn handshake_bytes(buf: &[u8]) -> Result<Option<Vec<u8>>, Peek> {
    let mut hs = Vec::new();
    let mut i = 0;
    loop {
        if buf.len() < i + 5 {
            return Ok(None);
        }
        let (ct, major, len) = (buf[i], buf[i + 1], u16::from_be_bytes([buf[i + 3], buf[i + 4]]) as usize);
        if ct != REC_HANDSHAKE {
            return Err(if i == 0 { Peek::NotTls } else { Peek::Malformed("interleaved non-handshake record") });
        }
        if major != 0x03 {
            return Err(if i == 0 { Peek::NotTls } else { Peek::Malformed("record version") });
        }
        if len == 0 || len > MAX_HELLO {
            return Err(Peek::Malformed("record length"));
        }
        if buf.len() < i + 5 + len {
            return Ok(None);
        }
        hs.extend_from_slice(&buf[i + 5..i + 5 + len]);
        i += 5 + len;
        if hs.len() >= 4 {
            if hs[0] != HS_CLIENT_HELLO {
                return Err(Peek::Malformed("not a ClientHello"));
            }
            let need = 4 + (((hs[1] as usize) << 16) | ((hs[2] as usize) << 8) | hs[3] as usize);
            if need > MAX_HELLO {
                return Err(Peek::Malformed("ClientHello too large"));
            }
            if hs.len() >= need {
                if hs.len() > need {
                    return Err(Peek::Malformed("data after ClientHello in handshake records"));
                }
                return Ok(Some(hs));
            }
        }
        if hs.len() > MAX_HELLO {
            return Err(Peek::Malformed("ClientHello too large"));
        }
    }
}

pub fn peek(buf: &[u8]) -> Peek {
    if let Some(&b) = buf.first()
        && b != REC_HANDSHAKE
    {
        return Peek::NotTls;
    }
    let hs = match handshake_bytes(buf) {
        Ok(Some(hs)) => hs,
        Ok(None) => return Peek::Incomplete,
        Err(p) => return p,
    };
    match parse_client_hello(&hs[4..]) {
        Ok(sni) => Peek::Hello { sni },
        Err(e) => Peek::Malformed(e),
    }
}

fn parse_client_hello(body: &[u8]) -> Result<Option<Vec<u8>>, &'static str> {
    let mut r = Reader::new(body);
    let legacy = r.u16().ok_or("short version")?;
    if legacy >> 8 != 0x03 {
        return Err("client version");
    }
    r.take(32).ok_or("short random")?;
    let sid = r.u8().ok_or("short session id")? as usize;
    if sid > 32 {
        return Err("session id length");
    }
    r.take(sid).ok_or("short session id")?;
    let cs = r.u16().ok_or("short cipher suites")? as usize;
    if cs < 2 || !cs.is_multiple_of(2) {
        return Err("cipher suites length");
    }
    r.take(cs).ok_or("short cipher suites")?;
    let cm = r.u8().ok_or("short compression")? as usize;
    if cm < 1 {
        return Err("compression methods length");
    }
    r.take(cm).ok_or("short compression")?;
    if r.rest() == 0 {
        return Ok(None); // no extensions (pre-TLS 1.2 style)
    }
    let ext_len = r.u16().ok_or("short extensions")? as usize;
    if ext_len != r.rest() {
        return Err("extensions length mismatch");
    }
    let mut seen = std::collections::HashSet::new();
    let mut sni = None;
    while r.rest() > 0 {
        let ty = r.u16().ok_or("short extension type")?;
        let len = r.u16().ok_or("short extension length")? as usize;
        let data = r.take(len).ok_or("short extension data")?;
        if !seen.insert(ty) {
            return Err("duplicate extension");
        }
        if ty == EXT_SERVER_NAME {
            sni = Some(parse_server_name(data)?);
        }
    }
    Ok(sni)
}

fn parse_server_name(data: &[u8]) -> Result<Vec<u8>, &'static str> {
    let mut r = Reader::new(data);
    let list = r.u16().ok_or("short server_name list")? as usize;
    if list == 0 || list != r.rest() {
        return Err("server_name list length");
    }
    let mut host = None;
    while r.rest() > 0 {
        let ty = r.u8().ok_or("short name type")?;
        let len = r.u16().ok_or("short name length")? as usize;
        let name = r.take(len).ok_or("short name")?;
        if ty != 0 {
            return Err("unknown server_name type");
        }
        if len == 0 {
            return Err("empty host_name");
        }
        if host.replace(name.to_vec()).is_some() {
            return Err("duplicate host_name");
        }
    }
    host.ok_or("no host_name")
}

/// Build a minimal ClientHello carrying `sni` (for tests and probes).
pub fn synthetic_client_hello(sni: Option<&[u8]>) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend([0x03, 0x03]);
    body.extend([0x11; 32]);
    body.push(0); // session id
    body.extend([0x00, 0x02, 0x13, 0x01]); // one cipher suite
    body.extend([0x01, 0x00]); // null compression
    let mut exts = Vec::new();
    if let Some(name) = sni {
        let mut sn = Vec::new();
        sn.push(0);
        sn.extend((name.len() as u16).to_be_bytes());
        sn.extend(name);
        let mut data = Vec::new();
        data.extend((sn.len() as u16).to_be_bytes());
        data.extend(sn);
        exts.extend(EXT_SERVER_NAME.to_be_bytes());
        exts.extend((data.len() as u16).to_be_bytes());
        exts.extend(data);
    }
    // supported_versions: TLS 1.3
    exts.extend([0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04]);
    body.extend((exts.len() as u16).to_be_bytes());
    body.extend(exts);
    let mut hs = vec![HS_CLIENT_HELLO];
    hs.extend(&(body.len() as u32).to_be_bytes()[1..]);
    hs.extend(body);
    let mut rec = vec![REC_HANDSHAKE, 0x03, 0x01];
    rec.extend((hs.len() as u16).to_be_bytes());
    rec.extend(hs);
    rec
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_sni() {
        let h = synthetic_client_hello(Some(b"api.github.com"));
        assert_eq!(peek(&h), Peek::Hello { sni: Some(b"api.github.com".to_vec()) });
        assert_eq!(peek(&synthetic_client_hello(None)), Peek::Hello { sni: None });
    }

    #[test]
    fn incomplete_prefixes() {
        let h = synthetic_client_hello(Some(b"example.com"));
        for n in 1..h.len() {
            assert_eq!(peek(&h[..n]), Peek::Incomplete, "prefix {n}");
        }
        assert_eq!(peek(&[]), Peek::Incomplete);
    }

    #[test]
    fn split_across_records() {
        let h = synthetic_client_hello(Some(b"example.com"));
        let hs = &h[5..];
        let (a, b) = hs.split_at(10);
        let mut two = vec![0x16, 0x03, 0x01];
        two.extend((a.len() as u16).to_be_bytes());
        two.extend(a);
        two.extend([0x16, 0x03, 0x01]);
        two.extend((b.len() as u16).to_be_bytes());
        two.extend(b);
        assert_eq!(peek(&two), Peek::Hello { sni: Some(b"example.com".to_vec()) });
    }

    #[test]
    fn not_tls_and_malformed() {
        assert_eq!(peek(b"GET / HTTP/1.1\r\n"), Peek::NotTls);
        assert_eq!(peek(b"SSH-2.0-OpenSSH_9.6\r\n"), Peek::NotTls);
        assert_eq!(peek(&[5, 1, 0]), Peek::NotTls);
        let mut dup = synthetic_client_hello(Some(b"a.com"));
        // Append a second server_name extension by rebuilding with two.
        let ext_start = 5 + 4 + 2 + 32 + 1 + 4 + 2;
        let ext_len = u16::from_be_bytes([dup[ext_start], dup[ext_start + 1]]) as usize;
        let sn_ext: Vec<u8> = dup[ext_start + 2..ext_start + 2 + 4 + 2 + 3 + 5].to_vec();
        dup.extend(&sn_ext);
        let new_ext_len = (ext_len + sn_ext.len()) as u16;
        dup[ext_start..ext_start + 2].copy_from_slice(&new_ext_len.to_be_bytes());
        let hs_len = dup.len() - 9;
        dup[6..9].copy_from_slice(&(hs_len as u32).to_be_bytes()[1..]);
        let rec_len = (dup.len() - 5) as u16;
        dup[3..5].copy_from_slice(&rec_len.to_be_bytes());
        assert_eq!(peek(&dup), Peek::Malformed("duplicate extension"));
    }
}

#[cfg(test)]
mod props {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(1024))]

        /// Never panics on arbitrary input.
        #[test]
        fn total(buf in proptest::collection::vec(any::<u8>(), 0..600)) {
            let _ = peek(&buf);
        }

        /// Round trip: any SNI we encode, we decode identically.
        #[test]
        fn round_trip(name in proptest::collection::vec(any::<u8>(), 1..200)) {
            let h = synthetic_client_hello(Some(&name));
            prop_assert_eq!(peek(&h), Peek::Hello { sni: Some(name) });
        }

        /// Single-byte corruption never yields a *different* SNI silently
        /// unless the corruption landed inside the name itself.
        #[test]
        fn corruption_is_detected_or_localised(idx in 0usize..80, flip in 1u8..=255) {
            let name = b"example.com";
            let mut h = synthetic_client_hello(Some(name));
            let i = idx % h.len();
            h[i] ^= flip;
            if let Peek::Hello { sni: Some(s) } = peek(&h)
                && s != name {
                    let start = h.len() - 7 - name.len();
                    prop_assert!(i >= start && i < start + name.len());
                }
        }
    }
}

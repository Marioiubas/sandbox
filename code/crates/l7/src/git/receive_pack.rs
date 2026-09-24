//! The `git-receive-pack` request body (gitprotocol-pack, "Reference Update
//! Request"): optional `shallow` lines, the command list
//! `old-oid SP new-oid SP refname` (capabilities after a NUL on the first),
//! a flush, optional push options and a flush, then the packfile.
//! Signed pushes (`push-cert`) are refused: fail closed on what is not parsed.

use super::pktline::{self, Pkt, PktError};
use policy::repo::valid_refname;

pub const MAX_COMMANDS: usize = 1000;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PushCommand {
    pub old: String,
    pub new: String,
    pub refname: String,
}

impl PushCommand {
    pub fn is_create(&self) -> bool {
        is_null(&self.old)
    }
    pub fn is_delete(&self) -> bool {
        is_null(&self.new)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceivePack<'a> {
    pub commands: Vec<PushCommand>,
    pub capabilities: Vec<String>,
    pub push_options: Vec<String>,
    /// Bytes after the command list (and push options): the packfile, or
    /// empty when every command deletes.
    pub pack: &'a [u8],
}

impl ReceivePack<'_> {
    pub fn has_cap(&self, c: &str) -> bool {
        self.capabilities.iter().any(|x| x == c)
    }
    /// SHA-256 repositories use 64-hex object IDs.
    pub fn oid_len(&self) -> usize {
        self.commands.first().map(|c| c.old.len()).unwrap_or(40)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RpError {
    Pkt(PktError),
    NoCommands,
    TooManyCommands,
    PushCertUnsupported,
    BadCommand(&'static str),
    BadRefname,
}

impl From<PktError> for RpError {
    fn from(e: PktError) -> Self {
        RpError::Pkt(e)
    }
}

pub fn is_null(oid: &str) -> bool {
    oid.bytes().all(|b| b == b'0')
}

fn oid_ok(s: &str) -> bool {
    (s.len() == 40 || s.len() == 64) && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn text(d: &[u8]) -> Result<&str, RpError> {
    let d = d.strip_suffix(b"\n").unwrap_or(d);
    std::str::from_utf8(d).map_err(|_| RpError::BadCommand("not UTF-8"))
}

pub fn parse(body: &[u8]) -> Result<ReceivePack<'_>, RpError> {
    let mut i = 0;
    let mut commands = Vec::new();
    let mut capabilities = Vec::new();
    loop {
        let (p, n) = pktline::read(&body[i..])?;
        i += n;
        let d = match p {
            Pkt::Flush => break,
            Pkt::Data(d) => d,
            Pkt::Delim | Pkt::ResponseEnd => return Err(RpError::BadCommand("unexpected special packet")),
        };
        if d.starts_with(b"push-cert") {
            return Err(RpError::PushCertUnsupported);
        }
        if commands.is_empty() && d.starts_with(b"shallow ") {
            let oid = text(&d[8..])?;
            if !oid_ok(oid) {
                return Err(RpError::BadCommand("bad shallow oid"));
            }
            continue;
        }
        let (line, caps) = match d.iter().position(|&b| b == 0) {
            Some(z) if commands.is_empty() => (&d[..z], Some(&d[z + 1..])),
            Some(_) => return Err(RpError::BadCommand("NUL after the first command")),
            None => (d, None),
        };
        if let Some(c) = caps {
            capabilities = text(c)?.split_ascii_whitespace().map(str::to_string).collect();
        }
        let line = text(line)?;
        let mut parts = line.splitn(3, ' ');
        let (old, new, refname) = match (parts.next(), parts.next(), parts.next()) {
            (Some(o), Some(n), Some(r)) => (o, n, r),
            _ => return Err(RpError::BadCommand("expected old new ref")),
        };
        if !oid_ok(old) || !oid_ok(new) || old.len() != new.len() {
            return Err(RpError::BadCommand("bad object id"));
        }
        if !commands.is_empty() && old.len() != commands.first().map(|c: &PushCommand| c.old.len()).unwrap_or(40) {
            return Err(RpError::BadCommand("mixed object formats"));
        }
        if is_null(old) && is_null(new) {
            return Err(RpError::BadCommand("null to null"));
        }
        if !valid_refname(refname) {
            return Err(RpError::BadRefname);
        }
        if commands.len() == MAX_COMMANDS {
            return Err(RpError::TooManyCommands);
        }
        commands.push(PushCommand { old: old.into(), new: new.into(), refname: refname.into() });
    }
    if commands.is_empty() {
        return Err(RpError::NoCommands);
    }
    let mut push_options = Vec::new();
    if capabilities.iter().any(|c| c == "push-options") {
        loop {
            let (p, n) = pktline::read(&body[i..])?;
            i += n;
            match p {
                Pkt::Flush => break,
                Pkt::Data(d) => push_options.push(text(d)?.to_string()),
                _ => return Err(RpError::BadCommand("unexpected special packet in push options")),
            }
            if push_options.len() > MAX_COMMANDS {
                return Err(RpError::TooManyCommands);
            }
        }
    }
    Ok(ReceivePack { commands, capabilities, push_options, pack: &body[i..] })
}

/// A `report-status` answer rejecting every ref, so `git push` prints
/// `! [remote rejected] <ref> (<msg>)`. With `side-band-64k` the report
/// travels in band 1 and `note` is shown as a `remote:` line (band 2).
pub fn rejection(capabilities: &[String], rejected: &[(String, String)], note: &str) -> Vec<u8> {
    let mut report = Vec::new();
    pktline::write(&mut report, b"unpack ok\n");
    for (r, msg) in rejected {
        let msg: String = msg.chars().filter(|c| !c.is_control()).collect();
        pktline::write(&mut report, format!("ng {r} {msg}\n").as_bytes());
    }
    pktline::flush(&mut report);
    if !capabilities.iter().any(|c| c == "side-band-64k" || c == "side-band") {
        return report;
    }
    let max = if capabilities.iter().any(|c| c == "side-band-64k") { 65515 } else { 995 };
    let mut out = Vec::new();
    for line in note.lines() {
        let mut d = vec![2u8];
        d.extend_from_slice(line.as_bytes());
        d.push(b'\n');
        d.truncate(max + 1);
        pktline::write(&mut out, &d);
    }
    for chunk in report.chunks(max) {
        let mut d = vec![1u8];
        d.extend_from_slice(chunk);
        pktline::write(&mut out, &d);
    }
    pktline::flush(&mut out);
    out
}

/// Whether the client asked for a status report at all.
pub fn wants_report(capabilities: &[String]) -> bool {
    capabilities.iter().any(|c| c == "report-status" || c == "report-status-v2")
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    const A: &str = "1111111111111111111111111111111111111111";
    const B: &str = "2222222222222222222222222222222222222222";
    const Z: &str = "0000000000000000000000000000000000000000";

    fn body(lines: &[&[u8]], pack: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        for l in lines {
            pktline::write(&mut v, l);
        }
        pktline::flush(&mut v);
        v.extend_from_slice(pack);
        v
    }

    #[test]
    fn command_list() {
        let first = format!("{A} {B} refs/heads/agent/x\0 report-status side-band-64k agent=git/2.47");
        let second = format!("{Z} {B} refs/heads/agent/new\n");
        let third = format!("{A} {Z} refs/heads/old");
        let b = body(&[first.as_bytes(), second.as_bytes(), third.as_bytes()], b"PACKDATA");
        let rp = parse(&b).unwrap();
        assert_eq!(rp.commands.len(), 3);
        assert_eq!(rp.commands[0].refname, "refs/heads/agent/x");
        assert!(rp.commands[1].is_create());
        assert!(rp.commands[2].is_delete());
        assert!(rp.has_cap("side-band-64k") && rp.has_cap("report-status"));
        assert_eq!(rp.pack, b"PACKDATA");
    }

    #[test]
    fn shallow_and_push_options() {
        let shallow = format!("shallow {A}");
        let first = format!("{A} {B} refs/heads/x\0push-options");
        let mut b = Vec::new();
        pktline::write(&mut b, shallow.as_bytes());
        pktline::write(&mut b, first.as_bytes());
        pktline::flush(&mut b);
        pktline::write(&mut b, b"ci.skip");
        pktline::flush(&mut b);
        b.extend_from_slice(b"PACK");
        let rp = parse(&b).unwrap();
        assert_eq!(rp.push_options, vec!["ci.skip"]);
        assert_eq!(rp.pack, b"PACK");
    }

    #[test]
    fn strict_rejections() {
        let cases: Vec<(Vec<u8>, RpError)> = vec![
            (body(&[], b""), RpError::NoCommands),
            (body(&[b"push-cert\0report-status"], b""), RpError::PushCertUnsupported),
            (body(&[format!("{A} {B}").as_bytes()], b""), RpError::BadCommand("expected old new ref")),
            (body(&[format!("{A} {} refs/heads/x", &B[..39]).as_bytes()], b""), RpError::BadCommand("bad object id")),
            (
                body(&[format!("{A} ABCDEF0123456789ABCDEF0123456789ABCDEF01 refs/heads/x").as_bytes()], b""),
                RpError::BadCommand("bad object id"),
            ),
            (body(&[format!("{Z} {Z} refs/heads/x").as_bytes()], b""), RpError::BadCommand("null to null")),
            (body(&[format!("{A} {B} refs/heads/a..b").as_bytes()], b""), RpError::BadRefname),
            (body(&[format!("{A} {B} main").as_bytes()], b""), RpError::BadRefname),
            (body(&[format!("{A} {B} refs/heads/x y").as_bytes()], b""), RpError::BadRefname),
            (
                body(
                    &[format!("{A} {B} refs/heads/x").as_bytes(), format!("{A} {B} refs/heads/y\0caps").as_bytes()],
                    b"",
                ),
                RpError::BadCommand("NUL after the first command"),
            ),
        ];
        for (b, want) in cases {
            assert_eq!(parse(&b).unwrap_err(), want, "{}", String::from_utf8_lossy(&b));
        }
        let truncated = &body(&[format!("{A} {B} refs/heads/x").as_bytes()], b"")[..20];
        assert_eq!(parse(truncated).unwrap_err(), RpError::Pkt(PktError::Truncated));
        let no_flush = {
            let mut v = Vec::new();
            pktline::write(&mut v, format!("{A} {B} refs/heads/x").as_bytes());
            v
        };
        assert_eq!(parse(&no_flush).unwrap_err(), RpError::Pkt(PktError::Truncated), "a flush is required");
    }

    #[test]
    fn rejection_report_shapes() {
        let refs = vec![("refs/heads/main".to_string(), "broker denied".to_string())];
        let plain = rejection(&["report-status".into()], &refs, "note");
        assert_eq!(plain, b"000eunpack ok\n0025ng refs/heads/main broker denied\n0000");
        let sb = rejection(&["report-status".into(), "side-band-64k".into()], &refs, "broker: see why");
        let (p, n) = pktline::read(&sb).unwrap();
        assert_eq!(p, Pkt::Data(b"\x02broker: see why\n"));
        let (p, _) = pktline::read(&sb[n..]).unwrap();
        match p {
            Pkt::Data(d) => {
                assert_eq!(d[0], 1);
                assert_eq!(&d[1..], plain.as_slice());
            }
            other => panic!("{other:?}"),
        }
        assert!(sb.ends_with(b"0000"));
    }

    proptest! {
        #[test]
        fn parse_never_panics(b in proptest::collection::vec(any::<u8>(), 0..300)) {
            let _ = parse(&b);
        }

        #[test]
        fn refnames_round_trip(name in "[a-z]{1,8}(/[a-z0-9-]{1,8}){0,3}") {
            let line = format!("{A} {B} refs/heads/{name}");
            let b = body(&[line.as_bytes()], b"");
            let rp = parse(&b).unwrap();
            prop_assert_eq!(&rp.commands[0].refname, &format!("refs/heads/{name}"));
        }
    }
}

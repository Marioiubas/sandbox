//! Just enough of the packfile format (gitformat-pack) to learn the commit
//! graph a push carries: object headers, zlib streams, OFS/REF deltas whose
//! base is a commit, and the trailing SHA-1. Everything else is inflated
//! and discarded. Limits bound memory and work; exceeding one is an error,
//! and an error makes every non-create update count as a force push.

use flate2::{Decompress, FlushDecompress, Status};
use sha1::{Digest, Sha1};
use std::collections::HashMap;

pub type Oid = [u8; 20];

#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub max_objects: u32,
    /// Largest inflated object considered (commits and deltas are kept).
    pub max_object: usize,
    /// Total bytes of commit/delta data kept for resolution.
    pub max_kept: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Limits { max_objects: 2_000_000, max_object: 64 << 20, max_kept: 64 << 20 }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PackError {
    BadHeader,
    Truncated,
    BadObject(&'static str),
    Zlib,
    Checksum,
    Limit(&'static str),
    TrailingBytes,
}

/// Commits found in the pack: oid → parents.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CommitGraph {
    pub commits: HashMap<Oid, Vec<Oid>>,
    /// Deltas whose base was not a commit found in the pack (thin-pack
    /// bases upstream, or tree/blob deltas): their type is unknown.
    pub unresolved_deltas: usize,
}

enum Raw {
    Commit(Vec<u8>),
    OfsDelta { base_offset: usize, delta: Vec<u8> },
    RefDelta { base: Oid, delta: Vec<u8> },
}

fn inflate(data: &[u8], expect: usize, keep: bool, limits: &Limits) -> Result<(Option<Vec<u8>>, usize), PackError> {
    if expect > limits.max_object {
        return Err(PackError::Limit("object too large"));
    }
    let mut z = Decompress::new(true);
    let mut out = Vec::with_capacity(if keep { expect } else { expect.min(64 << 10) });
    let mut scratch = vec![0u8; 64 << 10];
    let mut produced = 0usize;
    loop {
        let before_in = z.total_in() as usize;
        let before_out = z.total_out() as usize;
        let status = z
            .decompress(&data[before_in.min(data.len())..], &mut scratch, FlushDecompress::None)
            .map_err(|_| PackError::Zlib)?;
        let got = z.total_out() as usize - before_out;
        produced += got;
        if produced > expect {
            return Err(PackError::BadObject("inflated size exceeds header size"));
        }
        if keep {
            out.extend_from_slice(&scratch[..got]);
        }
        match status {
            Status::StreamEnd => break,
            Status::Ok | Status::BufError => {
                if z.total_in() as usize == before_in && got == 0 {
                    return Err(PackError::Truncated);
                }
            }
        }
    }
    if produced != expect {
        return Err(PackError::BadObject("inflated size differs from header size"));
    }
    Ok((keep.then_some(out), z.total_in() as usize))
}

fn commit_oid(data: &[u8]) -> Oid {
    let mut h = Sha1::new();
    h.update(format!("commit {}\0", data.len()).as_bytes());
    h.update(data);
    h.finalize().into()
}

fn hex_oid(s: &[u8]) -> Option<Oid> {
    let mut o = [0u8; 20];
    hex::decode_to_slice(s, &mut o).ok()?;
    Some(o)
}

/// `tree <oid>\n(parent <oid>\n)*...`
pub fn commit_parents(data: &[u8]) -> Result<Vec<Oid>, PackError> {
    let mut lines = data.split(|&b| b == b'\n');
    let tree = lines.next().ok_or(PackError::BadObject("empty commit"))?;
    if !(tree.len() == 45 && tree.starts_with(b"tree ") && hex_oid(&tree[5..]).is_some()) {
        return Err(PackError::BadObject("commit without tree"));
    }
    let mut parents = Vec::new();
    for l in lines {
        match l.strip_prefix(b"parent ") {
            Some(h) if h.len() == 40 => parents.push(hex_oid(h).ok_or(PackError::BadObject("bad parent"))?),
            Some(_) => return Err(PackError::BadObject("bad parent")),
            None => break,
        }
    }
    Ok(parents)
}

fn varint(data: &[u8], i: &mut usize) -> Result<usize, PackError> {
    let (mut v, mut shift) = (0usize, 0u32);
    loop {
        let b = *data.get(*i).ok_or(PackError::BadObject("delta header"))?;
        *i += 1;
        if shift > 56 {
            return Err(PackError::BadObject("delta varint too long"));
        }
        v |= ((b & 0x7f) as usize) << shift;
        shift += 7;
        if b & 0x80 == 0 {
            return Ok(v);
        }
    }
}

/// Apply a git delta to `base`.
pub fn apply_delta(base: &[u8], delta: &[u8], limits: &Limits) -> Result<Vec<u8>, PackError> {
    let mut i = 0;
    let src = varint(delta, &mut i)?;
    let dst = varint(delta, &mut i)?;
    if src != base.len() {
        return Err(PackError::BadObject("delta base size mismatch"));
    }
    if dst > limits.max_object {
        return Err(PackError::Limit("delta result too large"));
    }
    let mut out = Vec::with_capacity(dst);
    while i < delta.len() {
        let op = delta[i];
        i += 1;
        if op & 0x80 != 0 {
            let mut off = 0usize;
            let mut size = 0usize;
            for bit in 0..4 {
                if op & (1 << bit) != 0 {
                    off |= (*delta.get(i).ok_or(PackError::BadObject("copy op"))? as usize) << (8 * bit);
                    i += 1;
                }
            }
            for bit in 0..3 {
                if op & (0x10 << bit) != 0 {
                    size |= (*delta.get(i).ok_or(PackError::BadObject("copy op"))? as usize) << (8 * bit);
                    i += 1;
                }
            }
            if size == 0 {
                size = 0x10000;
            }
            let end = off.checked_add(size).ok_or(PackError::BadObject("copy overflow"))?;
            out.extend_from_slice(base.get(off..end).ok_or(PackError::BadObject("copy out of range"))?);
        } else if op != 0 {
            let n = op as usize;
            out.extend_from_slice(delta.get(i..i + n).ok_or(PackError::BadObject("insert out of range"))?);
            i += n;
        } else {
            return Err(PackError::BadObject("reserved delta opcode"));
        }
        if out.len() > dst {
            return Err(PackError::BadObject("delta result too long"));
        }
    }
    if out.len() != dst {
        return Err(PackError::BadObject("delta result size mismatch"));
    }
    Ok(out)
}

/// Parse a SHA-1 packfile and return the commit graph it contains.
pub fn commit_graph(pack: &[u8], limits: &Limits) -> Result<CommitGraph, PackError> {
    if pack.len() < 12 + 20 || &pack[..4] != b"PACK" {
        return Err(PackError::BadHeader);
    }
    let version = u32::from_be_bytes([pack[4], pack[5], pack[6], pack[7]]);
    if version != 2 && version != 3 {
        return Err(PackError::BadHeader);
    }
    let count = u32::from_be_bytes([pack[8], pack[9], pack[10], pack[11]]);
    if count > limits.max_objects {
        return Err(PackError::Limit("too many objects"));
    }
    let body_end = pack.len() - 20;
    let sum: [u8; 20] = Sha1::digest(&pack[..body_end]).into();
    if sum != pack[body_end..] {
        return Err(PackError::Checksum);
    }
    let mut raws: Vec<(usize, Raw)> = Vec::new();
    let mut kept = 0usize;
    let mut i = 12;
    for _ in 0..count {
        let obj_off = i;
        let mut b = *pack.get(i).filter(|_| i < body_end).ok_or(PackError::Truncated)?;
        i += 1;
        let ty = (b >> 4) & 7;
        let mut size = (b & 0x0f) as usize;
        let mut shift = 4;
        while b & 0x80 != 0 {
            b = *pack.get(i).filter(|_| i < body_end).ok_or(PackError::Truncated)?;
            i += 1;
            if shift > 56 {
                return Err(PackError::BadObject("size varint too long"));
            }
            size |= ((b & 0x7f) as usize) << shift;
            shift += 7;
        }
        let kind = match ty {
            1 => 'c',
            2..=4 => 'o',
            6 => {
                let mut c = *pack.get(i).filter(|_| i < body_end).ok_or(PackError::Truncated)?;
                i += 1;
                let mut off = (c & 0x7f) as usize;
                while c & 0x80 != 0 {
                    c = *pack.get(i).filter(|_| i < body_end).ok_or(PackError::Truncated)?;
                    i += 1;
                    off = off.checked_add(1).and_then(|o| o.checked_mul(128)).ok_or(PackError::BadObject("ofs"))?
                        | (c & 0x7f) as usize;
                }
                if off == 0 || off > obj_off {
                    return Err(PackError::BadObject("ofs-delta base out of range"));
                }
                raws.push((obj_off, Raw::OfsDelta { base_offset: obj_off - off, delta: vec![] }));
                'd'
            }
            7 => {
                let base = pack.get(i..i + 20).filter(|_| i + 20 <= body_end).ok_or(PackError::Truncated)?;
                i += 20;
                let mut o = [0u8; 20];
                o.copy_from_slice(base);
                raws.push((obj_off, Raw::RefDelta { base: o, delta: vec![] }));
                'd'
            }
            _ => return Err(PackError::BadObject("unknown object type")),
        };
        let keep = kind != 'o' && kept + size <= limits.max_kept;
        let (data, used) = inflate(&pack[i..body_end], size, keep, limits)?;
        i += used;
        match (kind, data) {
            ('c', Some(d)) => {
                kept += d.len();
                raws.push((obj_off, Raw::Commit(d)));
            }
            ('d', Some(d)) => {
                kept += d.len();
                match raws.last_mut() {
                    Some((_, Raw::OfsDelta { delta, .. })) | Some((_, Raw::RefDelta { delta, .. })) => *delta = d,
                    _ => return Err(PackError::BadObject("delta bookkeeping")),
                }
            }
            ('d', None) => {
                raws.pop(); // over the keep budget: stays unresolved
            }
            ('c', None) => return Err(PackError::Limit("commit data over budget")),
            _ => {}
        }
    }
    if i != body_end {
        return Err(PackError::TrailingBytes);
    }

    // Resolve: commits by offset and oid, then deltas whose base is known.
    let mut by_off: HashMap<usize, Vec<u8>> = HashMap::new();
    let mut by_oid: HashMap<Oid, usize> = HashMap::new();
    let mut graph = CommitGraph::default();
    let mut pending = Vec::new();
    for (off, r) in raws {
        match r {
            Raw::Commit(d) => {
                let oid = commit_oid(&d);
                graph.commits.insert(oid, commit_parents(&d)?);
                by_oid.insert(oid, off);
                by_off.insert(off, d);
            }
            other => pending.push((off, other)),
        }
    }
    loop {
        let mut progress = false;
        let mut rest = Vec::new();
        for (off, r) in pending {
            let base = match &r {
                Raw::OfsDelta { base_offset, .. } => by_off.get(base_offset),
                Raw::RefDelta { base, .. } => by_oid.get(base).and_then(|o| by_off.get(o)),
                Raw::Commit(_) => None,
            };
            match (base, &r) {
                (Some(b), Raw::OfsDelta { delta, .. } | Raw::RefDelta { delta, .. }) => {
                    let d = apply_delta(b, delta, limits)?;
                    let oid = commit_oid(&d);
                    graph.commits.insert(oid, commit_parents(&d)?);
                    by_oid.insert(oid, off);
                    by_off.insert(off, d);
                    progress = true;
                }
                _ => rest.push((off, r)),
            }
        }
        pending = rest;
        if !progress {
            break;
        }
    }
    graph.unresolved_deltas = pending.len();
    Ok(graph)
}

/// How a ref update relates to the old value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UpdateKind {
    Create,
    Delete,
    FastForward,
    /// Ancestry could not be proven from the pack: treated as force.
    Unknown,
}

impl UpdateKind {
    pub fn is_force(&self) -> bool {
        matches!(self, UpdateKind::Delete | UpdateKind::Unknown)
    }
    pub fn as_str(&self) -> &'static str {
        match self {
            UpdateKind::Create => "create",
            UpdateKind::Delete => "delete",
            UpdateKind::FastForward => "fast_forward",
            UpdateKind::Unknown => "not_provably_fast_forward",
        }
    }
}

pub const MAX_WALK: usize = 1_000_000;

/// Fast-forward only if walking parents inside the pack from `new` reaches
/// `old`. A commit outside the pack stops that branch of the walk.
pub fn classify(old_hex: &str, new_hex: &str, graph: Option<&CommitGraph>) -> UpdateKind {
    let null = |s: &str| s.bytes().all(|b| b == b'0');
    if null(new_hex) {
        return UpdateKind::Delete;
    }
    if null(old_hex) {
        return UpdateKind::Create;
    }
    if old_hex == new_hex {
        return UpdateKind::FastForward;
    }
    let (Some(g), Some(old), Some(new)) = (graph, hex_oid(old_hex.as_bytes()), hex_oid(new_hex.as_bytes())) else {
        return UpdateKind::Unknown;
    };
    let mut stack = vec![new];
    let mut seen = std::collections::HashSet::new();
    while let Some(c) = stack.pop() {
        if c == old {
            return UpdateKind::FastForward;
        }
        if !seen.insert(c) || seen.len() > MAX_WALK {
            continue;
        }
        if let Some(ps) = g.commits.get(&c) {
            stack.extend(ps.iter().copied());
        }
    }
    UpdateKind::Unknown
}

#[cfg(test)]
mod tests;

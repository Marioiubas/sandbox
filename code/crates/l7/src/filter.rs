//! Response filter (pipeline step 8, I1): an injected secret, in any of its
//! registered encodings, never flows back to the sandbox. Bodies are
//! scanned as they stream and the tail that could begin a secret is held
//! back, so a secret split across chunks is caught before any of it is
//! released. For identity bodies that is only the longest tail that is a
//! prefix of a needle (streamed events are not delayed); for compressed
//! bodies, whose raw bytes the client decodes, a fixed window of (longest
//! needle - 1) raw bytes. On a match the body errors out and the
//! connection is cut.
//! gzip and deflate bodies are scanned through a parallel decoder; other
//! encodings cannot be scanned and are refused before headers are sent.

use bytes::Bytes;
use http::HeaderMap;
use http_body::{Body, Frame};
use std::io::Write;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Found;

impl std::fmt::Display for Found {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("response contained an injected secret; cut by the broker")
    }
}
impl std::error::Error for Found {}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && hay.len() >= needle.len() && hay.windows(needle.len()).any(|w| w == needle)
}

/// Streaming exact-match scanner over one byte stream.
pub struct Scanner {
    needles: Arc<Vec<Vec<u8>>>,
    keep: usize,
    tail: Vec<u8>,
    /// Hold back only a tail that could begin a needle, not a fixed window.
    minimal: bool,
}

impl Scanner {
    /// Holds back a fixed window of (longest needle - 1) bytes.
    pub fn new(needles: Arc<Vec<Vec<u8>>>) -> Scanner {
        let keep = needles.iter().map(|n| n.len()).max().unwrap_or(1).saturating_sub(1);
        Scanner { needles, keep, tail: Vec::new(), minimal: false }
    }

    /// Holds back only the longest tail that is a proper prefix of a needle.
    /// Safe for bytes the client sees as they are: a needle that is not
    /// wholly inside the scanned bytes and starts before that tail would
    /// make a longer tail a prefix of it.
    pub fn minimal(needles: Arc<Vec<Vec<u8>>>) -> Scanner {
        Scanner { minimal: true, ..Scanner::new(needles) }
    }

    /// Length of the longest suffix of `buf` that is a proper prefix of a needle.
    fn partial(&self, buf: &[u8]) -> usize {
        let longest = |n: &Vec<u8>| {
            let max = n.len().saturating_sub(1).min(buf.len());
            (1..=max).rev().find(|&l| buf.ends_with(&n[..l])).unwrap_or(0)
        };
        self.needles.iter().map(longest).max().unwrap_or(0)
    }

    /// Feed a chunk; returns the bytes that are now safe to release.
    pub fn feed(&mut self, chunk: &[u8]) -> Result<Vec<u8>, Found> {
        let mut buf = std::mem::take(&mut self.tail);
        buf.extend_from_slice(chunk);
        if self.needles.iter().any(|n| contains(&buf, n)) {
            return Err(Found);
        }
        let cut = if self.minimal { buf.len() - self.partial(&buf) } else { buf.len().saturating_sub(self.keep) };
        self.tail = buf.split_off(cut);
        Ok(buf)
    }

    /// End of stream: release the held-back tail (already scanned).
    pub fn finish(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.tail)
    }
}

/// Whether any needle appears in `hay`.
pub fn bytes_contain(hay: &[u8], needles: &[Vec<u8>]) -> bool {
    needles.iter().any(|n| contains(hay, n))
}

/// Whether any needle appears in any header value.
pub fn headers_contain(h: &HeaderMap, needles: &[Vec<u8>]) -> bool {
    h.values().any(|v| needles.iter().any(|n| contains(v.as_bytes(), n)))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Coding {
    Identity,
    Gzip,
    Deflate,
}

/// The body coding from `Content-Encoding`; `None` if it cannot be scanned.
pub fn coding(h: &HeaderMap) -> Option<Coding> {
    let mut vals = h.get_all(http::header::CONTENT_ENCODING).iter();
    match (vals.next(), vals.next()) {
        (None, _) => Some(Coding::Identity),
        (Some(v), None) => match v.to_str().ok()?.trim().to_ascii_lowercase().as_str() {
            "identity" | "" => Some(Coding::Identity),
            "gzip" | "x-gzip" => Some(Coding::Gzip),
            "deflate" => Some(Coding::Deflate),
            _ => None,
        },
        _ => None,
    }
}

enum Decoder {
    Gzip(flate2::write::GzDecoder<Vec<u8>>),
    Deflate(flate2::write::ZlibDecoder<Vec<u8>>),
}

/// Upper bound on decoded bytes produced per input chunk (bomb guard).
const MAX_DECODED_PER_CHUNK: usize = 64 << 20;

/// Wraps a response body; scans the raw bytes and, for gzip/deflate, the
/// decoded bytes too. `cut` is set when a secret was found.
pub struct FilteredBody<B> {
    inner: B,
    raw: Scanner,
    decoded: Option<(Decoder, Scanner)>,
    trailer_needles: Arc<Vec<Vec<u8>>>,
    pending_trailers: Option<Frame<Bytes>>,
    done: bool,
    pub cut: Arc<AtomicBool>,
}

impl<B> FilteredBody<B> {
    pub fn new(inner: B, needles: Arc<Vec<Vec<u8>>>, coding: Coding, cut: Arc<AtomicBool>) -> Self {
        let decoded = match coding {
            Coding::Identity => None,
            Coding::Gzip => {
                Some((Decoder::Gzip(flate2::write::GzDecoder::new(Vec::new())), Scanner::new(needles.clone())))
            }
            Coding::Deflate => {
                Some((Decoder::Deflate(flate2::write::ZlibDecoder::new(Vec::new())), Scanner::new(needles.clone())))
            }
        };
        FilteredBody {
            inner,
            raw: match coding {
                Coding::Identity => Scanner::minimal(needles.clone()),
                Coding::Gzip | Coding::Deflate => Scanner::new(needles.clone()),
            },
            decoded,
            trailer_needles: needles,
            pending_trailers: None,
            done: false,
            cut,
        }
    }

    /// Scan the decoded form of `chunk`; `end` finishes the stream.
    fn scan_decoded(&mut self, chunk: &[u8], end: bool) -> Result<(), Found> {
        let Some((dec, sc)) = self.decoded.as_mut() else { return Ok(()) };
        let out = match dec {
            Decoder::Gzip(d) => d
                .write_all(chunk)
                .and_then(|_| if end { d.try_finish() } else { d.flush() })
                .map(|_| std::mem::take(d.get_mut())),
            Decoder::Deflate(d) => d
                .write_all(chunk)
                .and_then(|_| if end { d.try_finish() } else { d.flush() })
                .map(|_| std::mem::take(d.get_mut())),
        };
        // Undecodable or oversized: cannot prove the body clean.
        let out = out.map_err(|_| Found)?;
        if out.len() > MAX_DECODED_PER_CHUNK {
            return Err(Found);
        }
        sc.feed(&out).map(|_| ())
    }
}

pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

impl<B> Body for FilteredBody<B>
where
    B: Body<Data = Bytes> + Unpin,
    B::Error: Into<BoxError>,
{
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        let this = &mut *self;
        if let Some(t) = this.pending_trailers.take() {
            this.done = true;
            return Poll::Ready(Some(Ok(t)));
        }
        if this.done {
            return Poll::Ready(None);
        }
        loop {
            match Pin::new(&mut this.inner).poll_frame(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Some(Err(e))) => {
                    this.done = true;
                    return Poll::Ready(Some(Err(e.into())));
                }
                Poll::Ready(Some(Ok(frame))) => {
                    if let Some(data) = frame.data_ref() {
                        let res = this.raw.feed(data).and_then(|safe| this.scan_decoded(data, false).map(|_| safe));
                        match res {
                            Ok(safe) if safe.is_empty() => continue,
                            Ok(safe) => return Poll::Ready(Some(Ok(Frame::data(Bytes::from(safe))))),
                            Err(f) => {
                                this.done = true;
                                this.cut.store(true, Ordering::SeqCst);
                                return Poll::Ready(Some(Err(Box::new(f))));
                            }
                        }
                    }
                    if let Some(t) = frame.trailers_ref() {
                        if headers_contain(t, &this.trailer_needles) {
                            this.done = true;
                            this.cut.store(true, Ordering::SeqCst);
                            return Poll::Ready(Some(Err(Box::new(Found))));
                        }
                        if let Err(f) = this.scan_decoded(&[], true) {
                            this.done = true;
                            this.cut.store(true, Ordering::SeqCst);
                            return Poll::Ready(Some(Err(Box::new(f))));
                        }
                        // Release the held-back (already scanned) bytes, then the trailers.
                        let tail = this.raw.finish();
                        if tail.is_empty() {
                            this.done = true;
                            return Poll::Ready(Some(Ok(frame)));
                        }
                        this.pending_trailers = Some(frame);
                        return Poll::Ready(Some(Ok(Frame::data(Bytes::from(tail)))));
                    }
                    continue;
                }
                Poll::Ready(None) => {
                    this.done = true;
                    if let Err(f) = this.scan_decoded(&[], true) {
                        this.cut.store(true, Ordering::SeqCst);
                        return Poll::Ready(Some(Err(Box::new(f))));
                    }
                    let tail = this.raw.finish();
                    return if tail.is_empty() {
                        Poll::Ready(None)
                    } else {
                        Poll::Ready(Some(Ok(Frame::data(Bytes::from(tail)))))
                    };
                }
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.done
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt;
    use proptest::prelude::*;

    fn needles(n: &[&str]) -> Arc<Vec<Vec<u8>>> {
        Arc::new(n.iter().map(|s| s.as_bytes().to_vec()).collect())
    }

    struct Chunks(std::collections::VecDeque<Frame<Bytes>>);
    impl Body for Chunks {
        type Data = Bytes;
        type Error = std::convert::Infallible;
        fn poll_frame(
            mut self: Pin<&mut Self>,
            _: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
            Poll::Ready(self.0.pop_front().map(Ok))
        }
    }

    async fn run(chunks: Vec<&[u8]>, n: &[&str], coding: Coding) -> (Result<Vec<u8>, ()>, bool) {
        let frames = chunks.into_iter().map(|c| Frame::data(Bytes::copy_from_slice(c))).collect();
        let cut = Arc::new(AtomicBool::new(false));
        let body = FilteredBody::new(Chunks(frames), needles(n), coding, cut.clone());
        let r = body.collect().await.map(|c| c.to_bytes().to_vec()).map_err(|_| ());
        (r, cut.load(Ordering::SeqCst))
    }

    #[tokio::test]
    async fn body_filtering() {
        let (r, cut) = run(vec![b"abc SEC", b"RET-TOKEN def"], &["SECRET-TOKEN"], Coding::Identity).await;
        assert!(r.is_err() && cut);
        let (r, cut) = run(vec![b"abc ", b"def"], &["SECRET-TOKEN"], Coding::Identity).await;
        assert_eq!((r.unwrap(), cut), (b"abc def".to_vec(), false));
        // Inside a gzip body.
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gz.write_all(b"{\"echo\":\"SECRET-TOKEN\"}").unwrap();
        let z = gz.finish().unwrap();
        let (a, b) = z.split_at(z.len() / 2);
        let (r, cut) = run(vec![a, b], &["SECRET-TOKEN"], Coding::Gzip).await;
        assert!(r.is_err() && cut, "secrets inside gzip bodies are found");
        let (r, cut) = run(vec![b"not gzip at all"], &["SECRET-TOKEN"], Coding::Gzip).await;
        assert!(r.is_err() && cut, "an undecodable body cannot be proven clean");
    }

    #[test]
    fn scanner_catches_split_secrets() {
        let mut s = Scanner::new(needles(&["SECRET-TOKEN"]));
        let mut out = s.feed(b"hello SECR").unwrap();
        assert!(!out.windows(4).any(|w| w == b"SECR"), "the prefix is held back");
        assert_eq!(s.feed(b"ET-TOKEN tail"), Err(Found));
        let mut s = Scanner::new(needles(&["SECRET-TOKEN"]));
        out = s.feed(b"harmless ").unwrap();
        out.extend(s.feed(b"content").unwrap());
        out.extend(s.finish());
        assert_eq!(out, b"harmless content");
    }

    #[test]
    fn encodings() {
        let mut h = HeaderMap::new();
        assert_eq!(coding(&h), Some(Coding::Identity));
        h.insert("content-encoding", "gzip".parse().unwrap());
        assert_eq!(coding(&h), Some(Coding::Gzip));
        h.insert("content-encoding", "br".parse().unwrap());
        assert_eq!(coding(&h), None);
        h.append("content-encoding", "gzip".parse().unwrap());
        assert_eq!(coding(&h), None, "stacked codings are not scanned");
        let mut t = HeaderMap::new();
        t.insert("x-echo", "Bearer SECRET-TOKEN".parse().unwrap());
        assert!(headers_contain(&t, &needles(&["SECRET-TOKEN"])));
    }

    proptest! {
        /// However the body is chunked, a secret is never released, and a
        /// clean body is released unchanged.
        #[test]
        fn chunking_never_leaks(prefix in "[a-z ]{0,40}", suffix in "[a-z ]{0,40}", cuts in proptest::collection::vec(0usize..100, 0..6), with_secret in any::<bool>()) {
            let secret = "sk-CANARY-1234567890";
            let body = if with_secret { format!("{prefix}{secret}{suffix}") } else { format!("{prefix}{suffix}") };
            let bytes = body.as_bytes();
            let mut idx: Vec<usize> = cuts.iter().map(|c| c % (bytes.len() + 1)).collect();
            idx.sort();
            idx.dedup();
            let mut s = Scanner::new(needles(&[secret]));
            let mut released = Vec::new();
            let mut last = 0;
            let mut found = false;
            for &i in idx.iter().chain(std::iter::once(&bytes.len())) {
                match s.feed(&bytes[last..i]) {
                    Ok(out) => released.extend(out),
                    Err(Found) => { found = true; break; }
                }
                last = i;
            }
            if !found { released.extend(s.finish()); }
            prop_assert_eq!(found, with_secret);
            prop_assert!(!contains(&released, secret.as_bytes()));
            if !with_secret { prop_assert_eq!(released, bytes.to_vec()); }
        }

        /// Over a two-letter alphabet (so partial matches abound), in both
        /// modes and however the body is chunked: nothing at or after the
        /// first occurrence of a needle is ever released, a clean body is
        /// released unchanged, and the minimal mode never releases less.
        #[test]
        fn nothing_of_a_secret_is_released(body in "[ab]{0,40}", needle in "[ab]{2,7}", cuts in proptest::collection::vec(0usize..64, 0..8)) {
            let bytes = body.as_bytes();
            let first = bytes.windows(needle.len()).position(|w| w == needle.as_bytes());
            let mut idx: Vec<usize> = cuts.iter().map(|c| c % (bytes.len() + 1)).collect();
            idx.sort();
            idx.dedup();
            let mut fixed = Scanner::new(needles(&[&needle]));
            let mut minimal = Scanner::minimal(needles(&[&needle]));
            let (mut out_f, mut out_m, mut last) = (Vec::new(), Vec::new(), 0);
            let mut found = false;
            for &i in idx.iter().chain(std::iter::once(&bytes.len())) {
                match (fixed.feed(&bytes[last..i]), minimal.feed(&bytes[last..i])) {
                    (Ok(f), Ok(m)) => { out_f.extend(f); out_m.extend(m); }
                    (Err(Found), Err(Found)) => { found = true; break; }
                    _ => prop_assert!(false, "modes disagree"),
                }
                prop_assert!(out_m.len() >= out_f.len());
                last = i;
            }
            prop_assert_eq!(found, first.is_some());
            if let Some(s) = first {
                prop_assert!(out_m.len() <= s && out_f.len() <= s, "released {} / {} past {s}", out_m.len(), out_f.len());
            } else {
                out_f.extend(fixed.finish());
                out_m.extend(minimal.finish());
                prop_assert_eq!(&out_f, &bytes.to_vec());
                prop_assert_eq!(&out_m, &bytes.to_vec());
            }
        }
    }

    /// Streamed events (SSE) through an identity body are released as they
    /// arrive: none of them is a prefix of the secret.
    #[test]
    fn streamed_events_are_not_held_back() {
        let mut s = Scanner::minimal(needles(&["sk-ant-oat01-SECRET0123456789"]));
        for ev in ["data: {\"t\":\"Hel\"}\n\n", "data: {\"t\":\"lo\"}\n\n", "data: s"] {
            let out = s.feed(ev.as_bytes()).unwrap();
            if ev == "data: s" {
                assert_eq!(out, b"data: ", "an `s` could begin the secret");
            } else {
                assert_eq!(out, ev.as_bytes());
            }
        }
        assert_eq!(s.finish(), b"s");
    }
}

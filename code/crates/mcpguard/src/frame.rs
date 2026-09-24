//! Newline-delimited JSON-RPC 2.0 (the MCP stdio transport): a splitter
//! that bounds every frame, and a strict classifier. Anything that is not
//! one JSON object with `"jsonrpc": "2.0"` is malformed; batches (arrays)
//! are malformed too.

use serde_json::Value;

/// Largest frame accepted in either direction.
pub const MAX_FRAME: usize = 1 << 20;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Frame {
    Line(Vec<u8>),
    /// A line longer than `MAX_FRAME` (its bytes are discarded).
    TooLong,
}

/// Incremental splitter: feed chunks, get complete frames.
#[derive(Debug, Default)]
pub struct Lines {
    buf: Vec<u8>,
    over: bool,
}

impl Lines {
    /// Feed bytes; returns the frames they complete.
    pub fn push(&mut self, mut chunk: &[u8]) -> Vec<Frame> {
        let mut out = Vec::new();
        while let Some(i) = chunk.iter().position(|b| *b == b'\n') {
            self.take(&chunk[..i]);
            out.push(self.end());
            chunk = &chunk[i + 1..];
        }
        self.take(chunk);
        out
    }

    /// The last, unterminated frame at end of stream, if any.
    pub fn finish(&mut self) -> Option<Frame> {
        (self.over || !self.buf.is_empty()).then(|| self.end())
    }

    fn take(&mut self, part: &[u8]) {
        if self.over {
            return;
        }
        self.buf.extend_from_slice(part);
        if self.buf.len() > MAX_FRAME {
            self.over = true;
            self.buf = Vec::new();
        }
    }

    fn end(&mut self) -> Frame {
        let over = std::mem::take(&mut self.over);
        let mut line = std::mem::take(&mut self.buf);
        if over {
            return Frame::TooLong;
        }
        if line.last() == Some(&b'\r') {
            line.pop();
        }
        Frame::Line(line)
    }
}

/// What a frame is, by the JSON-RPC 2.0 rules.
#[derive(Clone, Debug, PartialEq)]
pub enum Kind {
    Request { id: Value, method: String },
    Notification { method: String },
    Response { id: Value },
    Malformed,
}

/// Classify a frame strictly. An `id` must be a string or an integer.
pub fn classify(bytes: &[u8]) -> (Kind, Option<Value>) {
    let Ok(v) = serde_json::from_slice::<Value>(bytes) else { return (Kind::Malformed, None) };
    if !v.is_object() || v.get("jsonrpc").and_then(|j| j.as_str()) != Some("2.0") {
        return (Kind::Malformed, None);
    }
    let id = v.get("id").cloned();
    let id_ok = |i: &Value| i.is_string() || i.is_i64() || i.is_u64();
    let method = v.get("method").map(|m| m.as_str().map(str::to_string));
    let kind = match (method, id) {
        (Some(Some(m)), Some(i)) if id_ok(&i) => Kind::Request { id: i, method: m },
        (Some(Some(m)), None) => Kind::Notification { method: m },
        (None, Some(i)) if id_ok(&i) && (v.get("result").is_some() ^ v.get("error").is_some()) => {
            Kind::Response { id: i }
        }
        _ => Kind::Malformed,
    };
    (kind, Some(v))
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn classifies_strictly() {
        let k = |s: &str| classify(s.as_bytes()).0;
        assert!(matches!(k(r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#), Kind::Request { .. }));
        assert!(matches!(k(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#), Kind::Notification { .. }));
        assert!(matches!(k(r#"{"jsonrpc":"2.0","id":"a","result":{}}"#), Kind::Response { .. }));
        for bad in [
            r#"[{"jsonrpc":"2.0","id":1,"method":"ping"}]"#,
            r#"{"jsonrpc":"1.0","id":1,"method":"ping"}"#,
            r#"{"id":1,"method":"ping"}"#,
            r#"{"jsonrpc":"2.0","id":{"x":1},"method":"ping"}"#,
            r#"{"jsonrpc":"2.0","id":1,"method":7}"#,
            r#"{"jsonrpc":"2.0","id":1,"result":{},"error":{}}"#,
            r#"{"jsonrpc":"2.0","id":1}"#,
            "not json",
        ] {
            assert_eq!(k(bad), Kind::Malformed, "{bad}");
        }
    }

    #[test]
    fn oversized_frames_are_dropped_not_split() {
        let mut l = Lines::default();
        let big = vec![b'x'; MAX_FRAME + 5];
        let mut frames = l.push(&big);
        frames.extend(l.push(b"\n{\"a\":1}\n"));
        assert_eq!(frames, vec![Frame::TooLong, Frame::Line(b"{\"a\":1}".to_vec())]);
    }

    proptest! {
        /// However the stream is chunked, the frames are the input's lines.
        #[test]
        fn chunking_never_changes_frames(
            lines in proptest::collection::vec("[ -~]{0,40}", 0..8),
            cuts in proptest::collection::vec(0usize..400, 0..6),
        ) {
            let input: Vec<u8> = lines.iter().flat_map(|l| format!("{l}\n").into_bytes()).collect();
            let mut cuts: Vec<usize> = cuts.into_iter().map(|c| c.min(input.len())).collect();
            cuts.sort();
            let mut l = Lines::default();
            let mut got = Vec::new();
            let mut at = 0;
            for c in cuts.into_iter().chain([input.len()]) {
                got.extend(l.push(&input[at..c]));
                at = c;
            }
            prop_assert_eq!(l.finish(), None);
            let want: Vec<Frame> = lines.iter().map(|x| Frame::Line(x.as_bytes().to_vec())).collect();
            prop_assert_eq!(got, want);
        }
    }
}

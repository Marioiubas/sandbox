//! MCP Guard's pure parts: manifest pinning (canonical digests and diffs of
//! a server's tools) and strict JSON-RPC 2.0 framing for the stdio
//! transport (one message per line). The daemon does the I/O.

pub mod frame;
pub mod manifest;

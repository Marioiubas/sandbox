//! The L4 fast path: after admission and the SNI check, relay bytes both ways
//! without decryption (TLS termination arrives in M1).

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SpliceStats {
    /// Sandbox → upstream.
    pub bytes_out: u64,
    /// Upstream → sandbox.
    pub bytes_in: u64,
}

/// Forward `prefix` (bytes already read from the client) upstream, then relay
/// until either side closes.
pub async fn splice<C, U>(client: &mut C, upstream: &mut U, prefix: &[u8]) -> std::io::Result<SpliceStats>
where
    C: AsyncRead + AsyncWrite + Unpin,
    U: AsyncRead + AsyncWrite + Unpin,
{
    upstream.write_all(prefix).await?;
    let (out, inn) = tokio::io::copy_bidirectional(client, upstream).await?;
    Ok(SpliceStats { bytes_out: out + prefix.len() as u64, bytes_in: inn })
}

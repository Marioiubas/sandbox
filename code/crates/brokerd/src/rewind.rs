//! A stream that first replays bytes already read (the peeked ClientHello)
//! and then continues with the underlying stream.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub struct Rewind<S> {
    prefix: Vec<u8>,
    pos: usize,
    inner: S,
}

impl<S> Rewind<S> {
    pub fn new(prefix: Vec<u8>, inner: S) -> Self {
        Rewind { prefix, pos: 0, inner }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Rewind<S> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        if self.pos < self.prefix.len() {
            let n = (self.prefix.len() - self.pos).min(buf.remaining());
            let start = self.pos;
            buf.put_slice(&self.prefix[start..start + n]);
            self.pos += n;
            if self.pos == self.prefix.len() {
                self.prefix = Vec::new();
                self.pos = 0;
            }
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Rewind<S> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, b: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, b)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn replays_then_continues() {
        let (mut a, b) = tokio::io::duplex(64);
        a.write_all(b" world").await.unwrap();
        drop(a);
        let mut r = Rewind::new(b"hello".to_vec(), b);
        let mut s = String::new();
        r.read_to_string(&mut s).await.unwrap();
        assert_eq!(s, "hello world");
    }
}

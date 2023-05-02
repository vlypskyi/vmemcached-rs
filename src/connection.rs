use pin_project_lite::pin_project;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncBufRead, AsyncRead, AsyncWrite, BufStream, ReadBuf};
use tokio::net::{TcpStream, ToSocketAddrs};

#[cfg(feature = "tls")]
use std::sync::Arc;
#[cfg(feature = "tls")]
use rustls::{ClientConfig, ServerName};
#[cfg(feature = "tls")]
use tokio_rustls::{TlsConnector, client::TlsStream};

#[cfg(not(feature = "tls"))]
type Stream = BufStream<TcpStream>;

#[cfg(feature = "tls")]
type Stream = BufStream<TlsStream<TcpStream>>;

pin_project! {
    /// Connection wrapper
    #[derive(Debug)]
    #[must_use = "Connection do nothing unless polled"]
    pub struct Connection {
        #[pin]
        stream: Stream
    }
}


/// Wrapped Rustls client configuration
#[cfg(feature = "tls")]
pub type TlsConfig = Arc<ClientConfig>;

impl AsyncRead for Connection {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &mut ReadBuf,
    ) -> Poll<io::Result<()>> {
        self.project().stream.poll_read(cx, buf)
    }
}

impl AsyncWrite for Connection {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context, buf: &[u8]) -> Poll<io::Result<usize>> {
        self.project().stream.poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        self.project().stream.poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        self.project().stream.poll_shutdown(cx)
    }
}

impl AsyncBufRead for Connection {
    fn poll_fill_buf(self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<&[u8]>> {
        self.project().stream.poll_fill_buf(cx)
    }

    fn consume(self: Pin<&mut Self>, amt: usize) {
        self.project().stream.consume(amt)
    }
}

#[cfg(not(feature = "tls"))]
impl Connection {
    /// Connect to to given socket address
    pub async fn connect<A: ToSocketAddrs>(address: A) -> Result<Connection, io::Error> {
        TcpStream::connect(address).await.map(|c| Connection {
            stream: BufStream::new(c),
        })
    }

    /// Check if connection is broken by trying to read from it
    ///
    /// try_read()
    /// If data is successfully read, `Ok(n)` is returned, where `n` is the
    /// number of bytes read. `Ok(0)` indicates the stream's read half is closed
    /// and will no longer yield data. If the stream is not ready to read data
    /// `Err(io::ErrorKind::WouldBlock)` is returned.
    pub fn has_broken(&self) -> bool {
        self.stream
            .get_ref()
            .try_read(&mut []) // dirty way to try to read without buffer
            .map(|value| value == 0) // 0 indicates the stream's read half is closed
            .unwrap_or(true) // unwrap any error as true
    }

    /// Get reference to Stream
    pub fn get_ref(&self) -> &TcpStream {
        &self.stream.get_ref()
    }
}

#[cfg(feature = "tls")]
impl Connection {
    /// Securely connect to to given socket address
    pub async fn connect<A: ToSocketAddrs>(address: A, server_name: ServerName, tls_config: TlsConfig) -> Result<Connection, io::Error> {
        let tls_connector = TlsConnector::from(tls_config);
        let tcp_stream = TcpStream::connect(&address).await?;
        let tls_stream = tls_connector.connect(server_name, tcp_stream).await?;

        Ok(Connection {
            stream: BufStream::new(tls_stream)
        })
    }

    /// Check if connection is broken by trying to read from it
    ///
    /// try_read()
    /// If data is successfully read, `Ok(n)` is returned, where `n` is the
    /// number of bytes read. `Ok(0)` indicates the stream's read half is closed
    /// and will no longer yield data. If the stream is not ready to read data
    /// `Err(io::ErrorKind::WouldBlock)` is returned.
    pub fn has_broken(&self) -> bool {
        self.stream
            .get_ref()
            .get_ref()
            .0
            .try_read(&mut []) // dirty way to try to read without buffer
            .map(|value| value == 0) // 0 indicates the stream's read half is closed
            .unwrap_or(true) // unwrap any error as true
    }

    /// Get reference to Stream
    pub fn get_ref(&self) -> &TlsStream<TcpStream> {
        &self.stream.get_ref()
    }
}

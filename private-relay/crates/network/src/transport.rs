use std::sync::{Arc, Mutex};
use std::time::Duration;

use private_relay_crypto::{LinkInitiator, LinkResponder, LinkSession, StaticKeypair};
use private_relay_protocol::{Cell, OUTER_WIRE_FRAME_BYTES, X25519_KEY_LEN};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::error::NetworkError;

const MAX_HANDSHAKE_FRAME_LEN: usize = 512;

/// Async read half of an authenticated `Noise_IK` TCP link receiving exact `600`-byte frames.
pub struct LinkReader<R> {
    reader: R,
    session: Arc<Mutex<LinkSession>>,
}

/// Async write half of an authenticated `Noise_IK` TCP link sending exact `600`-byte frames.
pub struct LinkWriter<W> {
    writer: W,
    session: Arc<Mutex<LinkSession>>,
}

impl<R: AsyncRead + Unpin> LinkReader<R> {
    /// Reads exact `600`-byte wire record with timeout (handling partial TCP reads) and Noise-opens `Cell`.
    pub async fn recv_cell(&mut self, io_timeout: Duration) -> Result<Cell, NetworkError> {
        self.recv_cell_with_timeouts(io_timeout, io_timeout).await
    }

    /// Reads exact `600`-byte wire record allowing a longer idle wait before byte 0 arrives, while
    /// bounding partial mid-frame completion (`wire[1..]`) by `frame_io_timeout`.
    pub async fn recv_cell_with_timeouts(
        &mut self,
        idle_timeout: Duration,
        frame_io_timeout: Duration,
    ) -> Result<Cell, NetworkError> {
        let mut wire = [0u8; OUTER_WIRE_FRAME_BYTES];
        match timeout(idle_timeout, self.reader.read(&mut wire[..1])).await {
            Ok(Ok(0)) => return Err(NetworkError::ConnectionClosed),
            Ok(Ok(_)) => {}
            Ok(Err(e)) => return Err(NetworkError::from(e)),
            Err(_) => return Err(NetworkError::Timeout("waiting for link frame")),
        }

        match timeout(frame_io_timeout, self.reader.read_exact(&mut wire[1..])).await {
            Ok(Ok(_read_len)) => {}
            Ok(Err(e)) => return Err(NetworkError::from(e)),
            Err(_) => return Err(NetworkError::Timeout("reading link frame body")),
        }

        let mut guard = self
            .session
            .lock()
            .map_err(|_| NetworkError::PolicyDenied("session mutex poisoned".into()))?;
        Ok(guard.open_cell(&wire)?)
    }
}

impl<W: AsyncWrite + Unpin> LinkWriter<W> {
    /// Seals `Cell` into fixed `600`-byte Noise frame and writes atomically with timeout (handling partial TCP writes).
    pub async fn send_cell(
        &mut self,
        cell: &Cell,
        io_timeout: Duration,
    ) -> Result<(), NetworkError> {
        let wire = {
            let mut guard = self
                .session
                .lock()
                .map_err(|_| NetworkError::PolicyDenied("session mutex poisoned".into()))?;
            guard.seal_cell(cell)?
        };

        match timeout(io_timeout, write_all_and_flush(&mut self.writer, &wire)).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) => Err(NetworkError::from(e)),
            Err(_) => Err(NetworkError::Timeout("writing link frame")),
        }
    }

    pub async fn shutdown(&mut self) -> Result<(), NetworkError> {
        self.writer.shutdown().await.map_err(NetworkError::from)
    }
}

/// Splits any `AsyncRead + AsyncWrite` stream into concurrent `(LinkReader, LinkWriter)` halves sharing a `LinkSession`.
pub fn split_framed_session<S>(
    stream: S,
    session: LinkSession,
) -> (
    LinkReader<tokio::io::ReadHalf<S>>,
    LinkWriter<tokio::io::WriteHalf<S>>,
)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (r, w) = tokio::io::split(stream);
    let shared = Arc::new(Mutex::new(session));
    (
        LinkReader {
            reader: r,
            session: Arc::clone(&shared),
        },
        LinkWriter {
            writer: w,
            session: shared,
        },
    )
}

/// Performs outbound TCP connect + `Noise_IK` initiator handshake, authenticating `expected_remote_pub`.
pub async fn connect_noise_link(
    addr: &str,
    local_keypair: &StaticKeypair,
    expected_remote_pub: [u8; X25519_KEY_LEN],
    handshake_timeout: Duration,
) -> Result<
    (
        LinkReader<tokio::io::ReadHalf<TcpStream>>,
        LinkWriter<tokio::io::WriteHalf<TcpStream>>,
    ),
    NetworkError,
> {
    let stream = match timeout(handshake_timeout, TcpStream::connect(addr)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => return Err(NetworkError::from(e)),
        Err(_) => return Err(NetworkError::Timeout("tcp connect")),
    };
    let _ = stream.set_nodelay(true);

    let (mut reader, mut writer) = tokio::io::split(stream);
    let session = run_initiator_handshake(
        &mut reader,
        &mut writer,
        local_keypair,
        expected_remote_pub,
        handshake_timeout,
    )
    .await?;

    let stream = reader.unsplit(writer);
    Ok(split_framed_session(stream, session))
}

/// Accepts an inbound connection + `Noise_IK` responder handshake, returning split transport & remote pubkey.
pub async fn accept_noise_link<S>(
    mut stream: S,
    local_keypair: &StaticKeypair,
    handshake_timeout: Duration,
) -> Result<
    (
        LinkReader<tokio::io::ReadHalf<S>>,
        LinkWriter<tokio::io::WriteHalf<S>>,
        [u8; X25519_KEY_LEN],
    ),
    NetworkError,
>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (mut reader, mut writer) = tokio::io::split(stream);
    let session =
        run_responder_handshake(&mut reader, &mut writer, local_keypair, handshake_timeout).await?;
    let remote_pub = *session.remote_static_pub();
    stream = reader.unsplit(writer);
    let (lr, lw) = split_framed_session(stream, session);
    Ok((lr, lw, remote_pub))
}

pub async fn run_initiator_handshake<R, W>(
    reader: &mut R,
    writer: &mut W,
    local_keypair: &StaticKeypair,
    expected_remote_pub: [u8; X25519_KEY_LEN],
    handshake_timeout: Duration,
) -> Result<LinkSession, NetworkError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut init = LinkInitiator::new(local_keypair, expected_remote_pub)?;
    let msg1 = init.write_msg1()?;
    timeout(handshake_timeout, write_handshake_msg(writer, &msg1))
        .await
        .map_err(|_| NetworkError::Timeout("handshake write msg1"))??;

    let msg2 = timeout(handshake_timeout, read_handshake_msg(reader))
        .await
        .map_err(|_| NetworkError::Timeout("handshake read msg2"))??;

    Ok(init.finish_with_msg2(&msg2)?)
}

pub async fn run_responder_handshake<R, W>(
    reader: &mut R,
    writer: &mut W,
    local_keypair: &StaticKeypair,
    handshake_timeout: Duration,
) -> Result<LinkSession, NetworkError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let msg1 = timeout(handshake_timeout, read_handshake_msg(reader))
        .await
        .map_err(|_| NetworkError::Timeout("handshake read msg1"))??;

    let resp = LinkResponder::new(local_keypair)?;
    let (msg2, session) = resp.process_msg1_and_finish(&msg1)?;

    timeout(handshake_timeout, write_handshake_msg(writer, &msg2))
        .await
        .map_err(|_| NetworkError::Timeout("handshake write msg2"))??;

    Ok(session)
}

async fn write_all_and_flush<W: AsyncWrite + Unpin>(
    writer: &mut W,
    bytes: &[u8],
) -> Result<(), std::io::Error> {
    writer.write_all(bytes).await?;
    writer.flush().await
}

async fn write_handshake_msg<W: AsyncWrite + Unpin>(
    writer: &mut W,
    msg: &[u8],
) -> Result<(), NetworkError> {
    if msg.is_empty() || msg.len() > MAX_HANDSHAKE_FRAME_LEN {
        return Err(NetworkError::HandshakeTooLarge {
            size: msg.len(),
            max: MAX_HANDSHAKE_FRAME_LEN,
        });
    }
    let len_bytes = (msg.len() as u16).to_be_bytes();
    writer.write_all(&len_bytes).await?;
    writer.write_all(msg).await?;
    writer.flush().await?;
    Ok(())
}

async fn read_handshake_msg<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Vec<u8>, NetworkError> {
    let mut len_bytes = [0u8; 2];
    reader.read_exact(&mut len_bytes).await?;
    let len = u16::from_be_bytes(len_bytes) as usize;
    if len == 0 || len > MAX_HANDSHAKE_FRAME_LEN {
        return Err(NetworkError::HandshakeTooLarge {
            size: len,
            max: MAX_HANDSHAKE_FRAME_LEN,
        });
    }
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf).await?;
    Ok(buf)
}

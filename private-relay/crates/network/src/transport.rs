use std::sync::{Arc, Mutex};
use std::time::Duration;

use private_relay_crypto::{
    LinkInitiator, LinkRekeyPolicy, LinkResponder, LinkSession, StaticKeypair,
};
use private_relay_protocol::{
    Cell, LinkFrame, ProtocolError, OUTER_WIRE_FRAME_BYTES, X25519_KEY_LEN,
};
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

    /// Returns `(outgoing_rekey_epoch, incoming_rekey_epoch)` for diagnostics and testing.
    pub fn rekey_epochs(&self) -> Result<(u64, u64), NetworkError> {
        let guard = self
            .session
            .lock()
            .map_err(|_| NetworkError::PolicyDenied("session mutex poisoned".into()))?;
        Ok(guard.rekey_epochs())
    }

    /// Reads exact `600`-byte wire record allowing a longer idle wait before byte 0 arrives, while
    /// bounding partial mid-frame completion (`wire[1..]`) by `frame_io_timeout` and consuming any
    /// synchronized `RekeyControl` frames atomically without resetting the deadline.
    pub async fn recv_cell_with_timeouts(
        &mut self,
        idle_timeout: Duration,
        frame_io_timeout: Duration,
    ) -> Result<Cell, NetworkError> {
        const MAX_CONSECUTIVE_REKEYS: u32 = 4;
        let deadline = tokio::time::Instant::now() + idle_timeout;
        let mut consecutive_rekeys = 0u32;

        loop {
            let now = tokio::time::Instant::now();
            if now >= deadline {
                return Err(NetworkError::Timeout("waiting for link frame"));
            }
            let remaining_idle = deadline.saturating_duration_since(now);

            let mut wire = [0u8; OUTER_WIRE_FRAME_BYTES];
            match timeout(remaining_idle, self.reader.read(&mut wire[..1])).await {
                Ok(Ok(0)) => {
                    if let Ok(mut guard) = self.session.lock() {
                        guard.mark_failed();
                    }
                    return Err(NetworkError::ConnectionClosed);
                }
                Ok(Ok(_)) => {}
                Ok(Err(e)) => {
                    if let Ok(mut guard) = self.session.lock() {
                        guard.mark_failed();
                    }
                    return Err(NetworkError::from(e));
                }
                Err(_) => return Err(NetworkError::Timeout("waiting for link frame")),
            }

            match timeout(frame_io_timeout, self.reader.read_exact(&mut wire[1..])).await {
                Ok(Ok(_read_len)) => {}
                Ok(Err(e)) => {
                    if let Ok(mut guard) = self.session.lock() {
                        guard.mark_failed();
                    }
                    return Err(NetworkError::from(e));
                }
                Err(_) => {
                    if let Ok(mut guard) = self.session.lock() {
                        guard.mark_failed();
                    }
                    return Err(NetworkError::Timeout("reading link frame body"));
                }
            }

            let frame = {
                let mut guard = self
                    .session
                    .lock()
                    .map_err(|_| NetworkError::PolicyDenied("session mutex poisoned".into()))?;
                guard.open_frame(&wire)?
            };

            match frame {
                LinkFrame::Cell(cell) => return Ok(cell),
                LinkFrame::RekeyControl { .. } => {
                    consecutive_rekeys += 1;
                    if consecutive_rekeys > MAX_CONSECUTIVE_REKEYS {
                        if let Ok(mut guard) = self.session.lock() {
                            guard.mark_failed();
                        }
                        return Err(NetworkError::Protocol(ProtocolError::MalformedPayload(
                            "excessive consecutive rekey control frames",
                        )));
                    }
                }
            }
        }
    }
}

impl<W: AsyncWrite + Unpin> LinkWriter<W> {
    /// Returns `(outgoing_rekey_epoch, incoming_rekey_epoch)` for diagnostics and testing.
    pub fn rekey_epochs(&self) -> Result<(u64, u64), NetworkError> {
        let guard = self
            .session
            .lock()
            .map_err(|_| NetworkError::PolicyDenied("session mutex poisoned".into()))?;
        Ok(guard.rekey_epochs())
    }

    /// Explicitly transmits an authenticated `RekeyControl` frame and advances the outgoing cipher key.
    pub async fn trigger_rekey(&mut self, io_timeout: Duration) -> Result<(), NetworkError> {
        let rekey_wire = {
            let mut guard = self
                .session
                .lock()
                .map_err(|_| NetworkError::PolicyDenied("session mutex poisoned".into()))?;
            guard.seal_rekey_and_rotate()?
        };
        if let Err(e) = write_frame_with_timeout(&mut self.writer, &rekey_wire, io_timeout).await {
            if let Ok(mut guard) = self.session.lock() {
                guard.mark_failed();
            }
            return Err(e);
        }
        Ok(())
    }

    /// Seals `Cell` into fixed `600`-byte Noise frame and writes atomically with timeout (handling partial TCP writes).
    /// Automatically rotates the outgoing cipher first when byte/time rekey thresholds are reached.
    pub async fn send_cell(
        &mut self,
        cell: &Cell,
        io_timeout: Duration,
    ) -> Result<(), NetworkError> {
        let maybe_rekey = {
            let mut guard = self
                .session
                .lock()
                .map_err(|_| NetworkError::PolicyDenied("session mutex poisoned".into()))?;
            if guard.should_rekey_outgoing() {
                Some(guard.seal_rekey_and_rotate()?)
            } else {
                None
            }
        };

        if let Some(rekey_wire) = maybe_rekey {
            if let Err(e) =
                write_frame_with_timeout(&mut self.writer, &rekey_wire, io_timeout).await
            {
                if let Ok(mut guard) = self.session.lock() {
                    guard.mark_failed();
                }
                return Err(e);
            }
        }

        let wire = {
            let mut guard = self
                .session
                .lock()
                .map_err(|_| NetworkError::PolicyDenied("session mutex poisoned".into()))?;
            guard.seal_cell(cell)?
        };

        if let Err(e) = write_frame_with_timeout(&mut self.writer, &wire, io_timeout).await {
            if let Ok(mut guard) = self.session.lock() {
                guard.mark_failed();
            }
            return Err(e);
        }
        Ok(())
    }

    pub async fn shutdown(&mut self) -> Result<(), NetworkError> {
        self.writer.shutdown().await.map_err(NetworkError::from)
    }
}

async fn write_frame_with_timeout<W: AsyncWrite + Unpin>(
    writer: &mut W,
    wire: &[u8; OUTER_WIRE_FRAME_BYTES],
    io_timeout: Duration,
) -> Result<(), NetworkError> {
    match timeout(io_timeout, write_all_and_flush(writer, wire)).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => Err(NetworkError::from(e)),
        Err(_) => Err(NetworkError::Timeout("writing link frame")),
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
    connect_noise_link_with_rekey(
        addr,
        local_keypair,
        expected_remote_pub,
        handshake_timeout,
        LinkRekeyPolicy::default(),
    )
    .await
}

/// Outbound TCP connect + `Noise_IK` handshake configuring a custom [`LinkRekeyPolicy`].
pub async fn connect_noise_link_with_rekey(
    addr: &str,
    local_keypair: &StaticKeypair,
    expected_remote_pub: [u8; X25519_KEY_LEN],
    handshake_timeout: Duration,
    rekey_policy: LinkRekeyPolicy,
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
    let mut session = run_initiator_handshake(
        &mut reader,
        &mut writer,
        local_keypair,
        expected_remote_pub,
        handshake_timeout,
    )
    .await?;
    session.set_rekey_policy(rekey_policy);

    let stream = reader.unsplit(writer);
    Ok(split_framed_session(stream, session))
}

/// Accepts an inbound connection + `Noise_IK` responder handshake, returning split transport & remote pubkey.
pub async fn accept_noise_link<S>(
    stream: S,
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
    accept_noise_link_with_rekey(
        stream,
        local_keypair,
        handshake_timeout,
        LinkRekeyPolicy::default(),
    )
    .await
}

/// Accepts an inbound Noise link configuring a custom [`LinkRekeyPolicy`].
pub async fn accept_noise_link_with_rekey<S>(
    mut stream: S,
    local_keypair: &StaticKeypair,
    handshake_timeout: Duration,
    rekey_policy: LinkRekeyPolicy,
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
    let mut session =
        run_responder_handshake(&mut reader, &mut writer, local_keypair, handshake_timeout).await?;
    session.set_rekey_policy(rekey_policy);
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

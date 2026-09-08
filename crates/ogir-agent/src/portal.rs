// SPDX-License-Identifier: Apache-2.0

//! The unprivileged local portal (M5-031, ADR-0027): the Unix-domain
//! listener Windows and native clients connect to. Authentication is
//! KERNEL-DERIVED: every accepted connection's credentials come from
//! SO_PEERCRED on the socket, never from anything the caller sends.
//! Messages are length-prefixed, bounded, and normalized before any
//! session logic sees them; misbehavior fails closed.

use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};

/// The credentials the kernel reports for a connected peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerCredentials {
    pub pid: u32,
    pub uid: u32,
    pub gid: u32,
}

/// The requests a connection may carry, with bounded fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PortalRequest {
    /// The client's greeting: its protocol version and a bounded
    /// client name. Nothing here is trusted for identity.
    Hello { version: u32, client_name: String },
}

/// The portal's normalized responses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PortalResponse {
    /// The greeting's answer, echoing the protocol version and
    /// reporting the credentials THE PORTAL OBSERVED for the peer
    /// (the kernel's answer, never the client's claim).
    HelloAck {
        version: u32,
        observed: PeerCredentials,
    },
    /// Anything malformed, oversized, or unknown.
    Rejected { reason: &'static str },
}

/// The hard frame ceiling: length prefixes above this reject without
/// reading the body (the request-flood defense; a hostile client
/// cannot make the portal allocate).
pub const MAX_FRAME: u32 = 1024;

/// The most frames one connection may send before the portal closes
/// it (the per-connection flood bound).
pub const MAX_FRAMES_PER_CONNECTION: u32 = 16;

/// Errors the portal produces. Deterministic, non-disciplinary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PortalError {
    /// The frame length prefix exceeded [`MAX_FRAME`].
    OversizedFrame,
    /// The connection ended inside a frame.
    Truncated,
    /// The decoded message was structurally invalid.
    Malformed(&'static str),
    /// The peer sent more frames than the bound allows.
    Flooded,
    /// Underlying I/O failure.
    Io(&'static str),
}

impl std::fmt::Display for PortalError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::OversizedFrame => formatter.write_str("frame exceeds the portal ceiling"),
            Self::Truncated => formatter.write_str("connection ended inside a frame"),
            Self::Malformed(detail) => write!(formatter, "malformed portal message: {detail}"),
            Self::Flooded => formatter.write_str("connection exceeded its frame budget"),
            Self::Io(detail) => write!(formatter, "portal i/o failure: {detail}"),
        }
    }
}

impl std::error::Error for PortalError {}

impl From<io::Error> for PortalError {
    fn from(_: io::Error) -> Self {
        Self::Io("read or write")
    }
}

/// Reads the kernel-reported credentials of a connected peer via
/// SO_PEERCRED. This is the ONLY audited unsafe block in ogir-agent
/// (ADR-0027; the workspace posture stays forbid-by-default).
///
/// # Safety
///
/// The block performs exactly two calls on locals: one `getsockopt`
/// with a stack-allocated, correctly-sized `ucred` buffer and its
/// address (the syscall writes at most that many bytes), and the
/// same-block call of the declared `getsockopt`. The descriptor
/// Reads the kernel-reported credentials of a connected peer via
/// SO_PEERCRED. Identity comes from the kernel, never the caller.
pub fn peer_credentials(stream: &UnixStream) -> io::Result<PeerCredentials> {
    #[repr(C)]
    struct Ucred {
        pid: i32,
        uid: u32,
        gid: u32,
    }
    let mut ucred = Ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut length = std::mem::size_of::<Ucred>() as u32;
    let result = crate::audited::getsockopt_peer_cred(
        stream.as_raw_fd(),
        &mut ucred as *mut Ucred as *mut core::ffi::c_void,
        &mut length,
    );
    if result != 0 || length as usize != std::mem::size_of::<Ucred>() {
        return Err(io::Error::last_os_error());
    }
    if ucred.pid < 0 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "negative pid"));
    }
    Ok(PeerCredentials {
        pid: ucred.pid as u32,
        uid: ucred.uid,
        gid: ucred.gid,
    })
}

/// Validates a caller-supplied socket path and returns the
/// reconstructed clean path: absolute, no parent traversal, within
/// the sun_path budget. Anything else is rejected.
fn sanitize_socket_path(path: &Path) -> io::Result<PathBuf> {
    use std::path::Component;
    if !path.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "the portal socket path must be absolute",
        ));
    }
    let mut clean = PathBuf::new();
    clean.push("/");
    for component in path.components() {
        match component {
            Component::Normal(part) => clean.push(part),
            Component::RootDir | Component::CurDir => {}
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "the portal socket path may not traverse",
                ));
            }
        }
    }
    if clean.as_os_str().len() > 104 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "the portal socket path exceeds the sun_path budget",
        ));
    }
    Ok(clean)
}

/// A bound portal.
#[derive(Debug)]
pub struct Portal {
    listener: UnixListener,
    path: PathBuf,
}

impl Portal {
    /// Binds the portal socket at `path`, creating the parent
    /// directory with 0700 and the socket itself 0600: only the same
    /// UID may connect.
    pub fn bind(path: &Path) -> io::Result<Self> {
        // The socket path is configuration (often from the
        // environment); validate and RECONSTRUCT it before any
        // filesystem use so a hostile value can neither traverse
        // nor overflow sun_path.
        let path = sanitize_socket_path(path)?;
        if let Some(parent) = path.parent() {
            // Harden only directories this call creates; never touch
            // the permissions of a pre-existing shared directory.
            if !parent.is_dir() {
                std::fs::create_dir_all(parent)?;
                std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
            }
        }
        let listener = UnixListener::bind(&path)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        Ok(Self { listener, path })
    }

    /// Accepts one connection and reads its kernel-derived
    /// credentials before any byte of payload is parsed.
    pub fn accept(&self) -> io::Result<(UnixStream, PeerCredentials)> {
        let (stream, _) = self.listener.accept()?;
        let credentials = peer_credentials(&stream)?;
        Ok((stream, credentials))
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for Portal {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Reads one length-prefixed frame within [`MAX_FRAME`].
pub fn read_frame(stream: &mut UnixStream) -> Result<Vec<u8>, PortalError> {
    let mut prefix = [0u8; 4];
    stream
        .read_exact(&mut prefix)
        .map_err(|_| PortalError::Truncated)?;
    let length = u32::from_be_bytes(prefix);
    if length > MAX_FRAME {
        return Err(PortalError::OversizedFrame);
    }
    let mut body = vec![0u8; length as usize];
    stream
        .read_exact(&mut body)
        .map_err(|_| PortalError::Truncated)?;
    Ok(body)
}

/// Writes one length-prefixed frame.
pub fn write_frame(stream: &mut UnixStream, body: &[u8]) -> Result<(), PortalError> {
    if body.len() > MAX_FRAME as usize {
        return Err(PortalError::OversizedFrame);
    }
    stream
        .write_all(&(body.len() as u32).to_be_bytes())
        .map_err(|_| PortalError::Io("write prefix"))?;
    stream
        .write_all(body)
        .map_err(|_| PortalError::Io("write body"))?;
    stream.flush().map_err(|_| PortalError::Io("flush"))
}

fn bounded_string(bytes: &[u8], limit: usize, detail: &'static str) -> Result<String, PortalError> {
    if bytes.is_empty() || bytes.len() > limit {
        return Err(PortalError::Malformed(detail));
    }
    String::from_utf8(bytes.to_vec()).map_err(|_| PortalError::Malformed(detail))
}

/// Decodes a request frame. Fail-closed on unknown kinds, wrong
/// field sizes, non-UTF-8, or empty names.
pub fn decode_request(frame: &[u8]) -> Result<PortalRequest, PortalError> {
    let Some((kind, rest)) = frame.split_first() else {
        return Err(PortalError::Malformed("empty frame"));
    };
    match kind {
        b'H' => {
            if rest.len() < 4 {
                return Err(PortalError::Malformed("short hello"));
            }
            let version = u32::from_be_bytes([rest[0], rest[1], rest[2], rest[3]]);
            let name = bounded_string(&rest[4..], 64, "client name")?;
            Ok(PortalRequest::Hello {
                version,
                client_name: name,
            })
        }
        _ => Err(PortalError::Malformed("unknown request kind")),
    }
}

/// Encodes a response frame.
pub fn encode_response(response: &PortalResponse) -> Result<Vec<u8>, PortalError> {
    match response {
        PortalResponse::HelloAck { version, observed } => {
            let mut body = Vec::with_capacity(17);
            body.push(b'H');
            body.extend_from_slice(&version.to_be_bytes());
            body.extend_from_slice(&observed.pid.to_be_bytes());
            body.extend_from_slice(&observed.uid.to_be_bytes());
            body.extend_from_slice(&observed.gid.to_be_bytes());
            Ok(body)
        }
        PortalResponse::Rejected { reason } => {
            let mut body = Vec::with_capacity(1 + reason.len());
            body.push(b'R');
            body.extend_from_slice(reason.as_bytes());
            Ok(body)
        }
    }
}

fn rejection(error: &PortalError) -> PortalResponse {
    let reason = match error {
        PortalError::OversizedFrame => "oversized frame",
        PortalError::Malformed(_) => "malformed message",
        PortalError::Truncated => "truncated message",
        PortalError::Flooded => "flood",
        PortalError::Io(_) => "i/o failure",
    };
    PortalResponse::Rejected { reason }
}

/// Serves the bounded v1 protocol on one connection: at most
/// [`MAX_FRAMES_PER_CONNECTION`] requests, each answered with the
/// normalized response built from the KERNEL-OBSERVED credentials.
/// Reading past the frame budget is reported as a flood.
pub fn serve_connection(
    stream: &mut UnixStream,
    observed: PeerCredentials,
) -> Result<(), PortalError> {
    for _ in 0..MAX_FRAMES_PER_CONNECTION {
        let frame = match read_frame(stream) {
            Ok(frame) => frame,
            Err(PortalError::Truncated) => return Ok(()),
            Err(error) => return Err(error),
        };
        let response = match decode_request(&frame) {
            Ok(PortalRequest::Hello { version, .. }) => {
                PortalResponse::HelloAck { version, observed }
            }
            Err(error) => rejection(&error),
        };
        write_frame(stream, &encode_response(&response)?)?;
    }
    let mut prefix = [0u8; 4];
    match stream.read_exact(&mut prefix) {
        Ok(()) => Err(PortalError::Flooded),
        Err(_) => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stream_pair() -> (UnixStream, UnixStream) {
        UnixStream::pair().unwrap_or_else(|e| panic!("{e:?}"))
    }

    fn real_uid() -> u32 {
        let status =
            std::fs::read_to_string("/proc/self/status").unwrap_or_else(|e| panic!("{e:?}"));
        let line = status
            .lines()
            .find(|line| line.starts_with("Uid:"))
            .unwrap_or_else(|| panic!("uid line"));
        line.split_whitespace()
            .nth(1)
            .and_then(|value| value.parse().ok())
            .unwrap_or_else(|| panic!("uid value"))
    }

    #[test]
    fn peer_credentials_report_the_real_process() {
        let (_client, server) = stream_pair();
        let credentials = peer_credentials(&server).unwrap_or_else(|e| panic!("{e:?}"));
        // Both ends of a socketpair are this process.
        assert_eq!(credentials.pid, std::process::id());
        assert_eq!(credentials.uid, real_uid());
    }

    #[test]
    fn oversized_frames_reject_without_reading_the_body() {
        let (mut client, mut server) = stream_pair();
        client
            .write_all(&(MAX_FRAME + 1).to_be_bytes())
            .unwrap_or_else(|e| panic!("{e:?}"));
        client.flush().unwrap_or_else(|e| panic!("{e:?}"));
        assert_eq!(read_frame(&mut server), Err(PortalError::OversizedFrame));
    }

    #[test]
    fn truncated_frames_reject() {
        let (mut client, mut server) = stream_pair();
        client
            .write_all(&8u32.to_be_bytes())
            .unwrap_or_else(|e| panic!("{e:?}"));
        client.flush().unwrap_or_else(|e| panic!("{e:?}"));
        // Header promises 8 bytes; only 3 arrive before the close.
        client.write_all(b"abc").unwrap_or_else(|e| panic!("{e:?}"));
        client.flush().unwrap_or_else(|e| panic!("{e:?}"));
        drop(client);
        assert_eq!(read_frame(&mut server), Err(PortalError::Truncated));
    }

    #[test]
    fn unknown_request_kinds_reject() {
        assert_eq!(
            decode_request(b"Zwhatever"),
            Err(PortalError::Malformed("unknown request kind"))
        );
        assert_eq!(
            decode_request(b""),
            Err(PortalError::Malformed("empty frame"))
        );
    }

    #[test]
    fn hello_decodes_with_bounded_name() {
        let mut body = vec![b'H'];
        body.extend_from_slice(&1u32.to_be_bytes());
        body.extend_from_slice(b"sample-client");
        assert_eq!(
            decode_request(&body).unwrap_or_else(|e| panic!("{e:?}")),
            PortalRequest::Hello {
                version: 1,
                client_name: "sample-client".to_string(),
            }
        );
        let long = "x".repeat(65);
        let mut body = vec![b'H'];
        body.extend_from_slice(&1u32.to_be_bytes());
        body.extend_from_slice(long.as_bytes());
        assert_eq!(
            decode_request(&body),
            Err(PortalError::Malformed("client name"))
        );
    }

    #[test]
    fn rejected_responses_encode_bounded_reasons() {
        let body = encode_response(&PortalResponse::Rejected {
            reason: "malformed message",
        })
        .unwrap_or_else(|e| panic!("{e:?}"));
        assert_eq!(body[0], b'R');
        assert_eq!(&body[1..], b"malformed message");
    }
}

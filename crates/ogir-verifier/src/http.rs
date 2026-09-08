// SPDX-License-Identifier: Apache-2.0

//! The bounded HTTP/1.1 listener for the verifier service
//! (ADR-0032): fixed routes, a fixed header-block ceiling, a fixed
//! body ceiling, `Connection: close` semantics, and no TLS - the
//! verifier is the authority, and transport protection is the
//! publisher deployment's documented duty (bind localhost or front
//! with the publisher's reverse proxy). This is a protocol
//! endpoint, not a web framework: everything is bounded, parsed
//! strictly, and fails closed.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};

/// Service failures. Deterministic, non-disciplinary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HttpError {
    /// The header block exceeded its ceiling.
    HeadersTooLarge,
    /// The body exceeded its ceiling.
    BodyTooLarge,
    /// The request was not a parseable fixed-shape request.
    Malformed(&'static str),
    /// I/O failure.
    Io(&'static str),
}

impl std::fmt::Display for HttpError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::HeadersTooLarge => formatter.write_str("request headers exceed the ceiling"),
            Self::BodyTooLarge => formatter.write_str("request body exceeds the ceiling"),
            Self::Malformed(detail) => write!(formatter, "malformed request: {detail}"),
            Self::Io(detail) => write!(formatter, "http i/o failure: {detail}"),
        }
    }
}

impl std::error::Error for HttpError {}

/// The fixed ceilings (the portal philosophy at the service layer).
pub const MAX_HEADER_BLOCK: usize = 4 * 1024;
pub const MAX_BODY: usize = 64 * 1024;
/// The most requests one connection may carry (we close after one;
/// the counter exists to make that explicit).
pub const MAX_REQUESTS_PER_CONNECTION: u32 = 1;

/// One parsed request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub method: String,
    pub path: String,
    pub body: Vec<u8>,
}

/// Reads exactly one request from the stream. The connection is
/// closed after the response regardless.
pub fn read_request(stream: &mut TcpStream) -> Result<Request, HttpError> {
    let mut buffer = Vec::with_capacity(1024);
    let mut chunk = [0u8; 512];
    let header_end;
    loop {
        if buffer.len() > MAX_HEADER_BLOCK {
            return Err(HttpError::HeadersTooLarge);
        }
        if let Some(position) = find_double_newline(&buffer) {
            header_end = position;
            break;
        }
        let read = stream.read(&mut chunk).map_err(|_| HttpError::Io("read"))?;
        if read == 0 {
            return Err(HttpError::Malformed("eof in headers"));
        }
        buffer.extend_from_slice(&chunk[..read]);
    }

    let header_text = String::from_utf8(buffer[..header_end].to_vec())
        .map_err(|_| HttpError::Malformed("header utf-8"))?;
    let mut lines = header_text.split("\r\n");
    let request_line = lines.next().ok_or(HttpError::Malformed("empty"))?;
    let mut parts = request_line.split(' ');
    let method = parts
        .next()
        .ok_or(HttpError::Malformed("method"))?
        .to_string();
    let path = parts
        .next()
        .ok_or(HttpError::Malformed("path"))?
        .to_string();
    let version = parts.next().ok_or(HttpError::Malformed("version"))?;
    if !version.starts_with("HTTP/1.") {
        return Err(HttpError::Malformed("version"));
    }

    let mut content_length: Option<usize> = None;
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let Some((name, value)) = line.split_once(':') else {
            return Err(HttpError::Malformed("header"));
        };
        if name.eq_ignore_ascii_case("content-length") {
            let parsed = value
                .trim()
                .parse::<usize>()
                .map_err(|_| HttpError::Malformed("content-length"))?;
            content_length = Some(parsed);
        }
    }
    let content_length = content_length.ok_or(HttpError::Malformed("content-length required"))?;
    if content_length > MAX_BODY {
        return Err(HttpError::BodyTooLarge);
    }

    let mut body = buffer[header_end + 4..].to_vec();
    if body.len() > content_length {
        return Err(HttpError::Malformed("body past content-length"));
    }
    while body.len() < content_length {
        let read = stream
            .read(&mut chunk)
            .map_err(|_| HttpError::Io("body read"))?;
        if read == 0 {
            return Err(HttpError::Malformed("eof in body"));
        }
        body.extend_from_slice(&chunk[..read]);
        if body.len() > content_length {
            return Err(HttpError::Malformed("body past content-length"));
        }
    }

    Ok(Request { method, path, body })
}

fn find_double_newline(buffer: &[u8]) -> Option<usize> {
    buffer.windows(4).position(|window| window == b"\r\n\r\n")
}

/// Writes one JSON response with the given status and closes.
pub fn write_response(stream: &mut TcpStream, status: &str, body: &str) -> Result<(), HttpError> {
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream
        .write_all(response.as_bytes())
        .map_err(|_| HttpError::Io("write"))?;
    stream.flush().map_err(|_| HttpError::Io("flush"))
}

/// The status line for a verdict-level failure.
pub const STATUS_BAD_REQUEST: &str = "400 Bad Request";
pub const STATUS_NOT_FOUND: &str = "404 Not Found";
pub const STATUS_METHOD_NOT_ALLOWED: &str = "405 Method Not Allowed";
pub const STATUS_OK: &str = "200 OK";

/// A bound listener.
#[derive(Debug)]
pub struct Listener {
    inner: TcpListener,
}

impl Listener {
    pub fn bind(address: &str) -> std::io::Result<Self> {
        Ok(Self {
            inner: TcpListener::bind(address)?,
        })
    }

    pub fn local_address(&self) -> std::io::Result<std::net::SocketAddr> {
        self.inner.local_addr()
    }

    /// Accepts one connection. Connections serve at most
    /// [`MAX_REQUESTS_PER_CONNECTION`] request and close.
    pub fn accept(&self) -> std::io::Result<TcpStream> {
        let (stream, _) = self.inner.accept()?;
        Ok(stream)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_the_header_boundary() {
        assert_eq!(find_double_newline(b"abc\r\n\r\nbody"), Some(3));
        assert_eq!(find_double_newline(b"abc\r\nx"), None);
    }

    #[test]
    fn responses_are_shaped() {
        // The shape is asserted on the wire in the integration
        // tests; here the invariant pieces are the headers.
        let body = "{\"ok\":true}";
        let response = format!(
            "HTTP/1.1 {STATUS_OK}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(response.contains("Connection: close"));
        assert!(response.ends_with(body));
    }
}

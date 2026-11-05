//! Language-agnostic IPC framing for the SignBridge JSON protocol.
//!
//! Two wire formats share the same JSON bodies ([`crate::protocol`]):
//!
//! - [`Framing::Ndjson`] — one JSON object per line (easy for Python / Node / Go).
//! - [`Framing::NativeMessage`] — Chrome/Firefox native-messaging (4-byte LE length).

use crate::error::{Error, Result};
use crate::protocol::{Request, Response};
use crate::service::{ConfirmPrompt, SignService};
use std::io::{BufRead, Write};

/// How messages are delimited on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Framing {
    /// One UTF-8 JSON object followed by `\n`.
    Ndjson,
    /// 4-byte little-endian length + UTF-8 JSON (native messaging).
    NativeMessage,
}

/// Read one framed request body. `Ok(None)` on clean EOF.
pub fn read_frame(reader: &mut impl BufRead, framing: Framing) -> Result<Option<Vec<u8>>> {
    match framing {
        Framing::Ndjson => {
            let mut line = String::new();
            let n = reader
                .read_line(&mut line)
                .map_err(|e| Error::Protocol(e.to_string()))?;
            if n == 0 {
                return Ok(None);
            }
            let trimmed = line.trim();
            if trimmed.is_empty() {
                return Ok(Some(Vec::new())); // caller may skip
            }
            Ok(Some(trimmed.as_bytes().to_vec()))
        }
        Framing::NativeMessage => {
            let mut len_buf = [0u8; 4];
            match std::io::Read::read_exact(reader, &mut len_buf) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
                Err(e) => return Err(Error::Protocol(e.to_string())),
            }
            let len = u32::from_le_bytes(len_buf) as usize;
            if len > 1024 * 1024 {
                return Err(Error::Protocol(format!("frame too large: {len}")));
            }
            let mut buf = vec![0u8; len];
            std::io::Read::read_exact(reader, &mut buf)
                .map_err(|e| Error::Protocol(e.to_string()))?;
            Ok(Some(buf))
        }
    }
}

/// Write one framed response body.
pub fn write_frame(writer: &mut impl Write, framing: Framing, body: &[u8]) -> Result<()> {
    match framing {
        Framing::Ndjson => {
            writer
                .write_all(body)
                .map_err(|e| Error::Protocol(e.to_string()))?;
            writer
                .write_all(b"\n")
                .map_err(|e| Error::Protocol(e.to_string()))?;
        }
        Framing::NativeMessage => {
            if body.len() > 1024 * 1024 {
                return Err(Error::Protocol(format!(
                    "frame too large to send: {}",
                    body.len()
                )));
            }
            let len = (body.len() as u32).to_le_bytes();
            writer
                .write_all(&len)
                .map_err(|e| Error::Protocol(e.to_string()))?;
            writer
                .write_all(body)
                .map_err(|e| Error::Protocol(e.to_string()))?;
        }
    }
    writer.flush().map_err(|e| Error::Protocol(e.to_string()))?;
    Ok(())
}

/// Handle a raw JSON request body and return a raw JSON response body.
pub fn handle_bytes<C: ConfirmPrompt>(service: &SignService<C>, raw: &[u8]) -> Vec<u8> {
    let response = match serde_json::from_slice::<Request>(raw) {
        Ok(req) => service.handle(req),
        Err(e) => Response::err("0", "protocol", format!("invalid request: {e}")),
    };
    serde_json::to_vec(&response).unwrap_or_else(|e| {
        format!(r#"{{"id":"0","ok":false,"error":{{"code":"internal","message":"{e}"}}}}"#)
            .into_bytes()
    })
}

/// Run a request/response loop until stdin EOF (native SignBridge protocol).
pub fn serve_stdio<C: ConfirmPrompt>(
    service: &SignService<C>,
    framing: Framing,
    input: impl BufRead,
    output: impl Write,
) -> Result<()> {
    serve_stdio_protocol(
        service,
        framing,
        crate::adapters::WireProtocol::SignBridge,
        input,
        output,
    )
}

/// Run a request/response loop with a chosen wire protocol (SignBridge / Web eID / AutoFirma).
pub fn serve_stdio_protocol<C: ConfirmPrompt>(
    service: &SignService<C>,
    framing: Framing,
    protocol: crate::adapters::WireProtocol,
    mut input: impl BufRead,
    mut output: impl Write,
) -> Result<()> {
    loop {
        let Some(raw) = read_frame(&mut input, framing)? else {
            break;
        };
        if raw.is_empty() {
            continue;
        }
        let out = match crate::adapters::handle_wire(protocol, service, &raw) {
            Ok(v) => serde_json::to_vec(&v).unwrap_or_else(|e| {
                format!(r#"{{"ok":false,"error":{{"code":"internal","message":"{e}"}}}}"#)
                    .into_bytes()
            }),
            Err(e) => serde_json::to_vec(&serde_json::json!({
                "ok": false,
                "error": {"code": e.code(), "message": e.to_string()}
            }))
            .unwrap_or_else(|_| b"{\"ok\":false}".to_vec()),
        };
        write_frame(&mut output, framing, &out)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AppConfig, AutoConfirm, SignService};
    use std::io::Cursor;

    #[test]
    fn ndjson_roundtrip_ping() {
        let svc = SignService::new(AppConfig::for_cli(), AutoConfirm::default());
        let mut out = Vec::new();
        let input = b"{\"id\":\"1\",\"method\":\"ping\"}\n";
        serve_stdio(&svc, Framing::Ndjson, Cursor::new(&input[..]), &mut out).unwrap();
        let line = std::str::from_utf8(&out).unwrap();
        assert!(line.contains("\"ok\":true"));
        assert!(line.contains("signbridge"));
    }
}

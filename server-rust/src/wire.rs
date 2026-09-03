//! PFUI wire format: a 4-byte big-endian length prefix followed by
//! (optionally lz4-frame compressed) JSON. protocol/PROTOCOL.md is normative.

use std::fmt;
use std::io::{self, Read};

/// 1 MiB ceiling per PFUI message, applied to the declared frame length and,
/// separately, to the decompressed payload while it expands.
pub const MAX_MESSAGE: usize = 1 << 20;

pub const HEADER_LEN: usize = 4;

/// One frame could not be decoded. Each variant maps onto exactly one of the
/// refusal strings in PROTOCOL.md.
#[derive(Debug)]
pub enum WireError {
    /// Declared payload length is zero or above MAX_MESSAGE -> "Bad length"
    BadLength(u32),
    /// Header complete but the payload stopped short of it -> "Truncated"
    Truncated { expected: usize, got: usize },
    /// lz4 frame incomplete: expansion exceeded MAX_MESSAGE, or the payload
    /// ended before the frame's EndMark -> "Bad frame"
    DecompressUnfinished,
    /// lz4 reports corruption (bad magic/header/checksum) -> "Failed to decode"
    DecompressCorrupt(String),
    /// Payload is not valid JSON -> "Failed to decode"
    Json(String),
    /// The payload's shape contradicts COMPRESS -> "Failed to decode".
    /// Compression is configuration on both ends and is not signalled on the
    /// wire, so a mismatch can only surface as a decode failure. The lz4 frame
    /// magic says which end is wrong, which is worth saying outright.
    CompressMismatch { compress_configured: bool },
}

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WireError::BadLength(n) => write!(f, "declared length {n} out of range"),
            WireError::Truncated { expected, got } => {
                write!(f, "truncated payload, expected {expected} bytes, got {got}")
            }
            WireError::DecompressUnfinished => {
                write!(f, "lz4 frame incomplete or over {MAX_MESSAGE} bytes")
            }
            WireError::DecompressCorrupt(e) => write!(f, "lz4 frame corrupt: {e}"),
            WireError::Json(e) => write!(f, "payload is not valid JSON: {e}"),
            WireError::CompressMismatch {
                compress_configured: true,
            } => write!(
                f,
                "payload is not an lz4 frame but COMPRESS is on: the sender is \
                 not compressing. COMPRESS must match at both ends"
            ),
            WireError::CompressMismatch {
                compress_configured: false,
            } => write!(
                f,
                "payload is an lz4 frame but COMPRESS is off: the sender is \
                 compressing. COMPRESS must match at both ends"
            ),
        }
    }
}

/// Io carries transport faults, a timeout among them; Wire carries protocol
/// faults.
#[derive(Debug)]
pub enum ReadError {
    Io(io::Error),
    Wire(WireError),
}

impl fmt::Display for ReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReadError::Io(e) => write!(f, "socket read failed: {e}"),
            ReadError::Wire(e) => e.fmt(f),
        }
    }
}

impl From<io::Error> for ReadError {
    fn from(e: io::Error) -> Self {
        ReadError::Io(e)
    }
}

impl From<WireError> for ReadError {
    fn from(e: WireError) -> Self {
        ReadError::Wire(e)
    }
}

enum Exactly {
    Complete(Vec<u8>),
    /// The peer closed before delivering all n bytes; `got` is what arrived.
    Closed {
        got: usize,
    },
}

/// Read exactly `n` bytes in at-most-`chunk` slices (SOCKET_BUFFER is a read
/// chunk, not a message limit).
fn read_exactly(reader: &mut impl Read, n: usize, chunk: usize) -> io::Result<Exactly> {
    let chunk = chunk.max(1);
    let mut buf = vec![0u8; n];
    let mut got = 0;
    while got < n {
        let want = chunk.min(n - got);
        match reader.read(&mut buf[got..got + want])? {
            0 => return Ok(Exactly::Closed { got }),
            r => got += r,
        }
    }
    Ok(Exactly::Complete(buf))
}

/// Read one frame and return its raw payload bytes.
///
/// Ok(None) means the peer closed before a complete header, which PROTOCOL.md
/// makes a non-error: there is no message. A payload short of the declared
/// length is Truncated, because the sender declared bytes it did not send.
pub fn read_frame_raw(reader: &mut impl Read, chunk: usize) -> Result<Option<Vec<u8>>, ReadError> {
    let header = match read_exactly(reader, HEADER_LEN, chunk)? {
        Exactly::Complete(h) => h,
        Exactly::Closed { .. } => return Ok(None),
    };
    let length = u32::from_be_bytes([header[0], header[1], header[2], header[3]]);
    // Rejected before buffering any payload
    if length == 0 || length as usize > MAX_MESSAGE {
        return Err(WireError::BadLength(length).into());
    }
    match read_exactly(reader, length as usize, chunk)? {
        Exactly::Complete(payload) => Ok(Some(payload)),
        Exactly::Closed { got } => Err(WireError::Truncated {
            expected: length as usize,
            got,
        }
        .into()),
    }
}

/// Read one frame and decode its payload to JSON.
pub fn read_frame(
    reader: &mut impl Read,
    chunk: usize,
    compress: bool,
) -> Result<Option<serde_json::Value>, ReadError> {
    match read_frame_raw(reader, chunk)? {
        None => Ok(None),
        Some(payload) => Ok(Some(decode(&payload, compress)?)),
    }
}

/// lz4 frame magic (0x184D2204, little-endian on the wire). Read only to tell
/// a compression mismatch from a payload that is genuinely damaged.
const LZ4_FRAME_MAGIC: [u8; 4] = [0x04, 0x22, 0x4d, 0x18];

/// Decode one frame's payload (the bytes after the length prefix). UDP
/// datagrams carry the payload alone, so this is also the datagram decoder.
pub fn decode(payload: &[u8], compress: bool) -> Result<serde_json::Value, WireError> {
    if payload.len() >= LZ4_FRAME_MAGIC.len() {
        let looks_lz4 = payload[..LZ4_FRAME_MAGIC.len()] == LZ4_FRAME_MAGIC;
        if looks_lz4 != compress {
            return Err(WireError::CompressMismatch {
                compress_configured: compress,
            });
        }
    }
    let plain;
    let bytes: &[u8] = if compress {
        plain = decompress_bounded(payload, MAX_MESSAGE)?;
        &plain
    } else {
        payload
    };
    serde_json::from_slice(bytes).map_err(|e| WireError::Json(e.to_string()))
}

/// Expand at most `limit` bytes, aborting while expanding rather than after,
/// so a decompression bomb is refused before it can be allocated.
///
/// An incomplete frame is DecompressUnfinished whether it exceeded the limit
/// or ended early. A complete frame is accepted whatever trails it.
pub fn decompress_bounded(blob: &[u8], limit: usize) -> Result<Vec<u8>, WireError> {
    let mut decoder = lz4_flex::frame::FrameDecoder::new(blob);
    let mut out = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        let want = buf.len().min(limit + 1 - out.len());
        match decoder.read(&mut buf[..want]) {
            Ok(0) => return Ok(out),
            Ok(n) => {
                out.extend_from_slice(&buf[..n]);
                if out.len() > limit {
                    return Err(WireError::DecompressUnfinished);
                }
            }
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                return Err(WireError::DecompressUnfinished)
            }
            Err(e) => return Err(WireError::DecompressCorrupt(e.to_string())),
        }
    }
}

/// Serialise one PFUI message, unframed. Used by the tests and the
/// conformance vectors; the daemon never encodes a message.
pub fn encode_payload(msg: &serde_json::Value, compress: bool) -> Result<Vec<u8>, WireError> {
    let json = serde_json::to_vec(msg).map_err(|e| WireError::Json(e.to_string()))?;
    let payload = if compress {
        lz4_flex::frame::FrameEncoder::new(Vec::new())
            .write_all_and_finish(&json)
            .map_err(|e| WireError::DecompressCorrupt(e.to_string()))?
    } else {
        json
    };
    if payload.len() > MAX_MESSAGE {
        return Err(WireError::BadLength(payload.len() as u32));
    }
    Ok(payload)
}

/// Prepend the length prefix to an already-serialised payload.
pub fn frame(payload: &[u8]) -> Result<Vec<u8>, WireError> {
    if payload.is_empty() || payload.len() > MAX_MESSAGE {
        return Err(WireError::BadLength(payload.len() as u32));
    }
    let mut out = Vec::with_capacity(HEADER_LEN + payload.len());
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

/// Serialise one PFUI message into a single length-prefixed frame.
pub fn encode(msg: &serde_json::Value, compress: bool) -> Result<Vec<u8>, WireError> {
    frame(&encode_payload(msg, compress)?)
}

trait WriteAllAndFinish {
    fn write_all_and_finish(self, data: &[u8]) -> io::Result<Vec<u8>>;
}

impl WriteAllAndFinish for lz4_flex::frame::FrameEncoder<Vec<u8>> {
    fn write_all_and_finish(mut self, data: &[u8]) -> io::Result<Vec<u8>> {
        use std::io::Write;
        self.write_all(data)?;
        self.finish().map_err(io::Error::other)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn compress(data: &[u8]) -> Vec<u8> {
        lz4_flex::frame::FrameEncoder::new(Vec::new())
            .write_all_and_finish(data)
            .unwrap()
    }

    #[test]
    fn bomb_is_refused_while_expanding() {
        // A small frame expanding past MAX_MESSAGE must die at the bound,
        // not after allocation
        let blob = compress(&vec![0u8; MAX_MESSAGE + 1]);
        assert!(blob.len() < MAX_MESSAGE);
        assert!(matches!(
            decompress_bounded(&blob, MAX_MESSAGE),
            Err(WireError::DecompressUnfinished)
        ));
    }

    #[test]
    fn output_of_exactly_the_limit_is_accepted() {
        let blob = compress(&vec![0u8; MAX_MESSAGE]);
        assert_eq!(
            decompress_bounded(&blob, MAX_MESSAGE).unwrap().len(),
            MAX_MESSAGE
        );
    }

    #[test]
    fn truncated_frame_is_unfinished_not_corrupt() {
        // A cleanly cut frame is Python's bare WireError ("Bad frame"), never
        // "Failed to decode"
        let blob = compress(br#"{"kind":"rr","AF4":[],"AF6":[]}"#);
        let cut = &blob[..blob.len() - 5];
        assert!(matches!(
            decompress_bounded(cut, MAX_MESSAGE),
            Err(WireError::DecompressUnfinished)
        ));
    }

    #[test]
    fn corrupt_magic_is_corrupt() {
        let mut blob = compress(br#"{}"#);
        blob[0] ^= 0xFF;
        assert!(matches!(
            decompress_bounded(&blob, MAX_MESSAGE),
            Err(WireError::DecompressCorrupt(_))
        ));
    }

    #[test]
    fn trailing_bytes_after_a_complete_frame_are_tolerated() {
        // python-lz4 parks a trailer in unused_data; refusing one would
        // reject traffic the Python daemon tolerates
        let mut blob = compress(b"payload");
        blob.extend_from_slice(b"trailing garbage");
        assert_eq!(decompress_bounded(&blob, MAX_MESSAGE).unwrap(), b"payload");
    }

    #[test]
    fn json_null_payload_decodes_to_null() {
        // The wire layer hands JSON null through; the receiver's shape check
        // is what turns it into "Invalid datatype"
        assert_eq!(decode(b"null", false).unwrap(), serde_json::Value::Null);
    }

    #[test]
    fn a_sender_that_does_not_compress_is_named_as_such() {
        let err = decode(br#"{"kind":"rr"}"#, true).expect_err("plain under COMPRESS");
        assert!(matches!(
            err,
            WireError::CompressMismatch {
                compress_configured: true
            }
        ));
        let text = err.to_string();
        assert!(text.contains("not compressing"), "{text}");
        assert!(text.contains("COMPRESS"), "{text}");
    }

    #[test]
    fn a_sender_that_compresses_when_we_do_not_is_named_as_such() {
        let compressed = compress(br#"{"kind":"rr"}"#);
        let err = decode(&compressed, false).expect_err("lz4 without COMPRESS");
        assert!(matches!(
            err,
            WireError::CompressMismatch {
                compress_configured: false
            }
        ));
        let text = err.to_string();
        assert!(text.contains("is compressing"), "{text}");
    }

    #[test]
    fn a_genuinely_damaged_frame_is_not_called_a_mismatch() {
        // Magic intact, body ruined: that is corruption, not a config error
        let mut blob = compress(b"payload");
        let n = blob.len();
        blob[n - 3] ^= 0xFF;
        assert!(!matches!(
            decompress_bounded(&blob, MAX_MESSAGE),
            Err(WireError::CompressMismatch { .. })
        ));
    }

    #[test]
    fn zero_chunk_still_makes_progress() {
        let frame_bytes = frame(b"{}").unwrap();
        let mut reader = frame_bytes.as_slice();
        assert_eq!(read_frame_raw(&mut reader, 0).unwrap().unwrap(), b"{}");
    }
}

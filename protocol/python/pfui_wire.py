"""PFUI wire format; a 4-byte big-endian length prefix followed by (optionally
lz4 compressed) JSON.

lz4 is an optional dependency: it is needed only when COMPRESS is on, and
HAVE_LZ4 reports whether it is available.

The length prefix replaces an in-band b"EOT" footer. lz4 output is arbitrary
binary and can contain those bytes, so a footer scan both truncated messages
early and missed real ends that straddled chunk boundaries.
"""

from json import dumps, loads
from struct import Struct

try:
    import lz4.frame
except ImportError:
    # Only a compressed payload needs it, and COMPRESS: False is how an operator
    # says there will not be one. Importing it unconditionally made the package
    # mandatory even then, so a resolver with compression off still could not
    # load this module.
    lz4 = None

HAVE_LZ4 = lz4 is not None

HEADER = Struct("!I")  # 4-byte big-endian payload length
MAX_MESSAGE = 1 << 20  # 1 MiB ceiling per PFUI message


class WireError(Exception):
    """A frame could not be decoded, or exceeded MAX_MESSAGE."""


class BadLength(WireError):
    """The declared payload length is zero or above MAX_MESSAGE.

    Distinct from Truncated so a receiver can send the distinct refusal
    PROTOCOL.md documents, and to match the C implementation's
    PFUI_BAD_LENGTH / PFUI_TRUNCATED, which the shared vectors also separate.
    """


class Truncated(WireError):
    """The header was complete but the payload stopped short of it."""


def _codec():
    """lz4.frame, or a WireError naming what to install.

    Raised rather than returned so a caller that asked for compression cannot
    silently send plain JSON, which the far end would refuse as a mismatch.
    """
    if not HAVE_LZ4:
        raise WireError(
            "COMPRESS is on but the lz4 package is not installed; install "
            "py3-lz4, or set COMPRESS: False on the resolver and the firewall"
        )
    return lz4.frame


def encode_payload(msg: dict, compress: bool = True) -> bytes:
    """Serialise one PFUI message, unframed. UDP datagrams are self-delimiting
    and carry the payload alone; only the TCP stream needs a length prefix.
    """
    payload = dumps(msg).encode("utf-8")
    if compress:
        payload = _codec().compress(payload)
    if len(payload) > MAX_MESSAGE:
        raise WireError(f"payload of {len(payload)} bytes exceeds {MAX_MESSAGE}")
    return payload


def frame(payload: bytes) -> bytes:
    """Prepend the length prefix to an already-serialised payload."""
    if len(payload) > MAX_MESSAGE:
        raise WireError(f"payload of {len(payload)} bytes exceeds {MAX_MESSAGE}")
    return HEADER.pack(len(payload)) + payload


def encode(msg: dict, compress: bool = True) -> bytes:
    """Serialise one PFUI message into a single length-prefixed frame."""
    return frame(encode_payload(msg, compress=compress))


def decompress_bounded(blob: bytes, limit: int = MAX_MESSAGE) -> bytes:
    """Expand at most `limit` bytes, so a decompression bomb is refused before
    it can be allocated. `max_length` caps what the decompressor produces, so an
    oversize frame stops at the ceiling with `eof` still unset.
    """
    decompressor = _codec().LZ4FrameDecompressor()
    out = decompressor.decompress(blob, max_length=limit)
    if not decompressor.eof:
        raise WireError(f"decompressed payload exceeds {limit} bytes")
    return out


def decode(payload: bytes, compress: bool = True) -> dict:
    """Decode one frame's payload (the bytes after the length prefix)."""
    if compress:
        payload = decompress_bounded(payload)
    return loads(payload)


def read_frame(recv_exactly, compress: bool = True):
    """Read one frame using `recv_exactly(n) -> bytes | None`.

    Returns None when the peer closed before sending a header; raises BadLength
    or Truncated (both WireError) so a caller can report which it was.
    """
    header = recv_exactly(HEADER.size)
    if header is None:
        return None
    (length,) = HEADER.unpack(header)
    if not 0 < length <= MAX_MESSAGE:
        raise BadLength(f"declared length {length} out of range")
    payload = recv_exactly(length)
    if payload is None:
        raise Truncated(f"truncated payload, expected {length} bytes")
    return decode(payload, compress=compress)


def decode_stream(blob: bytes, chunk: int = 512, compress: bool = True):
    """Decode a frame fed in fixed-size slices, the way recv() delivers it."""
    pos = 0

    def reader(n):
        nonlocal pos
        buf = b""
        while len(buf) < n:
            if pos >= len(blob):
                return None
            take = min(chunk, n - len(buf))
            buf += blob[pos : pos + take]
            pos += take
        return buf

    return read_frame(reader, compress=compress)

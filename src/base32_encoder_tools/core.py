"""Core RFC 4648 base32 encoding and decoding.

The implementation is deliberately small: it exposes only the standard
alphabet, accepts lower-case input on decode, and offers an optional
checksum layer for callers who want a cheap integrity check without
pulling in a hash library.
"""

from __future__ import annotations

from typing import Final

# The canonical RFC 4648 base32 alphabet. Exposed so callers can inspect it
# without re-declaring the string.
ALPHABET: Final[str] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

_PAD: Final[str] = "="

# Reverse lookup table for decoding. Lower-case letters map to the same
# values as their upper-case counterparts, which is why decode() is
# case-insensitive.
_REVERSE: Final[dict[str, int]] = {c: i for i, c in enumerate(ALPHABET)}
_REVERSE.update({c.lower(): i for i, c in enumerate(ALPHABET)})


class DecodeError(ValueError):
    """Raised when a string is not valid base32."""


class ChecksumError(ValueError):
    """Raised when a checksum does not match the decoded payload."""


# A small checksum: the sum of the payload bytes modulo 256, rendered as
# two base32 characters. It is not cryptographic; it catches transcription
# mistakes, which is the common failure mode for short encoded tokens.
_CHECKSUM_MOD: Final[int] = 256


def _checksum_bytes(payload: bytes) -> bytes:
    """Return the two-byte checksum suffix for *payload*.

    The checksum is ``sum(payload) % 256`` encoded big-endian in two bytes.
    Two bytes keep the suffix aligned with base32's 5-bit groups without
    needing partial padding of its own.
    """
    total = sum(payload) % _CHECKSUM_MOD
    return bytes([(total >> 8) & 0xFF, total & 0xFF])


def encode(data: bytes) -> str:
    """Encode *data* as an RFC 4648 base32 string with padding.

    The output uses upper-case letters and the digits 2-7. Padding is
    included so the result is a multiple of 8 characters, matching the
    specification.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("encode() requires bytes or bytearray")
    data = bytes(data)
    if not data:
        return ""

    bits = 0
    value = 0
    out: list[str] = []
    for byte in data:
        value = (value << 8) | byte
        bits += 8
        while bits >= 5:
            bits -= 5
            out.append(ALPHABET[(value >> bits) & 0x1F])
    if bits:
        out.append(ALPHABET[(value << (5 - bits)) & 0x1F])

    # Pad to a multiple of 8 characters. This is required by RFC 4648 and
    # makes the output length predictable for callers.
    while len(out) % 8:
        out.append(_PAD)
    return "".join(out)


def decode(text: str) -> bytes:
    """Decode an RFC 4648 base32 string.

    The input is case-insensitive: both ``"MZXW6"`` and ``"mzxw6"`` decode
    to the same bytes. Padding characters are accepted but not required,
    because many real-world producers omit trailing ``=``. Whitespace is
    rejected rather than silently stripped, so corrupted input fails loudly.
    """
    if not isinstance(text, str):
        raise TypeError("decode() requires str")

    # Strip a single trailing run of '=' characters. Anything else is data.
    stripped = text.rstrip(_PAD)
    if _PAD in stripped:
        raise DecodeError("padding is only allowed at the end")

    bits = 0
    value = 0
    out = bytearray()
    for ch in stripped:
        try:
            digit = _REVERSE[ch]
        except KeyError:
            raise DecodeError(f"invalid base32 character: {ch!r}") from None
        value = (value << 5) | digit
        bits += 5
        if bits >= 8:
            bits -= 8
            out.append((value >> bits) & 0xFF)

    # Any leftover bits must be zero; otherwise the input was truncated
    # mid-character and the trailing bits are not a valid encoding.
    if bits and (value & ((1 << bits) - 1)):
        raise DecodeError("non-zero trailing bits")
    return bytes(out)


def encode_with_checksum(data: bytes) -> str:
    """Encode *data* with a trailing checksum.

    The result is ``encode(data + checksum_bytes(data))``. The checksum is
    computed over the original payload, not over the padded encoding, so
    callers can verify it without re-encoding.
    """
    payload = bytes(data)
    return encode(payload + _checksum_bytes(payload))


def decode_with_checksum(text: str) -> bytes:
    """Decode a string produced by :func:`encode_with_checksum`.

    Raises :class:`ChecksumError` if the checksum does not match. Raises
    :class:`DecodeError` for malformed base32, so the two failure modes
    stay distinguishable.
    """
    raw = decode(text)
    if len(raw) < 2:
        raise ChecksumError("input is too short to contain a checksum")
    payload, suffix = raw[:-2], raw[-2:]
    expected = _checksum_bytes(payload)
    if suffix != expected:
        raise ChecksumError("checksum mismatch")
    return payload

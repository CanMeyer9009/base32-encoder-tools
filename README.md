# base32-encoder-tools

RFC 4648 base32 encoding and decoding with case-insensitive input and an optional checksum.

```python
from base32_encoder_tools import encode, decode, encode_with_checksum, decode_with_checksum

encode(b"foobar")          # 'MZXW6YTBOI======'
decode("mzxw6ytboi======") # b'foobar'

token = encode_with_checksum(b"hello")
decode_with_checksum(token)  # b'hello'
```

## Why this exists

Base32 shows up in places where a human might retype a value: TOTP secrets, recovery codes, short identifiers. The standard library has `base64`, but no base32, and most base32 snippets on the internet either reject lower-case input or silently strip whitespace. This library makes one decision and sticks to it: decoding is case-insensitive, padding is optional, and anything else that is not a strict base32 character is an error. That trade-off means a typo like `MZ XW6` fails immediately instead of producing a plausible-but-wrong byte string.

The checksum layer is a two-byte sum of the payload modulo 256, encoded as part of the base32 string. It is not cryptographic and is not meant to be. It catches the common case of a single character being mistyped when copying a token, and it keeps the dependency list at zero.

## API

- `ALPHABET` — the RFC 4648 alphabet, `"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"`.
- `encode(data: bytes) -> str` — encode with padding.
- `decode(text: str) -> bytes` — decode; accepts lower-case and missing padding.
- `encode_with_checksum(data: bytes) -> str` — encode with a trailing checksum.
- `decode_with_checksum(text: str) -> bytes` — decode and verify the checksum.
- `DecodeError` — raised for malformed base32.
- `ChecksumError` — raised when the checksum does not match.

## The awkward edge

`decode` rejects non-zero trailing bits. A five-character input like `MZXW7` looks valid but the final character carries bits that do not belong to any output byte, and the RFC requires them to be zero. If you have a producer that emits those bits set, this library will refuse the input rather than guess.

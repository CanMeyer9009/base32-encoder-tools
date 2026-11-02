import unittest

from base32_encoder_tools import (
    ALPHABET,
    ChecksumError,
    DecodeError,
    decode,
    decode_with_checksum,
    encode,
    encode_with_checksum,
)


class EncodeTests(unittest.TestCase):
    def test_empty(self):
        self.assertEqual(encode(b""), "")

    def test_rfc4648_vectors(self):
        # Vectors from RFC 4648 section 10.
        self.assertEqual(encode(b""), "")
        self.assertEqual(encode(b"f"), "MY======")
        self.assertEqual(encode(b"fo"), "MZXQ====")
        self.assertEqual(encode(b"foo"), "MZXW6===")
        self.assertEqual(encode(b"foob"), "MZXW6YQ=")
        self.assertEqual(encode(b"fooba"), "MZXW6YTB")
        self.assertEqual(encode(b"foobar"), "MZXW6YTBOI======")

    def test_accepts_bytearray(self):
        self.assertEqual(encode(bytearray(b"foo")), "MZXW6===")

    def test_rejects_str(self):
        with self.assertRaises(TypeError):
            encode("foo")  # type: ignore[arg-type]

    def test_alphabet_is_rfc4648(self):
        self.assertEqual(ALPHABET, "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")


class DecodeTests(unittest.TestCase):
    def test_round_trip_all_lengths(self):
        for length in range(0, 33):
            data = bytes(range(length))
            self.assertEqual(decode(encode(data)), data)

    def test_case_insensitive(self):
        self.assertEqual(decode("mzxw6"), b"foo")
        self.assertEqual(decode("MZXW6"), b"foo")
        self.assertEqual(decode("MzXw6"), b"foo")

    def test_padding_optional(self):
        self.assertEqual(decode("MZXW6"), b"foo")
        self.assertEqual(decode("MZXW6==="), b"foo")

    def test_rejects_invalid_character(self):
        # '1' is not in the base32 alphabet.
        with self.assertRaises(DecodeError):
            decode("MZXW1")

    def test_rejects_interior_padding(self):
        with self.assertRaises(DecodeError):
            decode("MZ=XW6")

    def test_rejects_non_zero_trailing_bits(self):
        # 'MZXW7' differs from 'MZXW6' only in the low bit of the final
        # character; that bit is padding and must be zero.
        with self.assertRaises(DecodeError):
            decode("MZXW7")

    def test_rejects_whitespace(self):
        with self.assertRaises(DecodeError):
            decode("MZ XW6")

    def test_rejects_non_str(self):
        with self.assertRaises(TypeError):
            decode(b"MZXW6")  # type: ignore[arg-type]


class ChecksumTests(unittest.TestCase):
    def test_round_trip(self):
        for data in (b"", b"f", b"foo", b"foobar", bytes(range(256))):
            self.assertEqual(decode_with_checksum(encode_with_checksum(data)), data)

    def test_detects_single_byte_change(self):
        encoded = encode_with_checksum(b"hello")
        # Flip a character in the payload region; the checksum should fail.
        corrupted = ("A" if encoded[0] != "A" else "B") + encoded[1:]
        with self.assertRaises(ChecksumError):
            decode_with_checksum(corrupted)

    def test_rejects_short_input(self):
        # An empty payload cannot carry a two-byte checksum.
        with self.assertRaises(ChecksumError):
            decode_with_checksum("")

    def test_malformed_base32_still_raises_decode_error(self):
        with self.assertRaises(DecodeError):
            decode_with_checksum("1")

    def test_checksum_is_deterministic(self):
        self.assertEqual(encode_with_checksum(b"foo"), encode_with_checksum(b"foo"))


if __name__ == "__main__":
    unittest.main()

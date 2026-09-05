import pathlib
import struct
import sys
import unittest


sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from verify_attestation import (  # noqa: E402
    TPM_GENERATED_VALUE,
    TPM_ST_ATTEST_NV,
    VerificationError,
    parse_nv_attestation,
    verify,
)


def tpm2b(value: bytes) -> bytes:
    return struct.pack(">H", len(value)) + value


def specimen(nonce: bytes, generation: int, nv_name: bytes) -> bytes:
    return b"".join(
        (
            struct.pack(">IH", TPM_GENERATED_VALUE, TPM_ST_ATTEST_NV),
            tpm2b(bytes.fromhex("000b") + b"q" * 32),
            tpm2b(nonce),
            struct.pack(">QII?Q", 1234, 2, 3, True, 99),
            tpm2b(nv_name),
            struct.pack(">H", 0),
            tpm2b(generation.to_bytes(8, "big")),
        )
    )


class NvAttestationTests(unittest.TestCase):
    def setUp(self):
        self.nonce = b"client-nonce-32-bytes-value!!!"[:32]
        self.nv_name = bytes.fromhex("000b") + b"n" * 32
        self.parsed = parse_nv_attestation(specimen(self.nonce, 71, self.nv_name))

    def test_accepts_exact_nonce_generation_and_name(self):
        verify(self.parsed, self.nonce, 71, self.nv_name.hex())

    def test_rejects_replayed_nonce(self):
        with self.assertRaisesRegex(VerificationError, "client nonce"):
            verify(self.parsed, b"different", 71, self.nv_name.hex())

    def test_rejects_stale_generation(self):
        with self.assertRaisesRegex(VerificationError, "generation"):
            verify(self.parsed, self.nonce, 72, self.nv_name.hex())

    def test_rejects_wrong_pinned_name(self):
        wrong = bytearray(self.nv_name)
        wrong[-1] ^= 1
        with self.assertRaisesRegex(VerificationError, "pinned NV Name"):
            verify(self.parsed, self.nonce, 71, bytes(wrong).hex())

    def test_rejects_trailing_data(self):
        with self.assertRaisesRegex(VerificationError, "trailing bytes"):
            parse_nv_attestation(specimen(self.nonce, 71, self.nv_name) + b"x")


if __name__ == "__main__":
    unittest.main()

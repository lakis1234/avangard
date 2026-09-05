#!/usr/bin/env python3
"""Strict verifier for the TPMS_ATTEST emitted by TPM2_NV_Certify."""

from __future__ import annotations

import argparse
import json
import pathlib
import struct
import sys
from dataclasses import asdict, dataclass


TPM_GENERATED_VALUE = 0xFF544347
TPM_ST_ATTEST_NV = 0x8014


class VerificationError(ValueError):
    pass


@dataclass(frozen=True)
class NvAttestation:
    magic: int
    attest_type: int
    qualified_signer_hex: str
    extra_data_hex: str
    clock: int
    reset_count: int
    restart_count: int
    safe: bool
    firmware_version: int
    index_name_hex: str
    offset: int
    nv_contents_hex: str
    generation: int


class Reader:
    def __init__(self, data: bytes):
        self.data = data
        self.offset = 0

    def take(self, size: int) -> bytes:
        end = self.offset + size
        if end > len(self.data):
            raise VerificationError(
                f"truncated TPMS_ATTEST at byte {self.offset}: need {size} more bytes"
            )
        value = self.data[self.offset:end]
        self.offset = end
        return value

    def u8(self) -> int:
        return self.take(1)[0]

    def u16(self) -> int:
        return struct.unpack(">H", self.take(2))[0]

    def u32(self) -> int:
        return struct.unpack(">I", self.take(4))[0]

    def u64(self) -> int:
        return struct.unpack(">Q", self.take(8))[0]

    def tpm2b(self) -> bytes:
        return self.take(self.u16())


def parse_nv_attestation(data: bytes) -> NvAttestation:
    reader = Reader(data)
    magic = reader.u32()
    attest_type = reader.u16()
    qualified_signer = reader.tpm2b()
    extra_data = reader.tpm2b()
    clock = reader.u64()
    reset_count = reader.u32()
    restart_count = reader.u32()
    safe_raw = reader.u8()
    firmware_version = reader.u64()
    index_name = reader.tpm2b()
    offset = reader.u16()
    nv_contents = reader.tpm2b()

    if reader.offset != len(data):
        raise VerificationError(
            f"trailing bytes after TPMS_ATTEST: {len(data) - reader.offset}"
        )
    if safe_raw not in (0, 1):
        raise VerificationError(f"invalid TPMS_CLOCK_INFO.safe value: {safe_raw}")
    if not nv_contents:
        raise VerificationError("NV_Certify returned empty NV contents")

    return NvAttestation(
        magic=magic,
        attest_type=attest_type,
        qualified_signer_hex=qualified_signer.hex(),
        extra_data_hex=extra_data.hex(),
        clock=clock,
        reset_count=reset_count,
        restart_count=restart_count,
        safe=bool(safe_raw),
        firmware_version=firmware_version,
        index_name_hex=index_name.hex(),
        offset=offset,
        nv_contents_hex=nv_contents.hex(),
        generation=int.from_bytes(nv_contents, "big"),
    )


def normalize_hex(value: str) -> str:
    compact = "".join(value.strip().split()).lower()
    if compact.startswith("0x"):
        compact = compact[2:]
    try:
        bytes.fromhex(compact)
    except ValueError as error:
        raise VerificationError(f"invalid expected NV Name hex: {value!r}") from error
    return compact


def verify(
    attestation: NvAttestation,
    expected_nonce: bytes,
    expected_generation: int,
    expected_nv_name_hex: str,
) -> None:
    checks = (
        (
            attestation.magic == TPM_GENERATED_VALUE,
            f"magic 0x{attestation.magic:08x} is not TPM_GENERATED_VALUE",
        ),
        (
            attestation.attest_type == TPM_ST_ATTEST_NV,
            f"attestation type 0x{attestation.attest_type:04x} is not TPM_ST_ATTEST_NV",
        ),
        (
            bytes.fromhex(attestation.extra_data_hex) == expected_nonce,
            "qualifying data does not equal the client nonce",
        ),
        (
            attestation.index_name_hex == normalize_hex(expected_nv_name_hex),
            "certified NV Name does not equal the pinned NV Name",
        ),
        (attestation.offset == 0, f"NV_Certify offset is {attestation.offset}, not 0"),
        (
            len(bytes.fromhex(attestation.nv_contents_hex)) == 8,
            "certified counter is not exactly 8 bytes",
        ),
        (
            attestation.generation == expected_generation,
            f"certified generation {attestation.generation} != expected {expected_generation}",
        ),
    )
    failures = [message for ok, message in checks if not ok]
    if failures:
        raise VerificationError("; ".join(failures))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--attestation", required=True, type=pathlib.Path)
    parser.add_argument("--nonce", required=True, type=pathlib.Path)
    parser.add_argument("--generation", required=True, type=int)
    parser.add_argument("--nv-name", required=True)
    parser.add_argument("--json-out", type=pathlib.Path)
    args = parser.parse_args()

    try:
        parsed = parse_nv_attestation(args.attestation.read_bytes())
        verify(parsed, args.nonce.read_bytes(), args.generation, args.nv_name)
    except (OSError, VerificationError) as error:
        print(f"NV_ATTESTATION_VERIFY=REJECTED: {error}", file=sys.stderr)
        return 1

    record = asdict(parsed)
    record["magic"] = f"0x{parsed.magic:08x}"
    record["attest_type"] = f"0x{parsed.attest_type:04x}"
    if args.json_out:
        args.json_out.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    print(
        "NV_ATTESTATION_VERIFY=PASS "
        f"generation={parsed.generation} nonce={parsed.extra_data_hex} "
        f"nv_name={parsed.index_name_hex}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

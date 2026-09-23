"""Shared x64dbg named-pipe wire protocol.

This module is the single Python source of truth for the framing shared by the
x64dbg bridge, orchestrator-facing code, and tests. The native plugin mirrors
this ABI in C++ and is covered by contract tests.
"""

from __future__ import annotations

import json
import struct
from dataclasses import dataclass
from enum import IntEnum

PIPE_MAGIC = b"X64A"
PIPE_VERSION = 1
MAX_PAYLOAD_BYTES = 64 * 1024 * 1024
PIPE_HEADER_STRUCT = struct.Struct("<4sHHII")
PIPE_HEADER_SIZE = PIPE_HEADER_STRUCT.size


class MsgType(IntEnum):
    COMMAND = 0x01
    RESPONSE = 0x02
    EVENT = 0x03
    HEARTBEAT = 0x04
    ACK = 0x05
    ERROR = 0xFF


@dataclass(frozen=True)
class PipeHeader:
    msg_type: MsgType
    payload_len: int
    seq_id: int
    version: int = PIPE_VERSION

    def pack(self) -> bytes:
        if self.payload_len < 0 or self.payload_len > MAX_PAYLOAD_BYTES:
            raise ValueError(f"Payload too large: {self.payload_len} bytes")
        return PIPE_HEADER_STRUCT.pack(
            PIPE_MAGIC,
            self.version,
            int(self.msg_type),
            self.payload_len,
            self.seq_id,
        )

    @classmethod
    def unpack(cls, data: bytes) -> "PipeHeader":
        if len(data) != PIPE_HEADER_SIZE:
            raise ValueError(
                f"Expected {PIPE_HEADER_SIZE}-byte header, got {len(data)} bytes"
            )
        magic, version, msg_type, payload_len, seq_id = PIPE_HEADER_STRUCT.unpack(data)
        if magic != PIPE_MAGIC:
            raise ValueError(f"Invalid magic: {magic!r}")
        if version != PIPE_VERSION:
            raise ValueError(f"Unsupported protocol version: {version}")
        if payload_len > MAX_PAYLOAD_BYTES:
            raise ValueError(f"Payload too large: {payload_len} bytes")
        return cls(
            msg_type=MsgType(msg_type),
            payload_len=payload_len,
            seq_id=seq_id,
            version=version,
        )


@dataclass(frozen=True)
class PipeMessage:
    msg_type: MsgType
    seq_id: int
    payload: dict

    HEADER_SIZE = PIPE_HEADER_SIZE

    def pack(self) -> bytes:
        payload_bytes = json.dumps(self.payload).encode("utf-8")
        header = PipeHeader(
            msg_type=self.msg_type,
            payload_len=len(payload_bytes),
            seq_id=self.seq_id,
        )
        return header.pack() + payload_bytes

    @classmethod
    def unpack(cls, data: bytes) -> "PipeMessage":
        if len(data) < PIPE_HEADER_SIZE:
            raise ValueError("Incomplete message header")
        header = PipeHeader.unpack(data[:PIPE_HEADER_SIZE])
        expected_size = PIPE_HEADER_SIZE + header.payload_len
        if len(data) != expected_size:
            raise ValueError(
                f"Message length mismatch: expected {expected_size}, got {len(data)}"
            )
        payload_bytes = data[PIPE_HEADER_SIZE:expected_size]
        payload = json.loads(payload_bytes) if payload_bytes else {}
        return cls(
            msg_type=header.msg_type,
            seq_id=header.seq_id,
            payload=payload,
        )

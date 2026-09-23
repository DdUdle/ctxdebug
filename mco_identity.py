"""Cross-debugger address and image identity contracts.

Runtime addresses are never treated as IDA addresses directly. An identity
carries the runtime module base and RVA together with PE build metadata so a
pivot can prove that the IDB represents the same image before decompiling it.
"""

from __future__ import annotations

from dataclasses import dataclass
import os
import re
from typing import Any


def _int_value(value: Any) -> int | None:
    if value is None or value == "":
        return None
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    text = str(value).strip()
    try:
        return int(text, 0)
    except ValueError:
        try:
            return int(text, 16)
        except ValueError:
            return None


def module_stem(value: str | None) -> str:
    if not value:
        return ""
    # Runtime/IDA paths are usually Windows paths even when contract tests run
    # on another OS. Normalize both separator styles explicitly.
    basename = re.split(r"[\\/]", value)[-1]
    return os.path.splitext(basename)[0].lower()


def pe_build_id(timestamp: int | None, size_of_image: int | None) -> str | None:
    if timestamp is None or size_of_image is None:
        return None
    return f"pe:{timestamp:08x}:{size_of_image:x}"


@dataclass(frozen=True)
class AddressIdentity:
    address: int
    source: str
    module: str | None = None
    runtime_base: int | None = None
    rva: int | None = None
    pe_timestamp: int | None = None
    pe_size_of_image: int | None = None
    image_hash: str | None = None

    @property
    def build_id(self) -> str | None:
        return pe_build_id(self.pe_timestamp, self.pe_size_of_image)

    @classmethod
    def from_runtime_module(
        cls,
        address: int,
        module: dict,
        source: str,
    ) -> "AddressIdentity":
        base = _int_value(module.get("_base_int", module.get("base")))
        rva = address - base if base is not None and address >= base else None
        return cls(
            address=address,
            source=source,
            module=module.get("name") or module.get("path"),
            runtime_base=base,
            rva=rva,
            pe_timestamp=_int_value(module.get("timestamp", module.get("pe_timestamp"))),
            pe_size_of_image=_int_value(
                module.get("size_of_image", module.get("pe_size_of_image", module.get("size")))
            ),
            image_hash=(module.get("image_hash") or module.get("md5") or None),
        )

    def as_dict(self) -> dict:
        return {
            "source": self.source,
            "module": self.module,
            "runtime_base": hex(self.runtime_base) if self.runtime_base is not None else None,
            "address": hex(self.address),
            "rva": hex(self.rva) if self.rva is not None else None,
            "pe_timestamp": hex(self.pe_timestamp) if self.pe_timestamp is not None else None,
            "pe_size_of_image": (
                hex(self.pe_size_of_image) if self.pe_size_of_image is not None else None
            ),
            "image_hash": self.image_hash,
            "build_id": self.build_id,
        }


_TIMESTAMP_PAREN_RE = re.compile(
    r"^\s*Timestamp:.*\(([0-9a-fA-F]{8})\)\s*$", re.IGNORECASE
)
_TIMESTAMP_HEX_RE = re.compile(
    r"^\s*Timestamp:\s*(?:0x)?([0-9a-fA-F]{8})\s*$", re.IGNORECASE
)
_IMAGE_SIZE_RE = re.compile(
    r"^\s*ImageSize:\s*(?:0x)?([0-9a-fA-F]+)\s*$", re.IGNORECASE
)
_IMAGE_NAME_RE = re.compile(r"^\s*Image name:\s*(.+?)\s*$", re.IGNORECASE)
_IMAGE_PATH_RE = re.compile(r"^\s*Image path:\s*(.+?)\s*$", re.IGNORECASE)


def parse_windbg_lmv_build(text: str) -> dict:
    result = {
        "pe_timestamp": None,
        "pe_size_of_image": None,
        "image_name": None,
        "image_path": None,
    }
    for line in text.splitlines():
        match = _TIMESTAMP_PAREN_RE.match(line) or _TIMESTAMP_HEX_RE.match(line)
        if match:
            result["pe_timestamp"] = int(match.group(1), 16)
            continue
        match = _IMAGE_SIZE_RE.match(line)
        if match:
            result["pe_size_of_image"] = int(match.group(1), 16)
            continue
        match = _IMAGE_NAME_RE.match(line)
        if match:
            result["image_name"] = match.group(1).strip()
            continue
        match = _IMAGE_PATH_RE.match(line)
        if match:
            result["image_path"] = match.group(1).strip()
    result["build_id"] = pe_build_id(
        result["pe_timestamp"], result["pe_size_of_image"]
    )
    return result


def compare_identity_to_ida(identity: AddressIdentity, ida_info: dict) -> dict:
    checks: dict[str, dict] = {}
    mismatches: list[str] = []

    runtime_stem = module_stem(identity.module)
    ida_stem = module_stem(ida_info.get("input_file"))
    if runtime_stem and ida_stem:
        match = runtime_stem == ida_stem
        checks["module"] = {
            "runtime": runtime_stem,
            "ida": ida_stem,
            "match": match,
        }
        if not match:
            mismatches.append("module")

    ida_timestamp = _int_value(ida_info.get("pe_timestamp"))
    if identity.pe_timestamp is not None and ida_timestamp is not None:
        match = identity.pe_timestamp == ida_timestamp
        checks["pe_timestamp"] = {
            "runtime": hex(identity.pe_timestamp),
            "ida": hex(ida_timestamp),
            "match": match,
        }
        if not match:
            mismatches.append("pe_timestamp")

    ida_size = _int_value(ida_info.get("pe_size_of_image"))
    if identity.pe_size_of_image is not None and ida_size is not None:
        match = identity.pe_size_of_image == ida_size
        checks["pe_size_of_image"] = {
            "runtime": hex(identity.pe_size_of_image),
            "ida": hex(ida_size),
            "match": match,
        }
        if not match:
            mismatches.append("pe_size_of_image")

    ida_hash = (ida_info.get("input_md5") or ida_info.get("image_hash") or "").lower()
    runtime_hash = (identity.image_hash or "").lower()
    if runtime_hash and ida_hash:
        match = runtime_hash == ida_hash
        checks["image_hash"] = {
            "runtime": runtime_hash,
            "ida": ida_hash,
            "match": match,
        }
        if not match:
            mismatches.append("image_hash")

    build_fields = {
        name for name in ("pe_timestamp", "pe_size_of_image", "image_hash")
        if name in checks
    }
    strong_build_evidence = (
        "image_hash" in build_fields
        or {"pe_timestamp", "pe_size_of_image"}.issubset(build_fields)
    )
    return {
        "compatible": not mismatches,
        "build_verified": strong_build_evidence and not any(
            name in mismatches for name in build_fields
        ),
        "verified_fields": list(checks),
        "checks": checks,
        "mismatches": mismatches,
        "runtime_build_id": identity.build_id,
        "ida_build_id": pe_build_id(ida_timestamp, ida_size),
        "ida_input_file": ida_info.get("input_file"),
        "ida_input_md5": ida_info.get("input_md5"),
    }

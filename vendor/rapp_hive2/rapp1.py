"""RAPP/1 frame math for rapp-hive/2 (Python stdlib + ``cryptography``).

Canonical JSON (the RFC 8785 subset RAPP/1 uses), particle/wave hashing, RAPPID
binding and detached EdDSA JWS. Pure: bytes in, verdict out; no filesystem,
network or OS dependency, so every platform reaches the same verdict.

particle = H("rapp/1:particle", payload)                -- WHAT a frame says
wave     = H("rapp/1:wave", frame - {frame_hash, sig})  -- WHERE/WHEN it said it
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from typing import Any

MAX_JSON_BYTES = 1024 * 1024
MAX_SAFE_INTEGER = 2**53 - 1
MAX_DEPTH = 48
MAX_MEMBERS = 10000
FRAME_KEYS = frozenset(
    {"spec", "kind", "stream_id", "seq", "utc", "payload", "payload_hash", "frame_hash", "prev", "prev_wave", "sig"}
)
HEAD_KEYS = ("stream_id", "seq", "payload_hash", "frame_hash")
HASH_RE = re.compile(r"[0-9a-f]{64}\Z")
LCLABEL = r"[a-z0-9]+(?:-[a-z0-9]+)*"  # RAPP/1 section 6.1.1
RAPPID_RE = re.compile(rf"rappid:@({LCLABEL})/({LCLABEL}):([0-9a-f]{{64}})\Z")
MEMORY_STREAM_RE = re.compile(rf"(rappid:@{LCLABEL}/{LCLABEL}:[0-9a-f]{{64}}):({LCLABEL})\Z")
KIND_RE = re.compile(rf"({LCLABEL})\.({LCLABEL})\Z")
UTC_RE = re.compile(r"([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})\.[0-9]{3}Z\Z")


class Refusal(Exception):
    """A typed, terminal refusal. ``code`` is stable machine data."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


def _string(value: str) -> str:
    try:
        value.encode("utf-8")
    except UnicodeError as exc:
        raise Refusal("REFUSE_CANONICAL_JSON", "Unpaired Unicode surrogates are forbidden.") from exc
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def utf16_sorted(keys: Any) -> list[str]:
    """Object keys in canonical (JCS, UTF-16 code unit) order: the order every engine walks objects in."""
    try:
        return sorted(keys, key=lambda key: key.encode("utf-16be"))
    except UnicodeError as exc:
        raise Refusal("REFUSE_CANONICAL_JSON", "Invalid Unicode object key.") from exc


def _canonical(value: object, depth: int = 0) -> str:
    if depth > MAX_DEPTH:
        raise Refusal("REFUSE_CANONICAL_JSON", "JSON nesting exceeds the bounded profile.")
    if value is None:
        return "null"
    if type(value) is bool:
        return "true" if value else "false"
    if type(value) is int:
        if abs(value) > MAX_SAFE_INTEGER:
            raise Refusal("REFUSE_CANONICAL_JSON", "Integers must be IEEE754 safe integers.")
        return str(value)
    if type(value) is str:
        return _string(value)
    if type(value) is list:
        if len(value) > MAX_MEMBERS:
            raise Refusal("REFUSE_CANONICAL_JSON", "JSON arrays exceed the bounded profile.")
        return "[" + ",".join(_canonical(item, depth + 1) for item in value) + "]"
    if type(value) is dict:
        if len(value) > MAX_MEMBERS or any(type(key) is not str for key in value):
            raise Refusal("REFUSE_CANONICAL_JSON", "Bounded string-keyed objects are required.")
        keys = utf16_sorted(value)
        return "{" + ",".join(_string(key) + ":" + _canonical(value[key], depth + 1) for key in keys) + "}"
    raise Refusal("REFUSE_CANONICAL_JSON", "Floats, subclasses and non-JSON values are forbidden.")


def canonical(value: object, *, limit: int = MAX_JSON_BYTES) -> bytes:
    """RFC 8785 (JCS) subset: UTF-16 key order, safe integers, no floats."""
    try:
        data = _canonical(value).encode("utf-8")
    except RecursionError as exc:
        raise Refusal("REFUSE_CANONICAL_JSON", "JSON nesting exceeds the bounded profile.") from exc
    if len(data) > limit:
        raise Refusal("REFUSE_JSON_SIZE", "JSON exceeds its byte limit.")
    return data


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise Refusal("REFUSE_CANONICAL_JSON", "Duplicate JSON keys are forbidden.")
        result[key] = value
    return result


def _no_float(_value: str) -> Any:
    raise Refusal("REFUSE_CANONICAL_JSON", "Floats and nonfinite JSON numbers are forbidden.")


def parse(data: bytes | str, *, require_canonical: bool = True, limit: int = MAX_JSON_BYTES) -> Any:
    """Strict bounded parse. Carried authority must already be canonical bytes."""
    raw = data.encode("utf-8") if isinstance(data, str) else data
    if type(raw) is not bytes or not raw or len(raw) > limit:
        raise Refusal("REFUSE_JSON_SIZE", "JSON must be nonempty and bounded.")
    try:
        value = json.loads(
            raw.decode("utf-8"), object_pairs_hook=_pairs, parse_float=_no_float, parse_constant=_no_float
        )
    except Refusal:
        raise
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise Refusal("REFUSE_CANONICAL_JSON", "Invalid bounded UTF-8 JSON input.") from exc
    if require_canonical and raw != canonical(value, limit=limit):
        raise Refusal("REFUSE_CANONICAL_JSON", "Carried bytes must be exactly canonical.")
    return value


def json_equal(left: object, right: object, *, limit: int = MAX_JSON_BYTES) -> bool:
    """Typed JSON equality (true is not 1); the browser engine compares the same way."""
    return canonical(left, limit=limit) == canonical(right, limit=limit)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hash_value(space: str, value: object, *, limit: int = MAX_JSON_BYTES) -> str:
    if space not in ("rapp/1:particle", "rapp/1:wave"):
        raise Refusal("REFUSE_HASH_SPACE", "Unsupported RAPP value hash domain.")
    return hashlib.sha256(space.encode("ascii") + b"\n" + canonical(value, limit=limit)).hexdigest()


def particle(payload: object, *, limit: int = MAX_JSON_BYTES) -> str:
    return hash_value("rapp/1:particle", payload, limit=limit)


def wave(frame: dict[str, Any]) -> str:
    return hash_value("rapp/1:wave", {key: item for key, item in frame.items() if key not in ("frame_hash", "sig")})


def head(frame: dict[str, Any]) -> dict[str, Any]:
    return {key: frame[key] for key in HEAD_KEYS}


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def unb64(value: object, *, limit: int = MAX_JSON_BYTES) -> bytes:
    if type(value) is not str or not value or len(value) > (limit * 4) // 3 + 4:
        raise Refusal("REFUSE_ENCODING", "Bounded canonical base64 is required.")
    try:
        data = base64.b64decode(value, validate=True)
    except (ValueError, UnicodeError) as exc:
        raise Refusal("REFUSE_ENCODING", "Invalid base64.") from exc
    if b64(data) != value or len(data) > limit:
        raise Refusal("REFUSE_ENCODING", "Noncanonical or oversized base64.")
    return data


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def unb64url(value: object) -> bytes:
    if type(value) is not str or not value or "=" in value:
        raise Refusal("REFUSE_SIGNATURE", "Canonical unpadded base64url is required.")
    try:
        decoded = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    except (ValueError, UnicodeError) as exc:
        raise Refusal("REFUSE_SIGNATURE", "Invalid base64url.") from exc
    if b64url(decoded) != value:
        raise Refusal("REFUSE_SIGNATURE", "Noncanonical base64url is forbidden.")
    return decoded


def protected_header(signer: str) -> bytes:
    return canonical({"alg": "EdDSA", "b64": False, "crit": ["b64"], "kid": signer})


def rappid_for_spki(owner: str, slug: str, spki: bytes) -> str:
    return f"rappid:@{owner}/{slug}:" + hashlib.sha256(b"rapp/1:rappid\n" + spki).hexdigest()


def spki_from_b64(value: object) -> bytes:
    if type(value) is not str or not value or len(value) > 1024:
        raise Refusal("REFUSE_IDENTITY", "A bounded public Ed25519 SPKI is required.")
    try:
        data = base64.b64decode(value, validate=True)
    except (ValueError, UnicodeError) as exc:
        raise Refusal("REFUSE_IDENTITY", "Invalid public Ed25519 SPKI.") from exc
    if base64.b64encode(data).decode("ascii") != value:
        raise Refusal("REFUSE_IDENTITY", "Only canonical base64 SPKI is supported.")
    return data


def check_rappid(rappid: object, spki: bytes | None = None) -> str:
    match = RAPPID_RE.fullmatch(rappid) if type(rappid) is str else None
    if match is None or len(match[1]) > 39 or len(match[2]) > 100:
        raise Refusal("REFUSE_IDENTITY", "A canonical keyed RAPP identity is required.")
    if spki is not None and match[3] != hashlib.sha256(b"rapp/1:rappid\n" + spki).hexdigest():
        raise Refusal("REFUSE_IDENTITY", "The RAPP identity does not match its public key.")
    return str(rappid)


def verify_signature(frame: dict[str, Any], spki_b64: str, signer: str) -> None:
    """Verify the detached unencoded EdDSA JWS over the frame minus ``sig``."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    spki = spki_from_b64(spki_b64)
    check_rappid(signer, spki)
    try:
        key = serialization.load_der_public_key(spki)
    except (ValueError, TypeError) as exc:
        raise Refusal("REFUSE_IDENTITY", "Invalid public Ed25519 SPKI.") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise Refusal("REFUSE_IDENTITY", "Only Ed25519 keys are supported.")
    signature = frame.get("sig")
    pieces = signature.split(".") if type(signature) is str and len(signature) <= 16384 else []
    if len(pieces) != 3 or pieces[1] != "" or unb64url(pieces[0]) != protected_header(signer):
        raise Refusal("REFUSE_SIGNATURE", "An exact detached unencoded EdDSA JWS is required.")
    raw = unb64url(pieces[2])
    if len(raw) != 64:
        raise Refusal("REFUSE_SIGNATURE", "Ed25519 signatures must be 64 bytes.")
    unsigned = {key_: item for key_, item in frame.items() if key_ != "sig"}
    try:
        key.verify(raw, pieces[0].encode("ascii") + b"." + canonical(unsigned))
    except InvalidSignature as exc:
        raise Refusal("REFUSE_SIGNATURE", "Ed25519 signature verification failed.") from exc


def utc_valid(value: object) -> bool:
    """RAPP/1 section 7.4: the fixed 24-byte form and a real calendar moment (no second 60)."""
    match = UTC_RE.fullmatch(value) if type(value) is str else None
    if match is None:
        return False
    year, month, day, hour, minute, second = (int(part) for part in match.groups())
    leap = year % 4 == 0 and (year % 100 != 0 or year % 400 == 0)
    days = (31, 29 if leap else 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31)
    return year >= 1 and 1 <= month <= 12 and 1 <= day <= days[month - 1] and hour <= 23 and minute <= 59 and second <= 59


def stream_family(stream: object) -> str | None:
    """rapp-hive/2 carries RAPP/1 memory streams (``<rappid>:<instance>``) and body streams (a bare RAPPID)."""
    if type(stream) is not str:
        return None
    memory = MEMORY_STREAM_RE.fullmatch(stream)
    if memory is not None:
        owner = RAPPID_RE.fullmatch(memory[1])
        return "memory" if len(owner[1]) <= 39 and len(owner[2]) <= 100 and len(memory[2]) <= 64 else None
    body = RAPPID_RE.fullmatch(stream)
    return "body" if body is not None and len(body[1]) <= 39 and len(body[2]) <= 100 else None


def frame_integrity(frame: object) -> dict[str, Any]:
    """RAPP/1 section 7.5 shape, particle, wave and wire checks. Signatures are checked separately."""
    if type(frame) is not dict or set(frame) != FRAME_KEYS:
        raise Refusal("REFUSE_FRAME_SHAPE", "An exact eleven-key RAPP/1 frame is required.")
    kind = KIND_RE.fullmatch(frame["kind"]) if type(frame["kind"]) is str else None
    if frame["spec"] != "rapp/1" or kind is None or len(kind[1]) > 64 or len(kind[2]) > 64:
        raise Refusal("REFUSE_FRAME_SHAPE", "Invalid RAPP/1 frame envelope (spec or kind grammar).")
    if stream_family(frame["stream_id"]) is None:
        raise Refusal("REFUSE_FRAME_SHAPE", "rapp-hive/2 carries RAPP/1 memory and body streams only.")
    if type(frame["seq"]) is not int or not 0 <= frame["seq"] <= MAX_SAFE_INTEGER:
        raise Refusal("REFUSE_FRAME_SHAPE", "Invalid frame sequence.")
    if not utc_valid(frame["utc"]):
        raise Refusal("REFUSE_FRAME_TIME", "RAPP/1 requires a real UTC moment with exactly three milliseconds.")
    if type(frame["payload"]) is not dict:
        raise Refusal("REFUSE_FRAME_SHAPE", "Frame payloads are JSON objects.")
    if frame["prev_wave"] is not None:
        raise Refusal("REFUSE_FRAME_SHAPE", "prev_wave is null off swarm (RAPP/1 wire chain).")
    prev = frame["prev"]
    if (frame["seq"] == 0) != (prev is None) or (
        prev is not None and (type(prev) is not str or not HASH_RE.fullmatch(prev))
    ):
        raise Refusal("REFUSE_HISTORY_ORDER", "Invalid genesis or particle predecessor.")
    if frame["payload_hash"] != particle(frame["payload"]):
        raise Refusal("REFUSE_FRAME_HASH", "RAPP/1 particle hash verification failed.")
    if frame["frame_hash"] != wave(frame):
        raise Refusal("REFUSE_FRAME_HASH", "RAPP/1 wave hash verification failed.")
    return head(frame)


def check_chain(frames: list[dict[str, Any]]) -> None:
    """Contiguous single-stream chain: seq 0..n, prev = predecessor particle, UTC monotone."""
    for index, frame in enumerate(frames):
        if frame["seq"] != index or frame["stream_id"] != frames[0]["stream_id"]:
            raise Refusal("REFUSE_HISTORY_ORDER", "A gap, replay or cross-stream frame was detected.")
        if index and (frame["prev"] != frames[index - 1]["payload_hash"] or frame["utc"] < frames[index - 1]["utc"]):
            raise Refusal("REFUSE_HISTORY_ORDER", "A broken particle chain or UTC rollback was detected.")


def check_extends(retained: dict[str, Any] | None, frames: list[dict[str, Any]]) -> None:
    """Refuse rollback and same-sequence forks against a retained high-water head."""
    if retained is None:
        return
    sequence = retained["seq"]
    if sequence >= len(frames):
        raise Refusal("REFUSE_ROLLBACK", "Offered history is below the retained high-water head.")
    if head(frames[sequence]) != retained:
        raise Refusal("REFUSE_FORK", "A same-sequence competing head differs from the retained vector.")


def jws_kid(frame: dict[str, Any]) -> str:
    """The keyed RAPPID named by a frame's detached JWS protected header."""
    signature = frame.get("sig")
    pieces = signature.split(".") if type(signature) is str and len(signature) <= 16384 else []
    if len(pieces) != 3:
        raise Refusal("REFUSE_SIGNATURE", "An exact detached unencoded EdDSA JWS is required.")
    header = parse(unb64url(pieces[0]), limit=4096) if pieces[0] else None
    if type(header) is not dict or set(header) != {"alg", "b64", "crit", "kid"}:
        raise Refusal("REFUSE_SIGNATURE", "The JWS protected header is exactly {alg, b64, crit, kid}.")
    return check_rappid(header["kid"])


def stream_signer(frame: dict[str, Any]) -> tuple[str, bool]:
    """rapp-hive/2 section 2: who signed a frame, and whether it is legacy (body-stream) evidence.

    On a memory stream the signer is the keyed RAPPID that prefixes ``stream_id`` (ownership is structural).
    On a body stream (``stream_id`` is a bare RAPPID, as the rapp-hive/1 Mother Hive is) the signer is the
    JWS ``kid``; such frames count only as content of their signer, never as rapp-hive/2 governance.
    """
    family = stream_family(frame.get("stream_id"))
    if family == "memory":
        return check_rappid(MEMORY_STREAM_RE.fullmatch(frame["stream_id"])[1]), False
    if family == "body":
        return jws_kid(frame), True
    raise Refusal("REFUSE_FRAME_SHAPE", "rapp-hive/2 carries RAPP/1 memory and body streams only.")

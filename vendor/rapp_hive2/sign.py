"""Signing and carrier layout for rapp-hive/2 frames (used by the migrator and the model Hive).

Verification never needs this module. ``test_key`` derives PUBLIC test keys from
published labels: anyone can re-derive them, so they prove nothing and must never
guard real data. Real use loads the owner's own key with ``load_key``.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from . import rapp1
from .rapp1 import Refusal

TEST_KEY_LABEL = "rapp-hive/2:public-test-key/1\n"


def test_key(label: str) -> Any:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    return Ed25519PrivateKey.from_private_bytes(hashlib.sha256((TEST_KEY_LABEL + label).encode("utf-8")).digest())


def load_key(path: Path) -> Any:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    key = serialization.load_pem_private_key(Path(path).read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise Refusal("REFUSE_IDENTITY", "Only Ed25519 keys sign rapp-hive/2 frames.")
    return key


class Signer:
    """One keyed RAPP identity. rapp-hive/2 frames go on its own memory streams only."""

    def __init__(self, key: Any, owner: str, slug: str) -> None:
        from cryptography.hazmat.primitives import serialization

        self._key = key
        spki = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        self.spki_b64 = rapp1.b64(spki)
        self.rappid = rapp1.check_rappid(rapp1.rappid_for_spki(owner, slug, spki))
        self.slug = slug

    def identity(self) -> dict[str, Any]:
        return {"schema": "rapp-hive/2-identity", "rappid": self.rappid, "spki_der_b64": self.spki_b64}

    def stream(self, instance: str) -> str:
        return f"{self.rappid}:{instance}"

    def frame(self, kind: str, instance: str, payload: dict[str, Any], utc: str, previous: dict[str, Any] | None) -> dict[str, Any]:
        return self._signed(kind, self.stream(instance), payload, utc, previous)

    def body_frame(self, kind: str, stream: str, payload: dict[str, Any], utc: str, previous: dict[str, Any] | None) -> dict[str, Any]:
        """A frame on a RAPP/1 body stream (a bare RAPPID), as rapp-hive/1 writes its Mother Hive; for models and tests."""
        if rapp1.stream_family(stream) != "body":
            raise Refusal("REFUSE_FRAME_SHAPE", "A body stream is a bare RAPPID.")
        return self._signed(kind, stream, payload, utc, previous)

    def _signed(self, kind: str, stream: str, payload: dict[str, Any], utc: str, previous: dict[str, Any] | None) -> dict[str, Any]:
        if previous is not None and previous["stream_id"] != stream:
            raise Refusal("REFUSE_HISTORY_ORDER", "A frame extends its own stream only.")
        frame: dict[str, Any] = {
            "spec": "rapp/1",
            "kind": kind,
            "stream_id": stream,
            "seq": 0 if previous is None else previous["seq"] + 1,
            "utc": utc,
            "payload": payload,
            "payload_hash": rapp1.particle(payload),
            "frame_hash": None,
            "prev": None if previous is None else previous["payload_hash"],
            "prev_wave": None,
            "sig": None,
        }
        frame["frame_hash"] = rapp1.wave(frame)
        header = rapp1.b64url(rapp1.protected_header(self.rappid))
        unsigned = {key: value for key, value in frame.items() if key != "sig"}
        frame["sig"] = header + ".." + rapp1.b64url(self._key.sign(header.encode("ascii") + b"." + rapp1.canonical(unsigned)))
        rapp1.frame_integrity(frame)
        return frame


def _hash12(rappid: str) -> str:
    return rappid.rsplit(":", 1)[-1][:12]


def identity_path(record: dict[str, Any]) -> str:
    slug = record["rappid"].split("/", 1)[1].split(":", 1)[0]
    return f"identities/{slug}.{_hash12(record['rappid'])}.json"


def frame_path(frame: dict[str, Any]) -> str:
    stream = frame["stream_id"]
    if rapp1.stream_family(stream) == "body":
        slug = stream.split("/", 1)[1].split(":", 1)[0]
        return f"streams/{slug}.{_hash12(stream)}/{frame['seq']:08d}.json"
    owner, _, instance = stream.rpartition(":")
    slug = owner.split("/", 1)[1].split(":", 1)[0]
    return f"streams/{slug}.{instance}.{_hash12(owner)}/{frame['seq']:08d}.json"


def carrier_files(anchor: str | None, identities: list[dict[str, Any]], objects: list[Any], frames: list[dict[str, Any]]) -> dict[str, bytes]:
    """The exact bytes of a carrier folder (canonical JSON; objects named by their particle)."""
    files: dict[str, bytes] = {}
    if anchor is not None:
        files["HIVE.json"] = rapp1.canonical({"schema": "rapp-hive/2-carrier", "anchor": anchor})
    for record in identities:
        files[identity_path(record)] = rapp1.canonical(record)
    for value in objects:
        files[f"objects/{rapp1.particle(value)}.json"] = rapp1.canonical(value)
    for frame in frames:
        files[frame_path(frame)] = rapp1.canonical(frame)
    return files

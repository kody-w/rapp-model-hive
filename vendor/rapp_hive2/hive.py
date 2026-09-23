"""rapp-hive/2: verify a carried Hive and derive its state deterministically.

Only signed frames, self-verifying identity records and content-addressed
objects are carried. Everything else (members, active policy and lenses, views,
exhausts, manifests' agreement) is derived here, identically on every device.
Integrity failures refuse the whole carrier; governance that does not meet the
rules is recorded as a refusal and has no effect.
"""

from __future__ import annotations

import os
import re
import stat
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import lens as lensmod, rapp1, schema as schemas, store
from .rapp1 import Refusal

ANCHOR, POLICY, IDENTITY, STATE, VERDICT = (
    "rapp-hive/2-anchor",
    "rapp-hive/2-policy",
    "rapp-hive/2-identity",
    "rapp-hive/2-state",
    "rapp-hive/2-verdict",
)
KINDS = {
    "hive2.accept": ("rapp-hive/2-accept", {"schema", "anchor"}),
    "hive2.join": ("rapp-hive/2-join", {"schema", "anchor", "policy"}),
    "hive2.grant": ("rapp-hive/2-grant", {"schema", "anchor", "member", "request"}),
    "hive2.adopt": ("rapp-hive/2-adopt", {"schema", "anchor", "object", "predecessor"}),
    "hive2.attest": ("rapp-hive/2-attest", {"schema", "anchor", "subject", "claim", "method"}),
    "hive2.manifest": ("rapp-hive/2-manifest", {"schema", "anchor", "heads", "state"}),
}
KEY_CONFIRMED = "key-confirmed"
ALL_MEMBERS = "members"
LEGACY_V1 = "rapp-hive/1"
V1_DECLARATION_KEYS = {"schema", "hive_rappid", "world_id", "created_utc", "authority_channel_id", "members", "rooms", "channels", "policy"}
V1_LABEL_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?\Z")
V1_DRIVE_RE = re.compile(r"[A-Za-z]:")
V1_ROLES = ("owner", "member", "viewer")
V1_ROOM_ACCESS = ("repository", "sealed")
V1_CHANNEL_KINDS = ("github", "sharepoint", "nas", "lan", "local", "custom")
V1_CHANNEL_ROLES = ("authority", "writable", "mirror", "cache", "backup")
V1_PRIVACY = {"godd_sharing": "explicit", "default_godd_scope": "local-only", "external_publication": "disabled", "conflict_mode": "explicit", "default_transfer": "copy"}
MAX_FILES = 20000
MAX_OBJECT_BYTES = 1024 * 1024
LABEL_RE = lensmod.ID_RE


# ---------------------------------------------------------------- carried objects


def _is_hex(value: Any) -> bool:
    return type(value) is str and lensmod.HEX_RE.fullmatch(value) is not None


def _is_rappid(value: Any) -> bool:
    try:
        rapp1.check_rappid(value)
    except Refusal:
        return False
    return True


def _hex(value: Any, what: str) -> str:
    if not _is_hex(value):
        raise Refusal("REFUSE_SCHEMA", f"{what} must be a 64-hex particle.")
    return value


def _sorted_unique_strings(value: Any) -> bool:
    return type(value) is list and bool(value) and all(type(item) is str for item in value) and value == sorted(set(value))


def _quorum(value: Any, what: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != {"quorum"} or type(value["quorum"]) is not int or value["quorum"] < 1:
        raise Refusal("REFUSE_SCHEMA", f"{what} is exactly {{quorum}} with a positive integer.")
    return value


def check_policy(policy: Any) -> dict[str, Any]:
    keys = {"schema", "version", "predecessor", "deciders", "admit", "change_policy", "adopt_lens", "migrate_pending", "data"}
    if type(policy) is not dict or set(policy) != keys or policy["schema"] != POLICY:
        raise Refusal("REFUSE_SCHEMA", "A policy has exactly the rapp-hive/2-policy keys.")
    version = policy["version"]
    if type(version) is not int or version < 1:
        raise Refusal("REFUSE_SCHEMA", "policy.version must be a positive integer.")
    if (version == 1) != (policy["predecessor"] is None):
        raise Refusal("REFUSE_SCHEMA", "Only version 1 of a policy has no predecessor.")
    if policy["predecessor"] is not None:
        _hex(policy["predecessor"], "policy.predecessor")
    admit = policy["admit"]
    if type(admit) is not dict or set(admit) != {"quorum", "attested"} or type(admit["quorum"]) is not int or admit["quorum"] < 1 or type(admit["attested"]) is not bool:
        raise Refusal("REFUSE_SCHEMA", "policy.admit is exactly {quorum, attested}.")
    _quorum(policy["change_policy"], "policy.change_policy")
    adopt = policy["adopt_lens"]
    if type(adopt) is not dict or set(adopt) != {"new", "additive", "successor"} or adopt["additive"] not in ("automatic", "quorum"):
        raise Refusal("REFUSE_SCHEMA", "policy.adopt_lens is exactly {new, additive, successor}.")
    _quorum(adopt["new"], "policy.adopt_lens.new")
    _quorum(adopt["successor"], "policy.adopt_lens.successor")
    if policy["migrate_pending"] not in ("keep-pinned", "re-decide"):
        raise Refusal("REFUSE_SCHEMA", "policy.migrate_pending is keep-pinned or re-decide.")
    if type(policy["data"]) is not dict:
        raise Refusal("REFUSE_SCHEMA", "policy.data is an object.")
    deciders = policy["deciders"]
    if deciders != ALL_MEMBERS:
        if not _sorted_unique_strings(deciders):
            raise Refusal("REFUSE_SCHEMA", 'policy.deciders is "members" or a sorted, unique, nonempty list of RAPPIDs.')
        for decider in deciders:
            rapp1.check_rappid(decider)
        quorums = (admit["quorum"], policy["change_policy"]["quorum"], adopt["new"]["quorum"], adopt["successor"]["quorum"])
        if max(quorums) > len(deciders):
            raise Refusal("REFUSE_SCHEMA", "A quorum cannot exceed the number of deciders.")
    return policy


def check_anchor(anchor: Any) -> dict[str, Any]:
    if type(anchor) is not dict or set(anchor) != {"schema", "name", "world_id", "founders", "policy", "legacy"} or anchor["schema"] != ANCHOR:
        raise Refusal("REFUSE_SCHEMA", "An anchor has exactly the rapp-hive/2-anchor keys.")
    if type(anchor["name"]) is not str or not 0 < len(anchor["name"]) <= 100:
        raise Refusal("REFUSE_SCHEMA", "anchor.name is a short text.")
    if type(anchor["world_id"]) is not str or len(anchor["world_id"]) > 64 or LABEL_RE.fullmatch(anchor["world_id"]) is None:
        raise Refusal("REFUSE_SCHEMA", "anchor.world_id is a lowercase label.")
    founders = anchor["founders"]
    if not _sorted_unique_strings(founders):
        raise Refusal("REFUSE_SCHEMA", "anchor.founders is a sorted, unique, nonempty list.")
    for founder in founders:
        rapp1.check_rappid(founder)
    _hex(anchor["policy"], "anchor.policy")
    legacy = anchor["legacy"]
    if legacy is not None:
        if type(legacy) is not dict or set(legacy) != {"from", "declaration", "join"} or type(legacy["from"]) is not str or not 0 < len(legacy["from"]) <= 100:
            raise Refusal("REFUSE_SCHEMA", "anchor.legacy is exactly {from, declaration, join}.")
        if (legacy["from"] == LEGACY_V1) != (legacy["declaration"] is not None):
            raise Refusal("REFUSE_SCHEMA", "A rapp-hive/1 legacy names its declaration; other sources name none.")
        if legacy["declaration"] is not None:
            _hex(legacy["declaration"], "anchor.legacy.declaration")
        join = legacy["join"]
        if join is not None:
            if type(join) is not dict or set(join) != {"requests"} or not _sorted_unique_strings(join["requests"]):
                raise Refusal("REFUSE_SCHEMA", "anchor.legacy.join is exactly {requests} with sorted unique frame hashes.")
            for item in join["requests"]:
                _hex(item, "anchor.legacy.join.requests[]")
    return anchor


@dataclass
class Carried:
    identities: dict[str, str] = field(default_factory=dict)
    objects: dict[str, Any] = field(default_factory=dict)
    frames: list[tuple[str, bytes]] = field(default_factory=list)
    anchor: str | None = None


def _files(root: Path) -> list[str]:
    """Every file under the carrier folder, relative and POSIX; links are refused, never followed."""
    found: list[str] = []
    pending = [""]
    while pending:
        relative = pending.pop()
        with os.scandir(root / relative if relative else root) as entries:
            for entry in entries:
                path = f"{relative}/{entry.name}" if relative else entry.name
                info = entry.stat(follow_symlinks=False)
                if store.is_link(info):
                    raise Refusal("REFUSE_UNSAFE_PATH", f"{path} is a link; carriers hold plain files only.")
                if stat.S_ISDIR(info.st_mode):
                    pending.append(path)
                elif stat.S_ISREG(info.st_mode):
                    found.append(path)
                else:
                    raise Refusal("REFUSE_UNSAFE_PATH", f"{path} is not a plain file or folder.")
                if len(found) > MAX_FILES:
                    raise Refusal("REFUSE_JSON_SIZE", "The carrier holds too many files.")
    return sorted(found)


def load(folder: Path) -> Carried:
    """Read a carrier folder: HIVE.json, identities/, objects/<particle>.json and streams/**."""
    carried = Carried()
    for path in _files(Path(folder)):
        top = path.split("/", 1)[0]
        if top not in ("HIVE.json", "identities", "objects", "streams") or not path.endswith(".json"):
            continue
        raw = store.read_inside(Path(folder), path, limit=MAX_OBJECT_BYTES)
        if path == "HIVE.json":
            pointer = rapp1.parse(raw)
            if type(pointer) is not dict or set(pointer) != {"schema", "anchor"} or pointer["schema"] != "rapp-hive/2-carrier":
                raise Refusal("REFUSE_SCHEMA", "HIVE.json is exactly {schema, anchor}.")
            carried.anchor = _hex(pointer["anchor"], "HIVE.json anchor")
        elif top == "identities":
            record = rapp1.parse(raw)
            if type(record) is not dict or set(record) != {"schema", "rappid", "spki_der_b64"} or record["schema"] != IDENTITY:
                raise Refusal("REFUSE_IDENTITY", f"{path} is not a rapp-hive/2 identity record.")
            rapp1.check_rappid(record["rappid"], rapp1.spki_from_b64(record["spki_der_b64"]))
            known = carried.identities.setdefault(record["rappid"], record["spki_der_b64"])
            if known != record["spki_der_b64"]:
                raise Refusal("REFUSE_IDENTITY", "Two different keys claim one RAPPID.")
        elif top == "objects":
            value = rapp1.parse(raw)
            name = path.rsplit("/", 1)[-1][: -len(".json")]
            if rapp1.particle(value, limit=MAX_OBJECT_BYTES) != name:
                raise Refusal("REFUSE_TAMPER", f"{path} does not hash to its name.")
            carried.objects[name] = value
        else:
            carried.frames.append((path, raw))
    return carried


# ---------------------------------------------------------------- verified frames


@dataclass(frozen=True)
class Record:
    frame: dict[str, Any] = field(repr=False)
    raw: bytes = field(repr=False)
    path: str
    owner: str
    wave: str
    particle: str
    stream: str
    seq: int
    utc: str
    kind: str
    legacy: bool = False  # on a body stream: content of its signer, never governance


def verify_frames(carried: Carried) -> list[Record]:
    """RAPP/1 integrity, the signer's own signature (the stream owner's on memory streams), whole streams."""
    records: list[Record] = []
    streams: dict[str, list[dict[str, Any]]] = {}
    for path, raw in carried.frames:
        frame = rapp1.parse(raw)
        rapp1.frame_integrity(frame)
        signer, legacy = rapp1.stream_signer(frame)
        spki = carried.identities.get(signer)
        if spki is None:
            raise Refusal("REFUSE_IDENTITY", f"{path}: no identity record for the signer.")
        rapp1.verify_signature(frame, spki, signer)
        records.append(Record(frame, raw, path, signer, frame["frame_hash"], frame["payload_hash"], frame["stream_id"], frame["seq"], frame["utc"], frame["kind"], legacy))
        streams.setdefault(frame["stream_id"], []).append(frame)
    for frames in streams.values():
        rapp1.check_chain(sorted(frames, key=lambda item: item["seq"]))
    if len({record.wave for record in records}) != len(records):
        raise Refusal("REFUSE_HISTORY_ORDER", "The same frame is carried twice.")
    return sorted(records, key=lambda record: (record.utc, record.wave))


# ---------------------------------------------------------------- evaluation


def _v1_text(value: Any, maximum: int = 256) -> bool:
    return type(value) is str and 0 < len(value) <= maximum and unicodedata.normalize("NFC", value) == value


def _v1_label(value: Any) -> bool:
    return _v1_text(value, 64) and V1_LABEL_RE.fullmatch(value) is not None


def _v1_path(value: Any) -> bool:
    """rapp-hive/1 relative_path: a canonical, relative, portable POSIX path."""
    if not _v1_text(value, 1024) or value.startswith("/") or "\\" in value or "\x7f" in value or V1_DRIVE_RE.match(value):
        return False
    return all(
        part not in ("", ".", "..") and not part.endswith((" ", ".")) and ":" not in part and all(ord(char) >= 32 for char in part) and part.split(".", 1)[0].upper() not in store.WINDOWS_RESERVED
        for part in value.split("/")
    )


def _v1_strings(value: Any) -> Any:
    if type(value) is str:
        yield value
    elif type(value) is dict:
        for key, item in value.items():
            yield key
            yield from _v1_strings(item)
    elif type(value) is list:
        for item in value:
            yield from _v1_strings(item)


def _v1_sorted_unique(values: list[str]) -> bool:
    return values == sorted(set(values))


def v1_declaration_problem(payload: dict[str, Any]) -> str | None:
    """Why ``payload`` is not a declaration rapp-hive/1 accepts (its reference ``validate_declaration``), or None."""
    if any(unicodedata.normalize("NFC", text) != text for text in _v1_strings(payload)):
        return "Every string of a rapp-hive/1 declaration is NFC."
    if set(payload) != V1_DECLARATION_KEYS or payload["schema"] != "rapp-hive/1-declaration":
        return "A rapp-hive/1 declaration has exactly its nine keys and its schema."
    if not _is_rappid(payload["hive_rappid"]) or not _v1_label(payload["world_id"]) or not rapp1.utc_valid(payload["created_utc"]) or not _v1_label(payload["authority_channel_id"]):
        return "hive_rappid, world_id, created_utc and authority_channel_id follow rapp-hive/1."
    members = payload["members"]
    if type(members) is not list or not members:
        return "declaration.members is a nonempty list."
    for member in members:
        if type(member) is not dict or set(member) != {"rappid", "role", "area"} or not _is_rappid(member["rappid"]) or type(member["role"]) is not str or member["role"] not in V1_ROLES or not _v1_path(member["area"]):
            return "Every declared member is exactly {rappid, role, area} with an owner, member or viewer role."
    member_ids = [member["rappid"] for member in members]
    if not _v1_sorted_unique(member_ids) or sum(member["role"] == "owner" for member in members) != 1:
        return "Members are unique, sorted by RAPPID, and exactly one is the owner."
    rooms = payload["rooms"]
    if type(rooms) is not list or not rooms:
        return "declaration.rooms is a nonempty list."
    for room in rooms:
        if type(room) is not dict or set(room) != {"id", "area", "members", "access"} or not _v1_label(room["id"]) or not _v1_path(room["area"]) or type(room["access"]) is not str or room["access"] not in V1_ROOM_ACCESS:
            return "Every room is exactly {id, area, members, access} with repository or sealed access."
        audience = room["members"]
        if type(audience) is not list or not audience or not all(_is_rappid(item) for item in audience) or not _v1_sorted_unique(audience) or not set(audience) <= set(member_ids):
            return "A room's members are a nonempty, sorted, unique list of declared members."
    if not _v1_sorted_unique([room["id"] for room in rooms]):
        return "Rooms are unique and sorted by id."
    channels = payload["channels"]
    if type(channels) is not list or not channels:
        return "declaration.channels is a nonempty list."
    authorities = []
    for channel in channels:
        if (
            type(channel) is not dict
            or set(channel) != {"id", "kind", "role", "locator", "writeback"}
            or not _v1_label(channel["id"])
            or type(channel["kind"]) is not str
            or channel["kind"] not in V1_CHANNEL_KINDS
            or type(channel["role"]) is not str
            or channel["role"] not in V1_CHANNEL_ROLES
            or not _v1_text(channel["locator"], 2048)
            or type(channel["writeback"]) is not bool
        ):
            return "Every channel is exactly {id, kind, role, locator, writeback} with a supported kind and role."
        if channel["role"] == "authority":
            if not channel["writeback"]:
                return "The authority channel supports writeback."
            authorities.append(channel["id"])
    if not _v1_sorted_unique([channel["id"] for channel in channels]) or authorities != [payload["authority_channel_id"]]:
        return "Channels are unique and sorted by id, with exactly the one named authority channel."
    policy = payload["policy"]
    if type(policy) is not dict or set(policy) != set(V1_PRIVACY) or any(policy[key] != value or type(policy[key]) is not str for key, value in V1_PRIVACY.items()):
        return "The rapp-hive/1 privacy policy has its fixed values."
    return None


def check_legacy_declaration(record: Record) -> dict[str, Any]:
    """A rapp-hive/1 declaration exactly as rapp-hive/1 accepts it: its payload passes rapp-hive/1's declaration
    rules, and it is the genesis of its Mother Hive body stream (``stream_id`` = ``hive_rappid``), signed by
    the one owner it declares."""
    payload = record.frame["payload"]
    if record.kind != "hive.declaration":
        raise Refusal("REFUSE_LEGACY", "The legacy declaration is not a hive.declaration frame.")
    problem = v1_declaration_problem(payload)
    if problem is not None:
        raise Refusal("REFUSE_LEGACY", f"Not a declaration rapp-hive/1 accepts: {problem}")
    roles: dict[str, list[str]] = {role: [item["rappid"] for item in payload["members"] if item["role"] == role] for role in V1_ROLES}
    if not record.legacy or record.stream != payload.get("hive_rappid") or record.seq != 0:
        raise Refusal("REFUSE_LEGACY", "A rapp-hive/1 declaration is the genesis of its Mother Hive stream (stream_id = hive_rappid).")
    if record.owner != roles["owner"][0]:
        raise Refusal("REFUSE_LEGACY", "A rapp-hive/1 declaration is signed by its declared owner.")
    return {
        "owner": roles["owner"][0],
        "members": sorted(set(roles["member"])),
        "viewers": sorted(set(roles["viewer"])),
        "world_id": payload["world_id"],
        "privacy": payload["policy"],
    }


def governance_problem(kind: str, payload: dict[str, Any]) -> str | None:
    """Why a governance payload is malformed (keys, schema and value types), or None."""
    name, keys = KINDS[kind]
    if set(payload) != keys or payload.get("schema") != name:
        return f"{kind} payload is not {name}."
    if not _is_hex(payload["anchor"]):
        return "anchor is a 64-hex particle."
    if kind == "hive2.join" and not _is_hex(payload["policy"]):
        return "A join pins a policy particle."
    if kind == "hive2.grant" and (not _is_rappid(payload["member"]) or not _is_hex(payload["request"])):
        return "A grant names a member RAPPID and a request frame hash."
    if kind == "hive2.adopt" and (not _is_hex(payload["object"]) or not (payload["predecessor"] is None or _is_hex(payload["predecessor"]))):
        return "An adoption names an object particle and a predecessor particle or null."
    if kind == "hive2.attest":
        if not _is_rappid(payload["subject"]):
            return "An attestation names a keyed RAPPID."
        if type(payload["claim"]) is not str or type(payload["method"]) is not str or not 0 < len(payload["claim"]) <= 100 or not 0 < len(payload["method"]) <= 200:
            return "An attestation has a short claim and method."
    return None


class Evaluation:
    """Processes verified frames in RAPP/1 cross-stream order (ascending utc, then frame_hash).

    Membership never depends on content or lenses, so it is decided first (a governance-only pass).
    Content of identities that are not members at the end is quarantined before any lens work: it never
    teaches an additive successor and is never weighed by the lens laws.
    """

    def __init__(self, carried: Carried, records: list[Record], anchor: str, *, members_only: bool = False) -> None:
        self.carried, self.anchor_particle = carried, anchor
        self.members_only = members_only
        self.final_members: set[str] = set() if members_only else set(Evaluation(carried, records, anchor, members_only=True).members)
        if anchor not in carried.objects:
            raise Refusal("REFUSE_ANCHOR", "The anchor object is not carried.")
        self.anchor = check_anchor(carried.objects[anchor])
        first = self._policy(self.anchor["policy"])
        if first["version"] != 1:
            raise Refusal("REFUSE_ANCHOR", "The anchor pins a version 1 policy.")
        self.policy_chain = [self.anchor["policy"]]
        self.members: dict[str, dict[str, Any]] = {}
        self.pending: dict[str, dict[str, Any]] = {}
        self.attested: dict[str, set[str]] = {}
        self.attestations: list[dict[str, Any]] = []
        self.active: dict[str, str] = {}
        self.lens_objects: dict[str, dict[str, Any]] = {}
        self.derived: list[str] = []
        self.history: list[str] = []
        self.tallies: dict[tuple[str, str], set[str]] = {}
        self.refusals: list[dict[str, Any]] = []
        self.events: list[dict[str, Any]] = []
        self.content: list[Record] = []
        self.quarantine: list[Record] = []
        self.manifests: list[Record] = []
        self.other_hives: list[str] = []
        self.schemas: dict[str, dict[str, Any]] = {
            key: schemas.check_schema(value) for key, value in carried.objects.items() if type(value) is dict and value.get("schema") == schemas.VERSION
        }
        self.frame_schema: dict[str, str] = {}
        self.records = records
        legacy = self.anchor["legacy"]
        self.legacy_joins = set(legacy["join"]["requests"]) if legacy and legacy["join"] else set()
        self.legacy_declaration = legacy["declaration"] if legacy else None
        self._check_legacy(records)
        for record in records:
            self._process(record)
        if not members_only:
            self._finish()

    # -- helpers
    def _policy(self, particle: str) -> dict[str, Any]:
        if particle not in self.carried.objects:
            raise Refusal("REFUSE_POLICY", "A referenced policy is not carried.")
        return check_policy(self.carried.objects[particle])

    @property
    def policy(self) -> dict[str, Any]:
        return self._policy(self.policy_chain[-1])

    def _refuse(self, record: Record, code: str, reason: str) -> None:
        self.refusals.append({"wave": record.wave, "code": code, "reason": reason})

    def _event(self, record: Record, text: str) -> None:
        self.events.append({"utc": record.utc, "wave": record.wave, "event": text})

    def _check_legacy(self, records: list[Record]) -> None:
        by_wave = {record.wave: record for record in records}
        if self.legacy_declaration is not None:
            declaration = by_wave.get(self.legacy_declaration)
            if declaration is None:
                raise Refusal("REFUSE_LEGACY", "The legacy declaration named by the anchor is not carried.")
            declared = check_legacy_declaration(declaration)
            if declared["world_id"] != self.anchor["world_id"] or not set(self.anchor["founders"]) <= {declared["owner"], *declared["members"]}:
                raise Refusal("REFUSE_LEGACY", "Founders and world must come from the legacy declaration.")
        for wave in self.legacy_joins:
            request = by_wave.get(wave)
            if request is None:
                raise Refusal("REFUSE_LEGACY", "A grandfathered legacy request is not carried.")
            if request.kind in KINDS or wave == self.legacy_declaration:
                raise Refusal("REFUSE_LEGACY", "A grandfathered request is a signed content frame of its requester.")

    def _decides(self, policy: dict[str, Any], who: str) -> bool:
        """A vote counts from a current member whom the governing policy lets decide."""
        return who in self.members and (policy["deciders"] == ALL_MEMBERS or who in policy["deciders"])

    def _try_admit(self, key: str) -> None:
        request = self.pending.get(key)
        if request is None:
            return
        if request["requester"] in self.members:
            del self.pending[key]
            self.events.append({"utc": None, "wave": key, "event": "request closed: already a member"})
            return
        pinned = self._policy(request["pinned"])
        rule = pinned["admit"]
        grants = {granter for granter in request["grants"] if self._decides(pinned, granter)}
        vouched = {voucher for voucher in self.attested.get(request["requester"], set()) if voucher in self.members and voucher != request["requester"]}
        if len(grants) >= rule["quorum"] and (not rule["attested"] or vouched):
            self.members[request["requester"]] = {
                "how": "admitted",
                "request": key,
                "under": request["pinned"],
                "legacy": request["legacy"],
                "grants": sorted(grants),
            }
            del self.pending[key]
            self.events.append({"utc": None, "wave": key, "event": "admitted"})
            for other in sorted(self.pending):
                if self.pending.get(other, {}).get("requester") == request["requester"]:
                    self._try_admit(other)

    def _schema(self, record: Record) -> str:
        if record.wave not in self.frame_schema:
            value = schemas.schema_of(record.frame)
            particle = schemas.particle(value)
            self.schemas.setdefault(particle, value)
            self.frame_schema[record.wave] = particle
        return self.frame_schema[record.wave]

    def _view(self, lens: dict[str, Any]) -> dict[str, Any]:
        view = self.carried.objects.get(lens["view"])
        if view is None:
            raise Refusal("REFUSE_LENS", "A lens names a view that is not carried.")
        return lensmod.check_view(view)

    def _mappers(self, schema_particle: str) -> list[tuple[str, int]]:
        found = []
        for lens_id in sorted(self.active):
            index = lensmod.mapping_for(self.lens_objects[self.active[lens_id]], schema_particle)
            if index is not None:
                found.append((lens_id, index))
        return found

    # -- processing
    def _process(self, record: Record) -> None:
        payload = record.frame["payload"]
        if record.kind in KINDS:
            if record.legacy:
                return self._refuse(record, "REFUSE_LEGACY_STREAM", "Governance is signed on the signer's own memory stream, never on a body stream.")
            if record.kind == "hive2.manifest":
                if payload.get("anchor") == self.anchor_particle:
                    self.manifests.append(record)
                return
            problem = governance_problem(record.kind, payload)
            if problem is not None:
                return self._refuse(record, "REFUSE_GOVERNANCE_SHAPE", problem)
            if payload["anchor"] != self.anchor_particle:
                self.other_hives.append(record.wave)
                return
            getattr(self, "_" + record.kind.split(".", 1)[1])(record, payload)
            return
        if record.wave == self.legacy_declaration:
            return
        if record.wave in self.legacy_joins:
            self.pending[record.wave] = {"requester": record.owner, "pinned": self.anchor["policy"], "grants": set(), "legacy": True}
            self._event(record, "legacy request carried over (pinned to the first policy)")
            self._try_admit(record.wave)
            return
        if self.members_only:
            return
        if record.owner not in self.final_members:
            self.quarantine.append(record)
            return
        self.content.append(record)
        self._route(record)

    def _accept(self, record: Record, payload: dict[str, Any]) -> None:
        if record.owner not in self.anchor["founders"]:
            return self._refuse(record, "REFUSE_NOT_FOUNDER", "Only a founder can accept the anchor.")
        if record.owner not in self.members:
            self.members[record.owner] = {"how": "founder"}
            self._event(record, "founder accepted the anchor")
            for key in sorted(self.pending):
                if self.pending.get(key, {}).get("requester") == record.owner:
                    self._try_admit(key)

    def _join(self, record: Record, payload: dict[str, Any]) -> None:
        if record.owner in self.members:
            return self._refuse(record, "REFUSE_ALREADY_MEMBER", "Members do not join again.")
        if payload["policy"] != self.policy_chain[-1]:
            return self._refuse(record, "REFUSE_STALE", "A request pins the policy active when it is made.")
        if any(item["requester"] == record.owner for item in self.pending.values()):
            return self._refuse(record, "REFUSE_DUPLICATE", "This identity already has a pending request.")
        self.pending[record.wave] = {"requester": record.owner, "pinned": payload["policy"], "grants": set(), "legacy": False}
        self._event(record, "requested to join")
        self._try_admit(record.wave)

    def _grant(self, record: Record, payload: dict[str, Any]) -> None:
        if record.owner not in self.members:
            return self._refuse(record, "REFUSE_NOT_MEMBER", "Only members grant.")
        request = self.pending.get(payload["request"])
        if request is None or request["requester"] != payload["member"]:
            return self._refuse(record, "REFUSE_UNKNOWN_REQUEST", "The grant names no pending request of that identity.")
        if not self._decides(self._policy(request["pinned"]), record.owner):
            return self._refuse(record, "REFUSE_NOT_DECIDER", "The policy this request is decided under does not let this member decide.")
        request["grants"].add(record.owner)
        self._event(record, "granted a pending request")
        self._try_admit(payload["request"])

    def _attest(self, record: Record, payload: dict[str, Any]) -> None:
        if record.owner not in self.members:
            return self._refuse(record, "REFUSE_NOT_MEMBER", "Only members attest.")
        self.attestations.append({"by": record.owner, "subject": payload["subject"], "claim": payload["claim"], "method": payload["method"], "wave": record.wave})
        if payload["claim"] == KEY_CONFIRMED and payload["subject"] != record.owner:
            self.attested.setdefault(payload["subject"], set()).add(record.owner)
        for key in sorted(self.pending):
            if self.pending.get(key, {}).get("requester") == payload["subject"]:
                self._try_admit(key)

    def _adopt(self, record: Record, payload: dict[str, Any]) -> None:
        if record.owner not in self.members:
            return self._refuse(record, "REFUSE_NOT_MEMBER", "Only members adopt.")
        target = payload["object"]
        value = self.carried.objects.get(target) or self.lens_objects.get(target)
        if type(value) is not dict:
            return self._refuse(record, "REFUSE_UNKNOWN_OBJECT", "The adopted object is not carried.")
        try:
            if value.get("schema") == POLICY:
                return self._adopt_policy(record, payload, target, check_policy(value))
            if value.get("schema") == lensmod.LENS:
                if self.members_only:
                    return None
                return self._adopt_lens(record, payload, target, lensmod.check_lens(value))
        except Refusal as error:
            return self._refuse(record, error.code, error.message)
        self._refuse(record, "REFUSE_UNKNOWN_OBJECT", "Only policies and lenses are adopted.")

    def _adopt_policy(self, record: Record, payload: dict[str, Any], target: str, value: dict[str, Any]) -> None:
        current, active = self.policy_chain[-1], self.policy
        if payload["predecessor"] != current or value["predecessor"] != current or value["version"] != active["version"] + 1:
            return self._refuse(record, "REFUSE_STALE", "A policy successor pins the active policy (compare-and-swap).")
        if not self._decides(active, record.owner):
            return self._refuse(record, "REFUSE_NOT_DECIDER", "The active policy does not let this member decide.")
        tally = self.tallies.setdefault(("policy", target), set())
        tally.add(record.owner)
        self._event(record, f"adopted policy v{value['version']}")
        if len({voter for voter in tally if self._decides(active, voter)}) >= active["change_policy"]["quorum"]:
            self.policy_chain.append(target)
            self._event(record, f"policy v{value['version']} is active")
            if value["migrate_pending"] == "re-decide":
                for request in self.pending.values():
                    request["pinned"] = target
            for key in sorted(self.pending):
                self._try_admit(key)

    def _adopt_lens(self, record: Record, payload: dict[str, Any], target: str, value: dict[str, Any]) -> None:
        self._view(value)
        current = self.active.get(value["id"])
        if payload["predecessor"] is None:
            if current is not None or value["predecessor"] is not None:
                return self._refuse(record, "REFUSE_STALE", "This lens id is active already; adopt a successor.")
            quorum = self.policy["adopt_lens"]["new"]["quorum"]
        else:
            if current is None or payload["predecessor"] != current or value["predecessor"] is None or not rapp1.json_equal(value["predecessor"], lensmod.reference(self.lens_objects[current])):
                return self._refuse(record, "REFUSE_STALE", "A lens successor pins the active version exactly (compare-and-swap).")
            quorum = self.policy["adopt_lens"]["successor"]["quorum"]
        active = self.policy
        if not self._decides(active, record.owner):
            return self._refuse(record, "REFUSE_NOT_DECIDER", "The active policy does not let this member decide.")
        self.lens_objects.setdefault(target, value)
        tally = self.tallies.setdefault(("lens", target), set())
        tally.add(record.owner)
        self._event(record, f"adopted lens {value['id']} v{value['version']}")
        if len({voter for voter in tally if self._decides(active, voter)}) >= quorum:
            if current is not None:
                broken = self._laws(value, self.lens_objects[current])
                if broken:
                    return self._refuse(record, "REFUSE_LENS_LAW", broken)
            self.active[value["id"]] = target
            self.history.append(target)
            self._event(record, f"lens {value['id']} v{value['version']} is active")

    def _laws(self, candidate: dict[str, Any], predecessor: dict[str, Any]) -> str | None:
        """Laws beat signatures: same view, nothing dropped, every old message keeps its meaning."""
        if candidate["view"] != predecessor["view"]:
            return "A successor keeps its predecessor's view (a new view is a new lens id)."
        accepted = {particle for mapping in predecessor["mappings"] for particle in mapping["accepts"]}
        if not accepted <= {particle for mapping in candidate["mappings"] for particle in mapping["accepts"]}:
            return "A successor accepts every schema its predecessor accepted."
        view = self._view(predecessor)
        for record in self.content:
            particle = self._schema(record)
            old_index = lensmod.mapping_for(predecessor, particle)
            if old_index is None:
                continue
            try:
                old = lensmod.forward(predecessor, old_index, record.frame, view)[1]
            except lensmod.LensExhaust:
                continue
            new_index = lensmod.mapping_for(candidate, particle)
            try:
                new = lensmod.forward(candidate, new_index, record.frame, view)[1] if new_index is not None else None
            except lensmod.LensExhaust:
                new = None
            if new != old:
                return f"The successor changes what an existing message means ({record.wave[:12]})."
        return None

    def _route(self, record: Record) -> None:
        """A new schema that only adds fields to one already-mapped schema teaches an automatic successor."""
        particle = self._schema(record)
        if self._mappers(particle):
            return
        candidates: dict[str, list[int]] = {}
        new_schema = self.schemas[particle]
        for lens_id in sorted(self.active):
            lens = self.lens_objects[self.active[lens_id]]
            for index, mapping in enumerate(lens["mappings"]):
                if any(old in self.schemas and schemas.is_additive(new_schema, self.schemas[old]) for old in mapping["accepts"]):
                    try:
                        lensmod.forward(lens, index, record.frame, self._view(lens))
                    except lensmod.LensExhaust:
                        continue
                    candidates.setdefault(lens_id, []).append(index)
        if len(candidates) != 1 or len(next(iter(candidates.values()))) != 1:
            return
        lens_id, (index,) = next(iter(candidates.items()))
        successor = lensmod.additive_successor(self.lens_objects[self.active[lens_id]], index, particle)
        target = rapp1.particle(successor)
        self.lens_objects.setdefault(target, successor)
        self.derived.append(target)
        if self.policy["adopt_lens"]["additive"] == "automatic":
            self.active[lens_id] = target
            self.history.append(target)
            self._event(record, f"new fields only: lens {lens_id} v{successor['version']} learned automatically")

    # -- results
    def _finish(self) -> None:
        self.views: list[dict[str, Any]] = []
        waiting: dict[str, dict[str, Any]] = {}
        self.quarantined = [record.wave for record in self.quarantine]
        for record in self.content:
            particle = self._schema(record)
            mappers = self._mappers(particle)
            if len(mappers) == 1:
                lens_id, index = mappers[0]
                lens = self.lens_objects[self.active[lens_id]]
                try:
                    value, view_particle = lensmod.forward(lens, index, record.frame, self._view(lens))
                except lensmod.LensExhaust as error:
                    code, detail = error.code, error.detail
                else:
                    self.views.append({"source": record.wave, "owner": record.owner, "schema": particle, "lens": lensmod.reference(lens), "view": view_particle, "value": value})
                    continue
            else:
                code, detail = ("ambiguous", {"lenses": [item[0] for item in mappers]}) if mappers else ("no-lens", {})
            entry = waiting.setdefault(particle, {"schema": particle, "code": code, "detail": detail, "waiting": []})
            entry["waiting"].append(record.wave)
        self.exhausts = [waiting[key] for key in sorted(waiting)]
        self.state = {
            "schema": STATE,
            "anchor": self.anchor_particle,
            "policy": self.policy_chain[-1],
            "members": sorted(self.members),
            "lenses": {key: self.active[key] for key in sorted(self.active)},
            "pending": sorted(self.pending),
        }
        self.state_particle = rapp1.particle(self.state)


def _at_heads(records: list[Record], heads: dict[str, Any]) -> list[Record]:
    by_stream_seq = {(record.stream, record.seq): record for record in records}
    for stream_id, head in heads.items():
        if type(head) is not dict or set(head) != {"seq", "frame_hash"} or type(head["seq"]) is not int or type(head["frame_hash"]) is not str:
            raise Refusal("REFUSE_MANIFEST", "A manifest head is exactly {seq, frame_hash}.")
        found = by_stream_seq.get((stream_id, head["seq"]))
        if found is None or found.wave != head["frame_hash"]:
            raise Refusal("REFUSE_MANIFEST", "A manifest head names a frame this carrier does not hold.")
        if found.kind == "hive2.manifest":
            raise Refusal("REFUSE_MANIFEST", "Manifest heads exclude manifests.")
    return [record for record in records if record.stream in heads and record.seq <= heads[record.stream]["seq"] and record.kind != "hive2.manifest"]


def manifests(carried: Carried, records: list[Record], evaluation: Evaluation) -> list[dict[str, Any]]:
    """Each member's latest manifest: consistent (its state follows from its heads) or divergent; agreement groups."""
    carrier_heads: dict[str, dict[str, Any]] = {}
    for record in records:
        if record.kind != "hive2.manifest" and (record.stream not in carrier_heads or record.seq > carrier_heads[record.stream]["seq"]):
            carrier_heads[record.stream] = {"seq": record.seq, "frame_hash": record.wave}
    latest: dict[str, Record] = {}
    for record in evaluation.manifests:  # section 1 order, so the last one seen is the member's newest
        if record.owner in evaluation.members:
            latest[record.owner] = record
    results = []
    for owner in sorted(latest):
        record = latest[owner]
        payload = record.frame["payload"]
        if set(payload) != KINDS["hive2.manifest"][1] or payload["schema"] != KINDS["hive2.manifest"][0] or type(payload["heads"]) is not dict or not _is_hex(payload["state"]):
            results.append({"wave": record.wave, "by": owner, "verdict": "malformed"})
            continue
        try:
            subset = _at_heads(records, payload["heads"])
            recomputed = Evaluation(carried, subset, evaluation.anchor_particle).state_particle
        except Refusal as error:
            results.append({"wave": record.wave, "by": owner, "verdict": "unverifiable", "code": error.code})
            continue
        heads = payload["heads"]
        position = "agrees" if heads == carrier_heads else "behind"
        results.append({
            "wave": record.wave,
            "by": owner,
            "verdict": "consistent" if recomputed == payload["state"] else "divergent",
            "position": position,
            "state": payload["state"],
            "same_state": payload["state"] == evaluation.state_particle,
            "missing_frames": sum(carrier_heads[stream]["seq"] - heads.get(stream, {"seq": -1})["seq"] for stream in carrier_heads),
        })
    return results


def verdict(evaluation: Evaluation, manifest_results: list[dict[str, Any]]) -> dict[str, Any]:
    """The conformance contract: every engine must derive exactly these bytes."""
    return {
        "schema": VERDICT,
        "state": evaluation.state,
        "state_particle": evaluation.state_particle,
        "views": [{"source": item["source"], "schema": item["schema"], "lens": item["lens"]["particle"], "view": item["view"]} for item in evaluation.views],
        "exhausts": [{"schema": item["schema"], "code": item["code"], "waiting": item["waiting"]} for item in evaluation.exhausts],
        "refusals": [{"wave": item["wave"], "code": item["code"]} for item in evaluation.refusals],
        "quarantined": evaluation.quarantined,
        "derived_lenses": evaluation.derived,
        "manifests": [{"wave": item["wave"], "verdict": item["verdict"], "position": item.get("position")} for item in manifest_results],
    }


def evaluate_folder(folder: Path, anchor: str | None = None) -> tuple[Carried, list[Record], Evaluation, dict[str, Any]]:
    carried = load(folder)
    records = verify_frames(carried)
    chosen = anchor or carried.anchor
    if chosen is None:
        raise Refusal("REFUSE_ANCHOR", "Name the anchor (HIVE.json or --anchor).")
    evaluation = Evaluation(carried, records, chosen)
    return carried, records, evaluation, verdict(evaluation, manifests(carried, records, evaluation))

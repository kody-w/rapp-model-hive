"""Conformance vectors for rapp-hive/2: every engine must reach exactly these verdicts.

Generated from the reference implementation: canonical-JSON and limit cases,
schema particles, the model Hive and its variants (full verdicts), tampered
carriers (exact refusal codes) and crossings. An engine conforms when it
reproduces every expectation byte for byte.
"""

from __future__ import annotations

import base64
import json
import tempfile
from pathlib import Path
from typing import Any

from . import crossing, hive, model, rapp1, schema as schemas, store
from .rapp1 import Refusal

SCHEMA = "rapp-hive/2-conformance/1"


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _run(files: dict[str, bytes]) -> tuple[dict[str, Any] | None, str | None, Any]:
    with tempfile.TemporaryDirectory() as scratch:
        folder = Path(scratch) / "hive"
        store.write_new_tree(folder, files)
        try:
            _carried, _records, evaluation, verdict = hive.evaluate_folder(folder)
        except Refusal as error:
            return None, error.code, None
        return verdict, None, evaluation


def _nested(levels: int) -> list:
    value: list = []
    for _ in range(levels - 1):
        value = [value]
    return value


def make(recipe: dict[str, int]) -> Any:
    """Limit cases are described, not stored: a string of n "x", an array of n zeros, or n nested arrays."""
    (kind, size), = recipe.items()
    return {"string": lambda: "x" * size, "array": lambda: [0] * size, "nested": lambda: _nested(size)}[kind]()


def canonical_cases() -> dict[str, Any]:
    samples = [
        {"b": 1, "a": [True, False, None], "é": "ü", "\u2028": "line sep", "emoji": "🐝", "ctl": "\u0001\u001f\n\t"},
        {"z": {"y": {"x": [1, -2, 9007199254740991]}}, "": "empty key", "A": "upper sorts first"},
        {"😀": "astral key sorts by UTF-16 units", "\uffff": "bmp max", "a\u0000b": "nul in key"},
        "plain string with \"quotes\" and \\backslash",
    ]
    limits = {
        "bytes-at-limit": {"string": rapp1.MAX_JSON_BYTES - 2},
        "bytes-over-limit": {"string": rapp1.MAX_JSON_BYTES - 1},
        "array-at-member-cap": {"array": rapp1.MAX_MEMBERS},
        "array-over-member-cap": {"array": rapp1.MAX_MEMBERS + 1},
        "depth-at-cap": {"nested": rapp1.MAX_DEPTH + 1},
        "depth-over-cap": {"nested": rapp1.MAX_DEPTH + 2},
    }
    out = []
    for value in samples:
        out.append({"json": json.dumps(value), "canonical_b64": _b64(rapp1.canonical(value)), "particle": rapp1.particle(value)})
    for name, recipe in limits.items():
        try:
            expect: dict[str, Any] = {"particle": rapp1.particle(make(recipe))}
        except Refusal as error:
            expect = {"refused": error.code}
        out.append({"name": name, "make": recipe, "expect": expect})
    refused = [
        {"why": "float", "b64": _b64(b'{"a":1.5}')},
        {"why": "exponent", "b64": _b64(b'{"a":1e3}')},
        {"why": "duplicate key", "b64": _b64(b'{"a":1,"a":1}')},
        {"why": "spacing", "b64": _b64(b'{"a": 1}')},
        {"why": "key order", "b64": _b64(b'{"b":1,"a":2}')},
        {"why": "bom", "b64": _b64(b'\xef\xbb\xbf{"a":1}')},
        {"why": "unsafe integer", "b64": _b64(b'{"a":9007199254740993}')},
        {"why": "invalid utf-8", "b64": _b64(b'{"a":"\xff"}')},
    ]
    return {"values": out, "refused": refused}


def _resigned(frame: dict[str, Any], signer: Any, **changes: Any) -> dict[str, Any]:
    """The frame with ``changes``, hashes recomputed and a valid signature, so only the change is wrong."""
    changed = {**frame, **changes}
    changed["payload_hash"] = rapp1.particle(changed["payload"])
    changed["frame_hash"] = rapp1.wave(changed)
    header = rapp1.b64url(rapp1.protected_header(signer.rappid))
    unsigned = {key: item for key, item in changed.items() if key != "sig"}
    changed["sig"] = header + ".." + rapp1.b64url(signer._key.sign(header.encode("ascii") + b"." + rapp1.canonical(unsigned)))
    return changed


def _tampered(files: dict[str, bytes], built: dict[str, Any]) -> dict[str, dict[str, bytes]]:
    people = {info["slug"]: rappid for rappid, info in built["people"].items()}
    cases: dict[str, dict[str, bytes]] = {}

    object_path = sorted(path for path in files if path.startswith("objects/"))[0]
    changed = dict(files)
    value = rapp1.parse(files[object_path])
    changed[object_path] = rapp1.canonical({**value, "schema": value["schema"] + "-edited"}) if type(value) is dict else files[object_path]
    cases["object-edited"] = changed

    avery = people["avery-laptop"]
    hive_frames = sorted((path for path in files if path.startswith("streams/") and ".hive." in path and rapp1.parse(files[path])["stream_id"].startswith(avery + ":")))
    last = rapp1.parse(files[hive_frames[-1]])
    previous = rapp1.parse(files[hive_frames[-2]])
    hijacker = model.signer("blake-phone")
    forged = dict(last)
    forged["payload"] = {**last["payload"], "method": "forged"}
    forged["payload_hash"] = rapp1.particle(forged["payload"])
    forged["frame_hash"] = rapp1.wave(forged)
    header = rapp1.b64url(rapp1.protected_header(hijacker.rappid))
    unsigned = {key: item for key, item in forged.items() if key != "sig"}
    forged["sig"] = header + ".." + rapp1.b64url(hijacker._key.sign(header.encode("ascii") + b"." + rapp1.canonical(unsigned)))
    changed = dict(files)
    changed[hive_frames[-1]] = rapp1.canonical(forged)
    cases["stream-hijack"] = changed

    fork = model.signer("avery-laptop").frame(last["kind"], "hive", {**last["payload"], "method": "a second story"} if "method" in last["payload"] else {**last["payload"]}, last["utc"], previous)
    changed = dict(files)
    changed[hive_frames[-1].replace(".json", "-fork.json")] = rapp1.canonical(fork)
    if rapp1.canonical(fork) != files[hive_frames[-1]]:
        cases["fork"] = changed

    cases["missing-identity"] = {path: data for path, data in files.items() if not path.startswith("identities/avery-laptop.")}

    changed = dict(files)
    changed["HIVE.json"] = rapp1.canonical({"schema": "rapp-hive/2-carrier", "anchor": "0" * 64})
    cases["missing-anchor"] = changed

    avery_signer = model.signer("avery-laptop")
    for name, change in (
        ("calendar-time", {"utc": last["utc"].replace("-09-22T", "-09-31T")}),
        ("prev-wave", {"prev_wave": previous["frame_hash"]}),
        ("kind-grammar", {"kind": "hive2.Attest"}),
    ):
        changed = dict(files)
        changed[hive_frames[-1]] = rapp1.canonical(_resigned(last, avery_signer, **change))
        cases[name] = changed

    declaration_path = next(path for path in files if path.startswith("streams/") and rapp1.parse(files[path])["kind"] == "hive.declaration")
    changed = dict(files)
    changed[declaration_path] = rapp1.canonical(_resigned(rapp1.parse(files[declaration_path]), model.signer("blake-phone")))
    cases["legacy-declaration-not-by-owner"] = changed

    declaration = rapp1.parse(files[declaration_path])
    anchor = rapp1.parse(files["objects/" + rapp1.parse(files["HIVE.json"])["anchor"] + ".json"])
    payload = declaration["payload"]
    for name, edited in (
        ("legacy-declaration-incomplete", {key: value for key, value in payload.items() if key != "rooms"}),
        ("legacy-declaration-malformed-role", {**payload, "members": [{**item, "role": []} if item["role"] == "viewer" or item["rappid"] == payload["members"][-1]["rappid"] else item for item in payload["members"]]}),
    ):
        resigned = _resigned(declaration, avery_signer, payload=edited)
        successor = {**anchor, "legacy": {**anchor["legacy"], "declaration": resigned["frame_hash"]}}
        changed = dict(files)
        changed[declaration_path] = rapp1.canonical(resigned)
        changed["objects/" + rapp1.particle(successor) + ".json"] = rapp1.canonical(successor)
        changed["HIVE.json"] = rapp1.canonical({"schema": "rapp-hive/2-carrier", "anchor": rapp1.particle(successor)})
        cases[name] = changed

    malformed_schema = {"schema": schemas.VERSION}
    changed = dict(files)
    changed["objects/" + rapp1.particle(malformed_schema) + ".json"] = rapp1.canonical(malformed_schema)
    cases["schema-object-malformed"] = changed
    return cases


def generate() -> dict[str, Any]:
    built = model.build()
    files = built["hive"]
    hives: list[dict[str, Any]] = []
    variants = {
        "model": {},
        "variant-re-decide": {"migrate_pending": "re-decide"},
        "variant-unattested": {"attest_drew": False},
        "variant-divergent-manifest": {"divergent_manifest": True},
        "variant-adversarial": {"adversarial": True},
        "variant-double-request": {"double_request": True},
    }
    for name, options in variants.items():
        variant = built if not options else model.build(**options)
        verdict, code, _evaluation = _run(variant["hive"])
        if verdict is None:
            raise AssertionError(f"{name} must verify, got {code}")
        hives.append({"name": name, "files": {path: _b64(data) for path, data in sorted(variant["hive"].items())}, "expect": {"verdict": verdict}})
    for name, changed in _tampered(files, built).items():
        verdict, code, _evaluation = _run(changed)
        if code is None:
            raise AssertionError(f"tamper case {name} must be refused")
        hives.append({"name": f"tamper-{name}", "files": {path: _b64(data) for path, data in sorted(changed.items())}, "expect": {"refused": code}})
    _verdict, _code, evaluation = _run(files)
    crossings = []
    for item in built["crossings"]:
        try:
            result = crossing.cross_to_member(evaluation, item["source"], item["member"])
            expect: dict[str, Any] = {"payload_particle": result["payload_particle"], "not_expressible_in_target": result["not_expressible_in_target"], "lossless": result["lossless"]}
        except Refusal as error:
            expect = {"refused": error.code}
        crossings.append({"hive": "model", "source": item["source"], "member": item["member"], "expect": expect})
    schema_cases = []
    for path in sorted(files):
        if path.startswith("streams/"):
            frame = rapp1.parse(files[path])
            schema_cases.append({"frame_b64": _b64(files[path]), "schema_particle": schemas.particle(schemas.schema_of(frame))})
    return {
        "schema": SCHEMA,
        "note": "SYNTHETIC. Public test keys; no real people, devices or data.",
        "canonical": canonical_cases(),
        "schemas": schema_cases,
        "hives": hives,
        "crossings": crossings,
    }


def encode(vectors: dict[str, Any]) -> bytes:
    return (json.dumps(vectors, indent=1, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8")


def check(vectors: dict[str, Any]) -> dict[str, Any]:
    """Run this engine against a vectors document; returns counts and any failures."""
    failures: list[str] = []
    passed = 0
    for item in vectors["canonical"]["values"]:
        value = make(item["make"]) if "make" in item else json.loads(item["json"])
        try:
            got: dict[str, Any] = {"particle": rapp1.particle(value)}
        except Refusal as error:
            got = {"refused": error.code}
        expect = item.get("expect") or {"particle": item["particle"]}
        if "canonical_b64" in item and _b64(rapp1.canonical(value)) != item["canonical_b64"]:
            failures.append("canonical bytes")
        passed += got == expect
        failures += [] if got == expect else [f"canonical {item.get('name') or item['json'][:30]}"]
    for item in vectors["canonical"]["refused"]:
        try:
            rapp1.parse(base64.b64decode(item["b64"]))
            failures.append(f"refused {item['why']}")
        except Refusal:
            passed += 1
    for item in vectors["schemas"]:
        frame = rapp1.parse(base64.b64decode(item["frame_b64"]))
        ok = schemas.particle(schemas.schema_of(frame)) == item["schema_particle"]
        passed += ok
        failures += [] if ok else ["schema particle"]
    evaluations: dict[str, Any] = {}
    for item in vectors["hives"]:
        files = {path: base64.b64decode(data) for path, data in item["files"].items()}
        verdict, code, evaluation = _run(files)
        got = {"verdict": verdict} if verdict is not None else {"refused": code}
        ok = rapp1.canonical(got) == rapp1.canonical(item["expect"])
        passed += ok
        failures += [] if ok else [f"hive {item['name']}"]
        evaluations[item["name"]] = evaluation
    for item in vectors["crossings"]:
        try:
            result = crossing.cross_to_member(evaluations[item["hive"]], item["source"], item["member"])
            got = {"payload_particle": result["payload_particle"], "not_expressible_in_target": result["not_expressible_in_target"], "lossless": result["lossless"]}
        except Refusal as error:
            got = {"refused": error.code}
        ok = got == item["expect"]
        passed += ok
        failures += [] if ok else [f"crossing {item['source'][:12]}"]
    return {"passed": passed, "failed": failures}


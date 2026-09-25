"""Rebuild the house before migration (rapp-hive/1) from the frames it shares with model/hive.

    python3 -B tools/before.py <new folder>    write the old house into a new or empty folder

The migration rewrote nothing, so every frame of the old house is still in model/hive, byte for
byte. Each frame is stored once in this repository: model/before/ keeps the old identity records and
FRAMES.json, which names every old frame by its path, frame hash and SHA-256. This tool reads those
frames from model/hive, refuses unless every one matches, verifies the whole house with the vendored
reference, and only then writes it, ready for `python3 -B -m rapp_hive2 migrate plan-hive1 <folder>`.

Everything here is SYNTHETIC: fictional people, public test keys, no real data.
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "vendor"))

from rapp_hive2 import hive, model as contoso, rapp1, sign, store  # noqa: E402
from rapp_hive2.rapp1 import Refusal  # noqa: E402

SCHEMA = "rapp-model-hive-before/1"
INDEX = "FRAMES.json"
STORED_IN = "model/hive"
INDEX_KEYS = {"schema", "note", "stored_in", "frames"}
ENTRY_KEYS = {"path", "frame_hash", "sha256"}


def stored(house: dict[str, bytes], hive_files: dict[str, bytes], note: str) -> dict[str, bytes]:
    """What model/before/ holds for a house: its identity records and FRAMES.json, never a second copy of a frame."""
    kept: dict[str, bytes] = {}
    frames = []
    for path, data in sorted(house.items()):
        if path.startswith("identities/"):
            kept[path] = data
        elif path.startswith("streams/"):
            if hive_files.get(path) != data:
                raise Refusal("REFUSE_TAMPER", f"{path} is not in the migrated Hive byte for byte; a migration never rewrites a frame.")
            frames.append({"path": path, "frame_hash": rapp1.parse(data)["frame_hash"], "sha256": rapp1.digest(data)})
        else:
            raise Refusal("REFUSE_SCHEMA", f"{path}: the house before migration holds only identities/ and streams/.")
    if not frames:
        raise Refusal("REFUSE_SCHEMA", "The house before migration has no frames.")
    kept[INDEX] = (json.dumps({"schema": SCHEMA, "note": note, "stored_in": STORED_IN, "frames": frames}, indent=1, ensure_ascii=False) + "\n").encode("utf-8")
    return kept


def house(root: Path = ROOT) -> dict[str, bytes]:
    """The house before migration, exactly: identity records from model/before, each frame from model/hive, all checked."""
    before, frames_root = root / "model" / "before", root / STORED_IN
    listed = rapp1.parse(store.read_inside(before, INDEX, limit=hive.MAX_OBJECT_BYTES), require_canonical=False)
    if type(listed) is not dict or set(listed) != INDEX_KEYS or listed["schema"] != SCHEMA or listed["stored_in"] != STORED_IN or type(listed["frames"]) is not list or not listed["frames"]:
        raise Refusal("REFUSE_SCHEMA", f"model/before/{INDEX} is not a {SCHEMA} listing.")
    rebuilt: dict[str, bytes] = {}
    for path in hive._files(before):
        if path.startswith("identities/"):
            rebuilt[path] = store.read_inside(before, path, limit=hive.MAX_OBJECT_BYTES)
        elif path != INDEX:
            raise Refusal("REFUSE_SCHEMA", f"model/before/{path} is unexpected: model/before holds only identities/ and {INDEX}, and each frame is stored once, in {STORED_IN}.")
    for entry in listed["frames"]:
        path = entry.get("path") if type(entry) is dict else None
        if (
            type(entry) is not dict
            or set(entry) != ENTRY_KEYS
            or type(path) is not str
            or not path.startswith("streams/")
            or path in rebuilt
            or any(type(entry[key]) is not str or not rapp1.HASH_RE.fullmatch(entry[key]) for key in ("frame_hash", "sha256"))
        ):
            raise Refusal("REFUSE_SCHEMA", f"model/before/{INDEX} names a frame it may not: {str(path)[:80]!r}.")
        data = store.read_inside(frames_root, path, limit=hive.MAX_OBJECT_BYTES)
        if rapp1.digest(data) != entry["sha256"]:
            raise Refusal("REFUSE_TAMPER", f"{STORED_IN}/{path} is not the frame model/before/{INDEX} names (SHA-256 differs).")
        frame = rapp1.parse(data)
        rapp1.frame_integrity(frame)
        if frame["frame_hash"] != entry["frame_hash"] or sign.frame_path(frame) != path:
            raise Refusal("REFUSE_TAMPER", f"{STORED_IN}/{path} is not the frame model/before/{INDEX} names (frame hash or place differs).")
        rebuilt[path] = data
    return rebuilt


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("folder", help="a new or empty folder for the house before migration")
    args = parser.parse_args()
    target = Path(args.folder)
    try:
        files = house()
        with tempfile.TemporaryDirectory() as scratch:
            trial = Path(scratch) / "before"
            store.write_new_tree(trial, files)
            records = hive.verify_frames(hive.load(trial))
        store.write_new_tree(target, files)
    except Refusal as error:
        print(json.dumps({"ok": False, "refusal": {"code": error.code, "message": error.message}}, indent=2))
        return 1
    declaration = next(record.wave for record in records if record.kind == "hive.declaration")
    requests = sorted(record.wave for record in records if record.frame["payload"].get("operation") == "join-request")
    folder = target.resolve()
    plan = folder.parent / (folder.name + "-plan.json")
    print(json.dumps({
        "ok": True,
        "folder": args.folder,
        "identities": sum(1 for path in files if path.startswith("identities/")),
        "frames_verified": len(records),
        "declaration": declaration,
        "legacy_requests": requests,
        "next": f'cd vendor && python3 -B -m rapp_hive2 migrate plan-hive1 "{folder}" --declaration {declaration} '
        + "".join(f"--legacy-request {request} " for request in requests)
        + f'--name "{contoso.NAME}" --out "{plan}"',
    }, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

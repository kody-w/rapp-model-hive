"""ModelHive: walk through the Contoso Model Hive with your Brainstem.

The Contoso Model Hive is a SYNTHETIC "model home" for the experimental rapp-hive/2 draft:
fictional people and devices, signed with public test keys that anyone can re-derive.

Hotloadable RAPP Brainstem agent. It reads the rapp-model-hive checkout it lives in (or the one
named by the RAPP_MODEL_HIVE environment variable), answers with JSON, and never writes into that
checkout, uses the network or signs anything real. It reads only plain folders inside the checkout
(never through links), and runs only the vendored reference engine whose exact bytes it pins below,
under a private module name, so it cannot collide with other engines.
"""

from __future__ import annotations

import hashlib
import importlib
import importlib.abc
import importlib.util
import json
import os
import stat
import sys
import tempfile
import threading
import types
from pathlib import Path
from typing import Any

try:
    from agents.basic_agent import BasicAgent
except ImportError:
    try:
        from basic_agent import BasicAgent
    except ImportError:
        class BasicAgent:  # standalone use outside a Brainstem
            def __init__(self, name: str | None = None, metadata: dict[str, Any] | None = None) -> None:
                self.name = name
                self.metadata = metadata

SYNTHETIC = "Synthetic model: fictional people and devices, signed with public test keys that anyone can re-derive. Never use them for real data."
REPOSITORY = "https://github.com/kody-w/rapp-model-hive"
TRUSTED_ANCHOR = "03972c7e8049b59134681ef9b1d7af369e4b06273d262691c5b28d6c48dcdce8"
# ENGINE-PINS-BEGIN (tools/vendor.py rewrites this block)
ENGINE_SHA256 = {
    "__init__.py": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "__main__.py": "9da1279d3a5a2427179a20893b67ae7e4832f5475c6c47afc8fe8959a7502838",
    "crossing.py": "9d3e89c7d9105e0e8fc50dbd42269436f73f892444740329247a9849e7f6e694",
    "hive.py": "08837efcaa3c3acf096a4dfc8f2f38d81f964b045c6b28aa035fd1ebaea1c83e",
    "lens.py": "4a26433e3c4c5306378df7755b10f9511b2d3b62e37c63b5bfd710808c7d33a2",
    "migrate.py": "bb863affb0a6412ce1a2b321853093853f272463bf299f5b763009689513d8f1",
    "model.py": "189df0c7cab872ca2ec8637c6bce048907fc488bbb10306395620db9c171988c",
    "rapp1.py": "2f564c56fb322a13af3910642903a6a64903ec63f43c6dac4329be49c83ef1fa",
    "schema.py": "0cf2d9a7c22595a6e15405ce84a1c3df842342c8bb7f778155d2dc668b61d23d",
    "sign.py": "cb224e81e5e023db1fba79835815ad5ba9c2fdcb73c5f74b45a211a7f52fef56",
    "store.py": "a3019971f27d7218bdf4c37536eac2d70465253cc6b803fa8d4c4281e7e86c02",
    "vectors.py": "59e329033f1152c9c6d7e85244ba420cfa503e93f38e0c6175f7202682b84eb5",
}
# ENGINE-PINS-END
ENGINE_MODULES = ("rapp1", "schema", "lens", "store", "hive", "sign", "crossing", "migrate", "model", "vectors", "__main__")
MIGRATION_STEPS = (("avery-laptop", 1, "2026-09-21T09:00:00.000Z"), ("blake-phone", 1, "2026-09-21T09:05:00.000Z"), ("casey-tablet", 1, "2026-09-21T09:10:00.000Z"), ("avery-laptop", 2, "2026-09-21T09:20:00.000Z"))
MAX_TEXT = 256 * 1024
MAX_VECTORS = 64 * 1024 * 1024
ACTIONS = ("tour", "status", "verify", "cross", "migrate_demo", "conformance")
PLAIN_FOLDERS = ("vendor", "vendor/rapp_hive2", "model", "model/hive", "model/before", "tour", "conformance")
BEFORE_SCHEMA = "rapp-model-hive-before/1"


class AgentError(Exception):
    def __init__(self, code: str, message: str, next_step: str) -> None:
        super().__init__(message)
        self.code, self.message, self.next_step = code, message, next_step


class _PinnedEngine(importlib.abc.MetaPathFinder, importlib.abc.Loader):
    """Serves exactly the verified source bytes: nothing is re-read from disk and no bytecode is written."""

    def __init__(self, name: str, folder: Path, sources: dict[str, bytes]) -> None:
        self.name, self.folder, self.sources = name, folder, sources

    def _short(self, fullname: str) -> str | None:
        if fullname == self.name:
            return "__init__"
        prefix = self.name + "."
        if fullname.startswith(prefix) and fullname[len(prefix):] + ".py" in self.sources:
            return fullname[len(prefix):]
        return None

    def find_spec(self, fullname: str, path: Any = None, target: Any = None) -> Any:
        short = self._short(fullname)
        if short is None:
            return None
        return importlib.util.spec_from_loader(fullname, self, origin=str(self.folder / f"{short}.py"), is_package=short == "__init__")

    def create_module(self, spec: Any) -> None:
        return None

    def exec_module(self, module: Any) -> None:
        short = self._short(module.__name__)
        module.__file__ = str(self.folder / f"{short}.py")
        exec(compile(self.sources[f"{short}.py"], module.__file__, "exec", dont_inherit=True), module.__dict__)


def _pins_digest() -> str:
    return hashlib.sha256(json.dumps(ENGINE_SHA256, sort_keys=True).encode("utf-8")).hexdigest()


def _registry() -> Any:
    """One lock and one readiness record per process, shared by every hotloaded copy of this file."""
    registry = sys.modules.setdefault("_rapp_model_hive_registry", types.ModuleType("_rapp_model_hive_registry"))
    registry.__dict__.setdefault("lock", threading.RLock())
    registry.__dict__.setdefault("ready", set())
    return registry


def _is_link(info: os.stat_result) -> bool:
    return stat.S_ISLNK(info.st_mode) or bool(getattr(info, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT)


def repository_root() -> Path:
    configured = os.environ.get("RAPP_MODEL_HIVE")
    root = Path(configured).expanduser().resolve() if configured else Path(__file__).resolve().parent.parent
    if not (root / "vendor" / "rapp_hive2").is_dir() or not (root / "model" / "hive").is_dir():
        raise AgentError("REPO_NOT_FOUND", "This agent cannot find a rapp-model-hive checkout.", f"Clone {REPOSITORY} and set RAPP_MODEL_HIVE to its folder, or run the agent from that checkout.")
    for relative in PLAIN_FOLDERS:
        current = root
        for part in relative.split("/"):
            current = current / part
            try:
                info = os.lstat(current)
            except OSError as error:
                raise AgentError("REPO_NOT_FOUND", f"{relative} is missing from the checkout.", f"Restore the checkout from {REPOSITORY}.") from error
            if _is_link(info) or not stat.S_ISDIR(info.st_mode):
                raise AgentError("UNSAFE_CHECKOUT", f"{relative} is a link or not a folder; this agent reads only plain folders inside its checkout.", f"Restore the checkout from {REPOSITORY}.")
    return root


def load_engine(root: Path) -> dict[str, Any]:
    """The vendored rapp-hive/2 reference under a private module name; warm after the first call."""
    name = "_rapp_model_hive_" + _pins_digest()[:16]
    registry = _registry()
    with registry.lock:
        if name not in registry.ready:
            for key in [key for key in sys.modules if key == name or key.startswith(name + ".")]:
                del sys.modules[key]
            folder = root / "vendor" / "rapp_hive2"
            sources: dict[str, bytes] = {}
            for filename, expected in ENGINE_SHA256.items():
                path = folder / filename
                if not path.is_file() or path.is_symlink() or path.stat().st_size > 2 * 1024 * 1024:
                    raise AgentError("ENGINE_MISSING", f"vendor/rapp_hive2/{filename} is missing or not a plain file.", f"Restore the checkout from {REPOSITORY}.")
                data = path.read_bytes()
                if hashlib.sha256(data).hexdigest() != expected:
                    raise AgentError("ENGINE_MISMATCH", f"vendor/rapp_hive2/{filename} is not the pinned reference; nothing was run.", "Restore the vendored files, or update this agent together with them (tools/vendor.py).")
                sources[filename] = data
            finder = _PinnedEngine(name, folder, sources)
            sys.meta_path.append(finder)
            try:
                spec = finder.find_spec(name)
                package = importlib.util.module_from_spec(spec)
                sys.modules[name] = package
                spec.loader.exec_module(package)
                for module in ENGINE_MODULES:
                    importlib.import_module(f"{name}.{module}")
            except BaseException:
                sys.meta_path.remove(finder)
                for key in [key for key in sys.modules if key == name or key.startswith(name + ".")]:
                    del sys.modules[key]
                raise
            registry.ready.add(name)
    return {module: sys.modules[f"{name}.{module}"] for module in ENGINE_MODULES}


def _read_text(engine: dict[str, Any], root: Path, relative: str) -> str:
    return engine["store"].read_inside(root, relative, limit=MAX_TEXT).decode("utf-8")


def _people(engine: dict[str, Any], root: Path) -> dict[str, dict[str, str]]:
    """Display labels only (model/STORY.json is derived and never authority)."""
    story = json.loads(_read_text(engine, root, "model/STORY.json"))
    return {rappid: {"slug": item["slug"], "label": item["label"]} for rappid, item in story["people"].items()}


def _slug(rappid: str) -> str:
    return rappid.split("/", 1)[1].split(":", 1)[0] if rappid.startswith("rappid:@") else rappid[:16]


def _evaluate(engine: dict[str, Any], folder: Path) -> tuple[Any, Any, Any, dict[str, Any]]:
    return engine["hive"].evaluate_folder(folder, TRUSTED_ANCHOR)


def tour(engine: dict[str, Any], root: Path, room: str) -> dict[str, Any]:
    rooms = sorted(path.name for path in (root / "tour").glob("[0-9][0-9]-*.md"))
    wanted = room.strip().lower().replace(" ", "-").replace("_", "-")
    if wanted in ("", "context", "start", "index", "rooms"):
        chosen = "CONTEXT.md"
    else:
        if wanted.isdigit():
            wanted = f"{int(wanted):02d}-"
        matches = [name for name in rooms if name.startswith(wanted) or wanted in name]
        if len(matches) != 1:
            raise AgentError("UNKNOWN_ROOM", f"No single tour room matches {room!r}.", "Choose one of: " + ", ".join(name[:-3] for name in rooms) + ".")
        chosen = matches[0]
    following = rooms[rooms.index(chosen) + 1][:-3] if chosen in rooms and rooms.index(chosen) + 1 < len(rooms) else (rooms[0][:-3] if chosen == "CONTEXT.md" else None)
    return {"room": chosen[:-3], "text": _read_text(engine, root, f"tour/{chosen}"), "next_room": following}


def status(engine: dict[str, Any], root: Path) -> dict[str, Any]:
    carried, records, evaluation, verdict = _evaluate(engine, root / "model" / "hive")
    return {
        "summary": engine["__main__"].status_lines(evaluation, verdict),
        "frames_verified": len(records),
        "anchor": TRUSTED_ANCHOR,
        "carrier_names_the_pinned_anchor": carried.anchor == TRUSTED_ANCHOR,
        "state_particle": evaluation.state_particle,
    }


def verify(engine: dict[str, Any], root: Path) -> dict[str, Any]:
    carried, records, evaluation, verdict = _evaluate(engine, root / "model" / "hive")
    return {
        "frames_verified": len(records),
        "anchor": TRUSTED_ANCHOR,
        "carrier_names_the_pinned_anchor": carried.anchor == TRUSTED_ANCHOR,
        "state_particle": evaluation.state_particle,
        "verdict": verdict,
    }


def cross(engine: dict[str, Any], root: Path, message: str, member: str) -> dict[str, Any]:
    _carried, _records, evaluation, verdict = _evaluate(engine, root / "model" / "hive")
    people = _people(engine, root)
    if not message.strip() or not member.strip():
        mapped = {item["source"] for item in verdict["views"]}
        choices = []
        for record in evaluation.content:
            if record.wave in mapped:
                payload = record.frame["payload"]
                choices.append({"message": record.wave[:12], "from": people.get(record.owner, {}).get("label", _slug(record.owner)), "says": payload.get("title") or payload.get("summary") or payload.get("text")})
        members = sorted(_slug(rappid) for rappid in evaluation.members)
        return {"outcome": "choose", "messages": choices, "members": members, "hint": "Call cross again with a message (its first 12 hex characters) and a receiving member."}
    try:
        result = engine["crossing"].cross_to_member(evaluation, message, member)
    except engine["rapp1"].Refusal as error:
        if error.code == "REFUSE_UNKNOWN_TARGET":
            raise AgentError("BAD_INPUT", error.message, "Call cross with no message or member to list the choices.") from error
        return {"outcome": "refused", "code": error.code, "reason": error.message}
    return {"outcome": "crossed", **result}


def _before_house(engine: dict[str, Any], root: Path) -> dict[str, bytes]:
    """The house before migration, exactly as tools/before.py rebuilds it: identity records from model/before, and each
    old frame from model/hive, where it is stored once, checked against model/before/FRAMES.json by path, SHA-256 and frame hash."""
    hive, rapp1, sign, store = engine["hive"], engine["rapp1"], engine["sign"], engine["store"]
    before, after = root / "model" / "before", root / "model" / "hive"
    listed = rapp1.parse(store.read_inside(before, "FRAMES.json", limit=MAX_TEXT), require_canonical=False)
    if type(listed) is not dict or set(listed) != {"schema", "note", "stored_in", "frames"} or listed["schema"] != BEFORE_SCHEMA or listed["stored_in"] != "model/hive" or type(listed["frames"]) is not list or not listed["frames"]:
        raise rapp1.Refusal("REFUSE_SCHEMA", f"model/before/FRAMES.json is not a {BEFORE_SCHEMA} listing.")
    house: dict[str, bytes] = {}
    for path in hive._files(before):
        if path.startswith("identities/"):
            house[path] = store.read_inside(before, path, limit=hive.MAX_OBJECT_BYTES)
        elif path != "FRAMES.json":
            raise rapp1.Refusal("REFUSE_SCHEMA", f"model/before/{path} is unexpected: each frame is stored once, in model/hive.")
    for entry in listed["frames"]:
        path = entry.get("path") if type(entry) is dict else None
        if type(entry) is not dict or set(entry) != {"path", "frame_hash", "sha256"} or type(path) is not str or not path.startswith("streams/") or path in house:
            raise rapp1.Refusal("REFUSE_SCHEMA", f"model/before/FRAMES.json names a frame it may not: {str(path)[:80]!r}.")
        data = store.read_inside(after, path, limit=hive.MAX_OBJECT_BYTES)
        if rapp1.digest(data) != entry["sha256"]:
            raise rapp1.Refusal("REFUSE_TAMPER", f"model/hive/{path} is not the frame model/before/FRAMES.json names (SHA-256 differs).")
        frame = rapp1.parse(data)
        rapp1.frame_integrity(frame)
        if frame["frame_hash"] != entry["frame_hash"] or sign.frame_path(frame) != path:
            raise rapp1.Refusal("REFUSE_TAMPER", f"model/hive/{path} is not the frame model/before/FRAMES.json names (frame hash or place differs).")
        house[path] = data
    return house


def migrate_demo(engine: dict[str, Any], root: Path) -> dict[str, Any]:
    """Replay the move from rapp-hive/1 on a private copy of the house before migration, each identity signing its own steps."""
    hive, migrate, model, store = engine["hive"], engine["migrate"], engine["model"], engine["store"]
    after = root / "model" / "hive"
    house = _before_house(engine, root)
    with tempfile.TemporaryDirectory() as scratch:
        folder = Path(scratch) / "hive"
        store.write_new_tree(folder, house)
        carried = hive.load(folder)
        records = hive.verify_frames(carried)
        declaration = next(item.wave for item in records if item.kind == "hive.declaration")
        requests = [item.wave for item in records if item.frame["payload"].get("operation") == "join-request"]
        plan = migrate.plan_from_rapp_hive_1(carried, records, declaration, name=model.NAME, legacy_requests=requests)
        steps = []
        for slug, phase, utc in MIGRATION_STEPS:
            written = migrate.apply(plan, folder, model.signer(slug), phase=phase, utc=utc)
            steps.append({"signer": slug, "phase": phase, "files_written": len(written)})
        compared = [path for path in hive._files(folder) if path.startswith("streams/")]
        differing = [path for path in compared if store.read_inside(folder, path, limit=hive.MAX_OBJECT_BYTES) != store.read_inside(after, path, limit=hive.MAX_OBJECT_BYTES)]
    return {
        "plan_particle": plan["plan_particle"],
        "old_frames_checked": sum(1 for path in house if path.startswith("streams/")),
        "steps": steps,
        "frames_compared": len(compared),
        "matches_committed_model": not differing,
        "differing": differing[:20],
        "explanation": "The old declaration and requests stay untouched: each old frame is stored once, in model/hive, and model/before/FRAMES.json names it by hash. The owner accepts a new anchor; each old member signs its own join; the steward policy (v1) mirrors the one owner, and the old onboarding request stays pending under v1's rules.",
    }


def conformance(engine: dict[str, Any], root: Path) -> dict[str, Any]:
    data = engine["store"].read_inside(root, "conformance/vectors.json", limit=MAX_VECTORS)
    outcome = engine["vectors"].check(json.loads(data))
    return {"passed": outcome["passed"], "failed": outcome["failed"]}


class ModelHiveAgent(BasicAgent):
    def __init__(self) -> None:
        self.name = "ModelHive"
        self.metadata = {
            "name": self.name,
            "description": (
                "Walk someone through the Contoso Model Hive: a fully synthetic example Hive (fictional people, public test keys) "
                "for the experimental rapp-hive/2 draft. Actions: tour (read a room: 1 front door, 2 residents, 3 renovation, "
                "4 schemas and lenses, 5 crossings, 6 agreement, 7 timeline), status (verify it and summarize in plain language), "
                "verify (the full derived verdict), cross (translate one person's message into another member's app shape; call "
                "with no message to list choices), migrate_demo (replay the move from rapp-hive/1 and compare byte for byte), "
                "conformance (run the protocol's conformance vectors)."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "action": {"type": "string", "enum": list(ACTIONS), "description": "What to do."},
                    "room": {"type": "string", "description": "For tour: a room number (1-7) or name; empty for the room list."},
                    "message": {"type": "string", "description": "For cross: the first 12 hex characters of a message."},
                    "member": {"type": "string", "description": "For cross: the receiving member, for example avery-laptop."},
                },
                "required": ["action"],
            },
        }
        super().__init__(name=self.name, metadata=self.metadata)

    def perform(self, **kwargs: Any) -> str:
        action = str(kwargs.get("action") or "").strip()
        try:
            if action not in ACTIONS:
                raise AgentError("UNKNOWN_ACTION", f"Unknown action {action!r}.", "Use one of: " + ", ".join(ACTIONS) + ".")
            root = repository_root()
            try:
                engine = load_engine(root)
            except ImportError as error:
                raise AgentError("MISSING_DEPENDENCY", f"The reference engine needs a Python package that is not installed ({error.name or error}).", "Install it with: python3 -m pip install 'cryptography>=43'") from error
            handlers = {
                "tour": lambda: tour(engine, root, str(kwargs.get("room") or "")),
                "status": lambda: status(engine, root),
                "verify": lambda: verify(engine, root),
                "cross": lambda: cross(engine, root, str(kwargs.get("message") or ""), str(kwargs.get("member") or "")),
                "migrate_demo": lambda: migrate_demo(engine, root),
                "conformance": lambda: conformance(engine, root),
            }
            try:
                result = handlers[action]()
            except ImportError as error:
                raise AgentError("MISSING_DEPENDENCY", f"The reference engine needs a Python package that is not installed ({error.name or error}).", "Install it with: python3 -m pip install 'cryptography>=43'") from error
            except AgentError:
                raise
            except Exception as error:
                refusal = sys.modules.get(f"_rapp_model_hive_{_pins_digest()[:16]}.rapp1")
                if refusal is not None and isinstance(error, refusal.Refusal):
                    raise AgentError(error.code, error.message, "The model did not verify. Restore it from the repository (tools/build.py --check shows what changed).") from error
                raise
            ok = action != "conformance" or not result["failed"]
            return json.dumps({"ok": ok, "action": action, "synthetic": SYNTHETIC, **result}, indent=2, ensure_ascii=False)
        except AgentError as error:
            return json.dumps({"ok": False, "action": action, "error": {"code": error.code, "message": error.message, "next": error.next_step}}, indent=2, ensure_ascii=False)
        except Exception as error:  # never crash the host
            return json.dumps({"ok": False, "action": action, "error": {"code": "INTERNAL", "message": f"{type(error).__name__}: {error}", "next": f"Report this at {REPOSITORY}/issues."}}, indent=2, ensure_ascii=False)

"""Model Hive checks. Run from the repository root: python3 -B -m unittest discover -s tests -v"""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import types
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
VENDOR = ROOT / "vendor"
PAGE = ROOT / "app" / "model-hive.html"
AGENT_FILE = ROOT / "agents" / "model_hive_agent.py"
UTF8 = {**os.environ, "PYTHONUTF8": "1", "PYTHONDONTWRITEBYTECODE": "1"}
sys.path.insert(0, str(VENDOR))

from rapp_hive2 import hive, model, rapp1, vectors  # noqa: E402

AGENT_COUNT = 0
RAPPID = re.compile(r"@[a-z0-9]+(?:-[a-z0-9]+)*/[a-z0-9]+(?:-[a-z0-9]+)*:[0-9a-f]{64}(?![0-9a-f])")  # a keyed rappid (RAPP/1 §6.1), with or without "rappid:"


def load_agent() -> types.ModuleType:
    """Hotload the agent file the way a Brainstem does: a fresh module object every time."""
    global AGENT_COUNT
    AGENT_COUNT += 1
    spec = importlib.util.spec_from_file_location(f"model_hive_agent_hotload_{AGENT_COUNT}", AGENT_FILE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def ask(agent: object, **kwargs: str) -> dict:
    return json.loads(agent.perform(**kwargs))


def run(*args: str, cwd: Path = ROOT, timeout: int = 300) -> subprocess.CompletedProcess:
    return subprocess.run(list(args), cwd=cwd, env=UTF8, capture_output=True, text=True, encoding="utf-8", timeout=timeout)


def copy_checkout(target: Path) -> Path:
    for part in ("vendor", "model", "tour", "conformance", "agents"):
        shutil.copytree(ROOT / part, target / part, ignore=shutil.ignore_patterns("__pycache__"))
    return target


def chrome() -> str | None:
    candidates = [
        os.environ.get("CHROME"),
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        shutil.which("google-chrome"),
        shutil.which("google-chrome-stable"),
        shutil.which("chromium"),
        shutil.which("chromium-browser"),
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
    ]
    return next((item for item in candidates if item and Path(item).is_file()), None)


class ModelTests(unittest.TestCase):
    def test_model_and_tour_are_exactly_what_the_reference_builds(self) -> None:
        done = run(sys.executable, "-B", "tools/build.py", "--check")
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertTrue(json.loads(done.stdout)["ok"])
        self.assertTrue(json.loads(done.stdout)["before_rebuilt_byte_for_byte"])

    def test_the_vendored_reference_is_the_pinned_commit(self) -> None:
        provenance = json.loads((VENDOR / "PROVENANCE.json").read_text(encoding="utf-8"))
        self.assertRegex(provenance["commit"], r"^[0-9a-f]{40}$")
        self.assertEqual(provenance["track"], "experimental-frontier")
        present = {f"rapp_hive2/{path.name}" for path in (VENDOR / "rapp_hive2").glob("*.py")}
        self.assertEqual(present, set(provenance["files_sha256"]))
        for name, digest in provenance["files_sha256"].items():
            self.assertEqual(hashlib.sha256((VENDOR / name).read_bytes()).hexdigest(), digest, name)
        self.assertEqual(hashlib.sha256((ROOT / "conformance" / "vectors.json").read_bytes()).hexdigest(), provenance["conformance"]["sha256"])

    def test_the_conformance_vectors_pass(self) -> None:
        outcome = vectors.check(json.loads((ROOT / "conformance" / "vectors.json").read_bytes()))
        self.assertEqual(outcome["failed"], [])
        self.assertGreater(outcome["passed"], 60)

    def test_the_model_verifies_against_the_published_anchor(self) -> None:
        agent = load_agent()
        story = json.loads((ROOT / "model" / "STORY.json").read_text(encoding="utf-8"))
        carrier = json.loads((ROOT / "model" / "hive" / "HIVE.json").read_bytes())
        self.assertEqual(agent.TRUSTED_ANCHOR, carrier["anchor"])
        self.assertEqual(agent.TRUSTED_ANCHOR, story["anchor"])
        self.assertIn(agent.TRUSTED_ANCHOR, (ROOT / "README.md").read_text(encoding="utf-8"))
        _carried, records, evaluation, verdict = hive.evaluate_folder(ROOT / "model" / "hive", agent.TRUSTED_ANCHOR)
        self.assertEqual(evaluation.state_particle, story["state_particle"])
        self.assertEqual(len(records), len(story["story"]))
        self.assertEqual(sorted(item["verdict"] for item in verdict["manifests"]), ["consistent"] * 4)
        self.assertEqual([item["code"] for item in verdict["refusals"]], ["REFUSE_NOT_DECIDER", "REFUSE_STALE", "REFUSE_LENS_LAW"])

    def test_the_agent_pins_exactly_the_vendored_engine(self) -> None:
        provenance = json.loads((VENDOR / "PROVENANCE.json").read_text(encoding="utf-8"))
        agent = load_agent()
        self.assertEqual({f"rapp_hive2/{name}": digest for name, digest in agent.ENGINE_SHA256.items()}, provenance["files_sha256"])

    def test_the_command_line_answers_in_plain_language(self) -> None:
        done = run(sys.executable, "-B", "-m", "rapp_hive2", "status", "../model/hive", cwd=VENDOR)
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        summary = json.loads(done.stdout)["summary"]
        self.assertTrue(summary[0].startswith("Contoso Model Hive"))
        self.assertTrue(any(line.startswith("Waiting: frankie-laptop has 1 of 2") for line in summary))


class BeforeTests(unittest.TestCase):
    """The house before migration: each frame is stored once (RAPP/1 §7.6), yet the old house is rebuilt byte for byte."""

    def test_each_frame_is_stored_once(self) -> None:
        positions: dict[tuple[str, int], str] = {}
        for path in sorted(ROOT.rglob("*.json")):
            relative = path.relative_to(ROOT)
            if {".git", "node_modules"}.intersection(relative.parts):
                continue
            try:
                value = json.loads(path.read_bytes())
            except ValueError:
                continue
            if isinstance(value, dict) and set(value) == rapp1.FRAME_KEYS and value.get("spec") == "rapp/1":
                position = (value["stream_id"], value["seq"])
                if position in positions:
                    self.fail(f"{relative.as_posix()} repeats the frame at {positions[position]} (a RAPP/1 §7.6 duplicate position)")
                positions[position] = relative.as_posix()
        self.assertEqual(sorted(positions.values()), sorted(path.relative_to(ROOT).as_posix() for path in (ROOT / "model" / "hive" / "streams").rglob("*.json")))

    def test_the_tour_commands_rebuild_the_house_and_the_plan(self) -> None:
        tour = (ROOT / "tour" / "03-renovation.md").read_text(encoding="utf-8")
        commands = tour.split("```sh\n", 1)[1].split("```", 1)[0].splitlines()
        self.assertEqual(commands[1], "cd vendor")
        with tempfile.TemporaryDirectory() as scratch:
            root = copy_checkout(Path(scratch) / "checkout")
            shutil.copytree(ROOT / "tools", root / "tools", ignore=shutil.ignore_patterns("__pycache__"))
            first, last = ([sys.executable, *shlex.split(line)[1:]] for line in (commands[0], commands[2]))
            done = run(*first, cwd=root)
            self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
            answer = json.loads(done.stdout)
            self.assertEqual(answer["frames_verified"], 4)
            folder = Path(scratch) / "contoso-before"
            self.assertEqual({path: (folder / path).read_bytes() for path in hive._files(folder)}, model.build()["before"])
            done = run(*last, cwd=root / "vendor")
            self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
            story = json.loads((ROOT / "model" / "STORY.json").read_text(encoding="utf-8"))
            self.assertEqual(json.loads(done.stdout)["plan_particle"], story["plan_particle"])
            self.assertTrue((Path(scratch) / "contoso-plan.json").is_file())
            self.assertIn(answer["declaration"], commands[2])
            for request in answer["legacy_requests"]:
                self.assertIn(request, commands[2])

    def test_the_agent_rebuilds_the_same_house(self) -> None:
        agent = load_agent()
        self.assertEqual(agent._before_house(agent.load_engine(ROOT), ROOT), model.build()["before"])

    def test_a_changed_or_misplaced_frame_is_refused(self) -> None:
        def index(root: Path) -> tuple[Path, dict]:
            path = root / "model" / "before" / "FRAMES.json"
            return path, json.loads(path.read_bytes())

        def changed_frame(root: Path) -> None:
            frame = root / "model" / "hive" / index(root)[1]["frames"][1]["path"]
            frame.write_bytes(frame.read_bytes().replace(b"Photograph the site walk-through", b"Photograph the site walk-thru"))

        def renamed(value: str) -> object:
            def change(root: Path) -> None:
                path, listed = index(root)
                listed["frames"][0]["path"] = value
                path.write_text(json.dumps(listed), encoding="utf-8")
            return change

        def listed_twice(root: Path) -> None:
            path, listed = index(root)
            listed["frames"][1] = dict(listed["frames"][0])
            path.write_text(json.dumps(listed), encoding="utf-8")

        def second_copy(root: Path) -> None:
            relative = index(root)[1]["frames"][0]["path"]
            (root / "model" / "before" / relative).parent.mkdir(parents=True)
            shutil.copyfile(root / "model" / "hive" / relative, root / "model" / "before" / relative)

        cases = [
            ("a frame changed in model/hive", changed_frame, "REFUSE_TAMPER"),
            ("a listed path outside streams/", renamed("HIVE.json"), "REFUSE_SCHEMA"),
            ("a listed path that climbs out", renamed("streams/../HIVE.json"), "REFUSE_PORTABLE_PATH"),
            ("a listed path naming another frame", renamed(index(ROOT)[1]["frames"][1]["path"]), "REFUSE_TAMPER"),
            ("one frame listed twice", listed_twice, "REFUSE_SCHEMA"),
            ("a second copy of a frame in model/before", second_copy, "REFUSE_SCHEMA"),
        ]
        for name, change, code in cases:
            with self.subTest(name), tempfile.TemporaryDirectory() as scratch:
                root = copy_checkout(Path(scratch) / "checkout")
                shutil.copytree(ROOT / "tools", root / "tools", ignore=shutil.ignore_patterns("__pycache__"))
                change(root)
                target = Path(scratch) / "contoso-before"
                done = run(sys.executable, "-B", "tools/before.py", str(target), cwd=root)
                self.assertEqual(done.returncode, 1, done.stdout + done.stderr)
                self.assertEqual(json.loads(done.stdout)["refusal"]["code"], code, done.stdout)
                self.assertFalse(target.exists(), "a refused house is never written")
                previous = os.environ.get("RAPP_MODEL_HIVE")
                os.environ["RAPP_MODEL_HIVE"] = str(root)
                try:
                    answer = ask(load_agent().ModelHiveAgent(), action="migrate_demo")
                finally:
                    if previous is None:
                        del os.environ["RAPP_MODEL_HIVE"]
                    else:
                        os.environ["RAPP_MODEL_HIVE"] = previous
                self.assertFalse(answer["ok"])
                self.assertEqual(answer["error"]["code"], code, answer)


class AgentTests(unittest.TestCase):
    def test_the_agent_hotloads_beside_another_engine(self) -> None:
        decoy = types.ModuleType("rapp_hive2")
        saved = {key: sys.modules[key] for key in list(sys.modules) if key == "rapp_hive2" or key.startswith("rapp_hive2.")}
        try:
            for key in saved:
                del sys.modules[key]
            sys.modules["rapp_hive2"] = decoy
            first, second = load_agent().ModelHiveAgent(), load_agent().ModelHiveAgent()
            self.assertTrue(ask(first, action="status")["ok"])
            self.assertTrue(ask(second, action="status")["ok"])
            self.assertIs(sys.modules["rapp_hive2"], decoy)
            self.assertFalse(hasattr(decoy, "hive"))
        finally:
            sys.modules.pop("rapp_hive2", None)
            sys.modules.update(saved)

    def test_the_agent_answers_every_action(self) -> None:
        agent = load_agent().ModelHiveAgent()
        self.assertEqual(agent.name, "ModelHive")
        self.assertEqual(agent.metadata["parameters"]["required"], ["action"])
        status = ask(agent, action="status")
        self.assertTrue(status["ok"] and status["carrier_names_the_pinned_anchor"])
        self.assertIn("Synthetic", status["synthetic"])
        rooms = [ask(agent, action="tour", room=str(number)) for number in range(1, 8)]
        self.assertEqual([room["room"][:2] for room in rooms], [f"{number:02d}" for number in range(1, 8)])
        self.assertEqual(ask(agent, action="tour")["next_room"], "01-front-door")
        self.assertEqual(ask(agent, action="tour", room="unknown room")["error"]["code"], "UNKNOWN_ROOM")
        choices = ask(agent, action="cross")
        self.assertEqual(choices["outcome"], "choose")
        story = json.loads((ROOT / "model" / "STORY.json").read_text(encoding="utf-8"))
        for example in story["crossings"]:
            answer = ask(agent, action="cross", message=example["source"][:12], member=example["member"])
            self.assertEqual(answer["outcome"], example["outcome"], example["what"])
            if example["outcome"] == "crossed":
                self.assertEqual(answer["payload"], example["payload"])
                self.assertEqual(answer["not_expressible_in_target"], example["not_expressible_in_target"])
            else:
                self.assertEqual(answer["code"], example["code"])
        self.assertEqual(ask(agent, action="cross", message="0000000000", member="avery-laptop")["error"]["code"], "BAD_INPUT")
        demo = ask(agent, action="migrate_demo")
        self.assertTrue(demo["matches_committed_model"], demo["differing"])
        self.assertEqual(demo["plan_particle"], story["plan_particle"])
        self.assertEqual(demo["old_frames_checked"], 4)
        self.assertEqual([step["signer"] for step in demo["steps"]], ["avery-laptop", "blake-phone", "casey-tablet", "avery-laptop"])
        verified = ask(agent, action="verify")
        self.assertEqual(verified["state_particle"], story["state_particle"])
        self.assertEqual(ask(agent, action="conformance")["failed"], [])
        self.assertEqual(ask(agent, action="teleport")["error"]["code"], "UNKNOWN_ACTION")

    def test_the_agent_refuses_a_tampered_model(self) -> None:
        agent = load_agent().ModelHiveAgent()
        with tempfile.TemporaryDirectory() as scratch:
            root = copy_checkout(Path(scratch))
            frame = next(path for path in (root / "model" / "hive" / "streams").rglob("*.json") if b"Draft the onboarding checklist" in path.read_bytes())
            frame.write_bytes(frame.read_bytes().replace(b"Draft the onboarding checklist", b"Draft the onboarding checkliST"))
            previous = os.environ.get("RAPP_MODEL_HIVE")
            os.environ["RAPP_MODEL_HIVE"] = str(root)
            try:
                answer = ask(agent, action="status")
            finally:
                if previous is None:
                    del os.environ["RAPP_MODEL_HIVE"]
                else:
                    os.environ["RAPP_MODEL_HIVE"] = previous
        self.assertFalse(answer["ok"])
        self.assertTrue(answer["error"]["code"].startswith("REFUSE_"), answer)

    def test_the_agent_never_runs_an_unpinned_engine(self) -> None:
        with tempfile.TemporaryDirectory() as scratch:
            root = copy_checkout(Path(scratch))
            marker = Path(scratch) / "ran"
            engine = root / "vendor" / "rapp_hive2" / "__init__.py"
            engine.write_text(f"open({str(marker)!r}, 'w').close()\n", encoding="utf-8")
            code = "import importlib.util, json, sys; spec = importlib.util.spec_from_file_location('probe', sys.argv[1]); m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m); print(m.ModelHiveAgent().perform(action='status'))"
            done = subprocess.run([sys.executable, "-B", "-c", code, str(root / "agents" / "model_hive_agent.py")], env={**UTF8, "RAPP_MODEL_HIVE": str(root)}, capture_output=True, text=True, encoding="utf-8", timeout=120)
            answer = json.loads(done.stdout)
            self.assertEqual(answer["error"]["code"], "ENGINE_MISMATCH", done.stdout + done.stderr)
            self.assertFalse(marker.exists(), "tampered engine code must never run")

    @unittest.skipIf(os.name == "nt", "symlinks need privileges on Windows")
    def test_the_agent_never_reads_through_links(self) -> None:
        with tempfile.TemporaryDirectory() as scratch:
            root = copy_checkout(Path(scratch) / "checkout")
            outside = Path(scratch) / "outside"
            outside.mkdir()
            for relative in ("model/hive", "conformance"):
                shutil.move(str(root / relative), str(outside / relative.replace("/", "-")))
                (root / relative).symlink_to(outside / relative.replace("/", "-"), target_is_directory=True)
            code = "import importlib.util, sys; spec = importlib.util.spec_from_file_location('probe', sys.argv[1]); m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m); print(m.ModelHiveAgent().perform(action=sys.argv[2]))"
            for action in ("status", "conformance"):
                done = subprocess.run([sys.executable, "-B", "-c", code, str(root / "agents" / "model_hive_agent.py"), action], env={**UTF8, "RAPP_MODEL_HIVE": str(root)}, capture_output=True, text=True, encoding="utf-8", timeout=120)
                self.assertEqual(json.loads(done.stdout)["error"]["code"], "UNSAFE_CHECKOUT", done.stdout + done.stderr)

    def test_a_hotload_never_uses_a_half_loaded_engine(self) -> None:
        """Another hotload is mid-load (lock held, package published, submodules missing): a second one must wait, not use it."""
        code = "\n".join([
            "import importlib.util, json, sys, threading, time, types",
            "def hotload(name):",
            "    spec = importlib.util.spec_from_file_location(name, sys.argv[1])",
            "    module = importlib.util.module_from_spec(spec)",
            "    spec.loader.exec_module(module)",
            "    return module",
            "first = hotload('hotload_first')",
            "registry = first._registry()",
            "name = '_rapp_model_hive_' + first._pins_digest()[:16]",
            "results = []",
            "registry.lock.acquire()",
            "sys.modules[name] = types.ModuleType(name)",
            "worker = threading.Thread(target=lambda: results.append(json.loads(hotload('hotload_second').ModelHiveAgent().perform(action='status'))))",
            "worker.start()",
            "time.sleep(0.5)",
            "waited = worker.is_alive() and not results",
            "registry.lock.release()",
            "worker.join(120)",
            "print(json.dumps({'waited': waited, 'ok': [item['ok'] for item in results]}))",
        ])
        done = subprocess.run([sys.executable, "-B", "-c", code, str(AGENT_FILE)], env=UTF8, capture_output=True, text=True, encoding="utf-8", timeout=300)
        self.assertEqual(json.loads(done.stdout), {"waited": True, "ok": [True]}, done.stdout + done.stderr)

    def test_the_agent_names_a_missing_checkout(self) -> None:
        with tempfile.TemporaryDirectory() as scratch:
            code = "import importlib.util, sys; spec = importlib.util.spec_from_file_location('probe', sys.argv[1]); m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m); print(m.ModelHiveAgent().perform(action='status'))"
            done = subprocess.run([sys.executable, "-B", "-c", code, str(AGENT_FILE)], env={**UTF8, "RAPP_MODEL_HIVE": scratch}, capture_output=True, text=True, encoding="utf-8", timeout=120)
        answer = json.loads(done.stdout)
        self.assertEqual(answer["error"]["code"], "REPO_NOT_FOUND")
        self.assertIn("RAPP_MODEL_HIVE", answer["error"]["next"])


class AnchorRequestTests(unittest.TestCase):
    """ANCHOR-REQUEST.md asks the estate owner for exactly the model's published keys. It is never a RAPP/1 trust anchor, a rapp/1-registry or a registry entry with authority, and it cites the real estate by public pointer only."""

    def test_the_request_names_exactly_the_published_keys(self) -> None:
        request = json.loads((ROOT / "anchor-request.json").read_text(encoding="utf-8"))
        text = (ROOT / "ANCHOR-REQUEST.md").read_text(encoding="utf-8")
        self.assertNotEqual(request["schema"], "rapp/1-registry")
        self.assertNotIn("sig", request)
        records = sorted((json.loads(path.read_bytes()) for path in (ROOT / "model" / "hive" / "identities").glob("*.json")), key=lambda record: record["rappid"])
        entries = [{"type": "spki", "rappid": record["rappid"], "spki_der_b64": record["spki_der_b64"], "deprecated": False} for record in records]
        self.assertEqual(request["requested"]["entries"], entries)
        keys = {entry["rappid"]: entry["spki_der_b64"] for entry in entries}
        frames = [rapp1.parse(path.read_bytes()) for path in sorted((ROOT / "model" / "hive" / "streams").rglob("*.json"))]
        signed: dict[str, int] = {}
        for frame in frames:
            kid = rapp1.jws_kid(frame)
            rapp1.verify_signature(frame, keys[kid], kid)
            signed[kid] = signed.get(kid, 0) + 1
        self.assertEqual(signed, request["self_consistency"]["frames_verified_per_kid"])
        self.assertEqual(sum(signed.values()), request["subject"]["frames"])
        for entry in entries:
            self.assertIn(entry["rappid"], text)
            self.assertIn(entry["spki_der_b64"], text)
        optional = request["not_needed_for_rapp_check"]
        kinds = sorted({(frame["kind"], rapp1.stream_family(frame["stream_id"])) for frame in frames if frame["kind"] != "memory.save"})
        self.assertEqual(optional["kind"]["entries"], [{"type": "kind", "kind": kind, "family": family, "deprecated": False} for kind, family in kinds])
        genesis = sorted(({"type": "genesis", "stream_id": frame["stream_id"], "frame_hash": frame["frame_hash"], "deprecated": False} for frame in frames if frame["seq"] == 0), key=lambda entry: entry["stream_id"])
        self.assertEqual(optional["genesis"]["entries"], genesis)

    def test_the_estate_is_cited_by_public_pointer_only(self) -> None:
        request = json.loads((ROOT / "anchor-request.json").read_text(encoding="utf-8"))
        text = (ROOT / "ANCHOR-REQUEST.md").read_text(encoding="utf-8")
        anchor = request["trust_anchor"]
        published = anchor["published_in"]
        self.assertEqual((published["repository"], published["path"], published["section"]), ("https://github.com/kody-w/rapp-1", "README.md", "Trust anchor (out-of-band publication, §13.1)"))
        self.assertEqual(RAPPID.findall(json.dumps(anchor, ensure_ascii=False)), [], "the trust anchor is a pointer, never a value")
        self.assertEqual(anchor["same_value_at"]["json_pointer"], request["registry_of_record"]["estate_owner_json_pointer"])
        self.assertIn(published["section"], text)
        self.assertIn(published["url"], text)
        tooling = request["ceremony"]["tooling"]
        for pointer in (published, anchor["same_value_at"], tooling, *request["flags_for_estate_lead"]["flags"]):
            self.assertRegex(pointer["commit"], r"^[0-9a-f]{40}$")
            self.assertIn(pointer["commit"][:7], text, pointer["repository"])
        for tool in (tooling["sign_and_verify"], tooling["gate"]):
            self.assertIn(tool["path"], text)
        model_rappids = {rappid for path in (ROOT / "model").rglob("*.json") for rappid in RAPPID.findall(path.read_text(encoding="utf-8"))}
        for name, body in (("anchor-request.json", json.dumps(request, ensure_ascii=False)), ("ANCHOR-REQUEST.md", text)):
            named = set(RAPPID.findall(body))
            self.assertTrue(named, name)
            self.assertEqual(named - model_rappids, set(), f"{name} names a rappid that is not one of the model's own")

    def test_nothing_here_is_a_rapp1_trust_anchor_or_registry(self) -> None:
        """AGENTS.md: no RAPP/1 trust anchor, rapp/1-registry or §13 entry with authority. The Hive's own rapp-hive/2 anchor is part of the model and is not one."""

        def nodes(value: object):
            yield value
            for child in value.values() if isinstance(value, dict) else value if isinstance(value, list) else ():
                yield from nodes(child)

        authority = {"estate_owner", "tombstone", "re-anchor", "grail-kernel"}
        for path in sorted(ROOT.rglob("*.json")):
            relative = path.relative_to(ROOT)
            if {".git", "node_modules"}.intersection(relative.parts):
                continue
            try:
                value = json.loads(path.read_bytes())
            except ValueError:
                continue
            if isinstance(value, dict):
                self.assertNotEqual(value.get("schema"), "rapp/1-registry", relative.as_posix())
            for node in nodes(value):
                if isinstance(node, dict):
                    self.assertNotIn(node.get("type"), authority, relative.as_posix())
        request = json.loads((ROOT / "anchor-request.json").read_text(encoding="utf-8"))
        self.assertEqual([node for node in nodes(request) if isinstance(node, dict) and "sig" in node], [], "the request is never signed")
        self.assertTrue(json.loads((ROOT / "model" / "hive" / "HIVE.json").read_bytes())["schema"].startswith("rapp-hive/2"))


class PublicSafetyTests(unittest.TestCase):
    """A generic scan for things that must never be published. Patterns are assembled so this file cannot match itself."""

    PATTERNS = {
        "email address": re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}"),
        "macOS home path": re.compile("/" + "Users/" + r"[^/\s\"']+"),
        "Linux home path": re.compile("/" + "home/" + r"[a-z_][a-z0-9_-]*/"),
        "Windows home path": re.compile(r"[A-Za-z]:\\\\?" + "Users" + r"\\\\?"),
        "temporary folder path": re.compile("/var/" + "folders/"),
        "private key block": re.compile("-----BEGIN [A-Z ]*" + "PRIVATE KEY-----"),
        "GitHub token": re.compile("gh" + r"[pousr]_[A-Za-z0-9]{30,}|github_" + "pat_"),
        "cloud access key": re.compile("AK" + r"IA[0-9A-Z]{16}"),
    }
    KEY_SUFFIXES = (".pem", ".key", ".p12", ".pfx", ".jks", ".kdbx")

    def files(self) -> list[Path]:
        skip = {".git", "__pycache__", "node_modules"}
        return [path for path in ROOT.rglob("*") if path.is_file() and not skip.intersection(path.relative_to(ROOT).parts)]

    def test_nothing_personal_or_secret_is_published(self) -> None:
        findings = []
        for path in self.files():
            relative = path.relative_to(ROOT).as_posix()
            if path.suffix.lower() in self.KEY_SUFFIXES:
                findings.append(f"{relative}: key file")
            text = path.read_bytes().decode("utf-8", errors="replace")
            for label, pattern in self.PATTERNS.items():
                for match in pattern.finditer(text):
                    findings.append(f"{relative}: {label}: {match.group(0)[:40]!r}")
        self.assertEqual(findings, [])

    def test_every_rappid_is_fictional(self) -> None:
        """A keyed rappid is a key fingerprint (RAPP/1 §13.1), so a real one is real data. Every rappid here is a fictional @contoso one."""
        findings = sorted({f"{path.relative_to(ROOT).as_posix()}: {match.group(0).split('/')[0]}" for path in self.files() for match in RAPPID.finditer(path.read_bytes().decode("utf-8", errors="replace")) if not match.group(0).startswith("@contoso/")})
        self.assertEqual(findings, [])

    def test_the_model_is_labelled_synthetic_everywhere_people_look(self) -> None:
        for relative in ("README.md", "AGENTS.md", "tour/CONTEXT.md", "tour/01-front-door.md", "model/STORY.json"):
            text = (ROOT / relative).read_text(encoding="utf-8")
            self.assertRegex(text, r"(?i)synthetic|SYNTHETIC", relative)
            self.assertIn("test key", text.lower(), relative)


@unittest.skipUnless(PAGE.is_file(), "app/model-hive.html has not been built")
class PageTests(unittest.TestCase):
    FORBIDDEN = (".inner" + "HTML", ".outer" + "HTML", "insertAdjacent" + "HTML", "ev" + "al(", "new " + "Function(", "document." + "write(", "http" + "://", "https" + "://", "@im" + "port")

    def test_the_page_is_one_csp_locked_file(self) -> None:
        html = PAGE.read_text(encoding="utf-8")
        policy = re.search(r'<meta http-equiv="Content-Security-Policy" content="([^"]+)"', html)
        self.assertIsNotNone(policy, "the page must declare its Content-Security-Policy")
        directives = {part.split()[0]: part.split()[1:] for part in policy.group(1).split(";") if part.strip()}
        for name in ("default-src", "connect-src", "base-uri", "form-action"):
            self.assertEqual(directives.get(name), ["'none'"], name)
        self.assertNotIn("'unsafe-inline'", policy.group(1))
        self.assertNotIn("'unsafe-eval'", policy.group(1))
        digest = lambda text: "'sha256-" + base64.b64encode(hashlib.sha256(text.encode("utf-8")).digest()).decode("ascii") + "'"  # noqa: E731
        scripts = [(attributes or "", body) for attributes, body in re.findall(r"<script(\s[^>]*)?>(.*?)</script>", html, re.S)]
        code = [body for attributes, body in scripts if not re.search(r'type="(?!module|text/javascript)[^"]+"', attributes)]
        self.assertTrue(code, "the page must carry its engine inline")
        self.assertEqual(sorted(directives["script-src"]), sorted(digest(body) for body in code))
        styles = re.findall(r"<style>(.*?)</style>", html, re.S)
        self.assertEqual(sorted(directives["style-src"]), sorted(digest(body) for body in styles))
        self.assertNotRegex(html, r"<script[^>]+src=|<link[^>]+href=|<iframe|<object|<embed")
        unfetched = re.sub(r"http://www\.w3\.org/(?:2000/svg|1999/xhtml|1999/xlink)", "", html)  # XML namespaces are names, never fetched
        for pattern in self.FORBIDDEN:
            self.assertNotIn(pattern, unfetched, pattern)

    def test_the_page_is_exactly_what_its_sources_build(self) -> None:
        done = run(sys.executable, "-B", "tools/build_app.py", "--check")
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_the_browser_engine_matches_every_vector(self) -> None:
        done = run("node", "tests/parity.mjs", timeout=600)
        self.assertEqual(done.returncode, 0, done.stdout[-4000:] + done.stderr[-4000:])
        self.assertEqual(json.loads(done.stdout)["failed"], [])

    @unittest.skipUnless(chrome(), "Chrome is not installed")
    def test_the_page_verifies_in_headless_chrome(self) -> None:
        dom, log = render_in_chrome(PAGE)
        self.assertIn("Verified in this browser", dom, log[-3000:])
        for heading in ("Front door", "Residents", "Renovation", "Schemas and lenses", "Crossings", "Agreement", "Timeline"):
            self.assertIn(heading, dom)
        for problem in ("Content Security Policy", "Uncaught", "SyntaxError", "TypeError"):
            self.assertNotIn(problem, log, problem)


def render_in_chrome(page: Path, deadline: float = 90.0) -> tuple[str, str]:
    """Headless Chrome prints the rendered DOM and may then linger; read until </html> and stop its whole process tree."""
    import threading
    import time

    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as profile:
        command = [chrome(), "--headless=new", "--disable-gpu", "--no-first-run", "--no-default-browser-check", f"--user-data-dir={profile}", "--enable-logging=stderr", "--v=0", "--virtual-time-budget=15000", "--dump-dom", page.as_uri()]
        if sys.platform.startswith("linux"):
            command.insert(1, "--no-sandbox")
        extra = {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP} if os.name == "nt" else {"start_new_session": True}
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, **extra)
        out: list[bytes] = []
        err: list[bytes] = []
        done = threading.Event()

        def pump(stream: object, sink: list[bytes], watch: bool) -> None:
            for chunk in iter(lambda: stream.read1(65536), b""):
                sink.append(chunk)
                if watch and b"</html>" in b"".join(sink[-2:]):
                    done.set()
            if watch:
                done.set()

        readers = [threading.Thread(target=pump, args=(process.stdout, out, True), daemon=True), threading.Thread(target=pump, args=(process.stderr, err, False), daemon=True)]
        for reader in readers:
            reader.start()
        done.wait(deadline)
        time.sleep(0.5)
        if process.poll() is None:
            if os.name == "nt":
                subprocess.run(["taskkill", "/T", "/F", "/PID", str(process.pid)], capture_output=True, timeout=30)
            else:
                import signal

                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
        try:
            process.wait(timeout=30)
        except subprocess.TimeoutExpired:
            process.kill()
        for reader in readers:
            reader.join(timeout=5)
        process.stdout.close()
        process.stderr.close()
    dom = re.sub(r"<script\b.*?</script>", "", b"".join(out).decode("utf-8", errors="replace"), flags=re.S)
    return dom, b"".join(err).decode("utf-8", errors="replace")

if __name__ == "__main__":
    unittest.main()

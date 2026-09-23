"""Re-vendor the rapp-hive/2 reference from a rapp-workspace checkout, pinned to one exact commit.

    python3 -B tools/vendor.py <rapp-workspace checkout> <commit> [--branch NAME]

Reads committed bytes only (``git show <commit>:<path>``, never the working tree), then rewrites
vendor/rapp_hive2/, conformance/vectors.json, vendor/PROVENANCE.json, and the agent's engine pins
and trusted anchor. Afterwards delete model/ and tour/, run tools/build.py, and run the tests.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SOURCE = "protocols/rapp-hive/2/reference/rapp_hive2"
VECTORS = "protocols/rapp-hive/2/conformance/vectors.json"
AGENT = ROOT / "agents" / "model_hive_agent.py"


def git(checkout: Path, *args: str) -> bytes:
    return subprocess.run(["git", "-C", str(checkout), *args], check=True, capture_output=True).stdout


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("checkout")
    parser.add_argument("commit")
    parser.add_argument("--branch", default="experimental/frontier-rapp-hive-2")
    args = parser.parse_args()
    checkout = Path(args.checkout)
    commit = git(checkout, "rev-parse", "--verify", f"{args.commit}^{{commit}}").decode().strip()
    names = sorted(name for name in git(checkout, "ls-tree", "--name-only", commit, f"{SOURCE}/").decode().splitlines() if name.endswith(".py"))
    files = {name.rsplit("/", 1)[1]: git(checkout, "show", f"{commit}:{name}") for name in names}
    vectors = git(checkout, "show", f"{commit}:{VECTORS}")
    target = ROOT / "vendor" / "rapp_hive2"
    shutil.rmtree(target, ignore_errors=True)
    target.mkdir(parents=True)
    for name, data in files.items():
        (target / name).write_bytes(data)
    (ROOT / "conformance" / "vectors.json").write_bytes(vectors)
    pins = {name: hashlib.sha256(data).hexdigest() for name, data in sorted(files.items())}
    provenance = {
        "schema": "rapp-model-hive-vendor/1",
        "repository": "https://github.com/kody-w/rapp-workspace",
        "branch": args.branch,
        "commit": commit,
        "source": SOURCE,
        "files_sha256": {f"rapp_hive2/{name}": digest for name, digest in pins.items()},
        "conformance": {"path": VECTORS, "sha256": hashlib.sha256(vectors).hexdigest()},
        "track": "experimental-frontier",
        "ring": "canary",
    }
    (ROOT / "vendor" / "PROVENANCE.json").write_bytes((json.dumps(provenance, indent=2) + "\n").encode("utf-8"))
    anchor = subprocess.run(
        [sys.executable, "-B", "-c", "import sys; sys.path.insert(0, 'vendor'); from rapp_hive2 import model; print(model.build()['anchor'])"],
        cwd=ROOT, check=True, capture_output=True, text=True,
    ).stdout.strip()
    block = "ENGINE_SHA256 = {\n" + "".join(f'    "{name}": "{digest}",\n' for name, digest in pins.items()) + "}\n"
    text = AGENT.read_text(encoding="utf-8")
    text, count = re.subn(r"(# ENGINE-PINS-BEGIN[^\n]*\n)ENGINE_SHA256 = \{\n.*?\}\n(# ENGINE-PINS-END)", lambda m: m.group(1) + block + m.group(2), text, flags=re.S)
    text, anchors = re.subn(r'^TRUSTED_ANCHOR = "[0-9a-f]{64}"$', f'TRUSTED_ANCHOR = "{anchor}"', text, flags=re.M)
    if count != 1 or anchors != 1:
        print(json.dumps({"ok": False, "refusal": "the agent's pin block or anchor line was not found"}))
        return 1
    AGENT.write_bytes(text.encode("utf-8"))
    print(json.dumps({"ok": True, "commit": commit, "files": len(pins), "anchor": anchor, "next": "delete model/ and tour/, run tools/build.py and tools/build_app.py, then the tests"}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

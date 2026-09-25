"""Build the deterministic offline tour: python3 -B tools/build_app.py.

Use --check to compare the built page with its sources without writing anything.
Only app/model-hive.html is written. The browser verifies the original carried
bytes; STORY.json and lessons supply narration, never verification authority.
The before copy is the house before migration, rebuilt byte for byte from
model/before and the frames it names in model/hive (tools/before.py).
No dependencies are downloaded and no timestamps or local paths are embedded.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import html
import json
import re
import sys
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "vendor"))
sys.path.insert(0, str(ROOT / "tools"))

from rapp_hive2 import hive, rapp1, store  # noqa: E402

import before  # noqa: E402

MAX_BUNDLE_BYTES = 8 * 1024 * 1024
THEME = """(() => {
  const param = new URLSearchParams(window.location.search).get("scoutTheme");
  const theme =
    param || (window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
  document.documentElement.setAttribute("data-theme", theme);
})();"""


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def digest(text: str) -> str:
    return "sha256-" + b64(hashlib.sha256(text.encode("utf-8")).digest())


def bundle_files(files: dict[str, bytes]) -> str:
    return b64(rapp1.canonical({path: b64(data) for path, data in files.items()}, limit=MAX_BUNDLE_BYTES))


def bundle(folder: Path) -> str:
    return bundle_files({path: store.read_inside(folder, path, limit=hive.MAX_OBJECT_BYTES) for path in hive._files(folder)})


def data(value: object) -> str:
    return b64(rapp1.canonical(value))


def source(name: str) -> str:
    return (ROOT / "app" / "src" / name).read_text(encoding="utf-8")


def build() -> bytes:
    pointer = rapp1.parse((ROOT / "model" / "hive" / "HIVE.json").read_bytes())
    if set(pointer) != {"schema", "anchor"} or pointer["schema"] != "rapp-hive/2-carrier":
        raise ValueError("The model HIVE.json is not a carrier pointer.")
    trust = {"anchor": pointer["anchor"]}
    blocks = [
        ("model-carrier", bundle(ROOT / "model" / "hive")),
        ("before-carrier", bundle_files(before.house(ROOT))),
        ("tour-story", data(json.loads((ROOT / "model" / "STORY.json").read_text(encoding="utf-8")))),
        ("tour-lessons", data(json.loads(source("lessons.json")))),
        ("model-trust", data(trust)),
    ]
    scripts = [source(name) for name in ("rapp1-primitives.js", "rapp_hive2.js", "app.js")]
    style = source("app.css")
    for text in [THEME, *scripts, style]:
        if re.search(r"</(?:script|style)(?=[\s/>])", text, re.IGNORECASE):
            raise ValueError("An inline source contains an HTML closing tag.")
    hashes = [digest(text) for text in [THEME, *scripts]]
    policy = "; ".join([
        "default-src 'none'",
        "script-src " + " ".join("'" + value + "'" for value in hashes),
        "style-src '" + digest(style) + "'",
        "img-src data:",
        "connect-src 'none'",
        "base-uri 'none'",
        "form-action 'none'",
        "object-src 'none'",
    ])
    parts = [
        "<!doctype html>",
        '<html lang="en">',
        "<head>",
        '<meta charset="utf-8">',
        '<meta http-equiv="Content-Security-Policy" content="' + html.escape(policy, quote=False) + '">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        '<meta name="referrer" content="no-referrer">',
        "<title>Contoso Model Hive - an offline open house</title>",
        "<script>" + THEME + "</script>",
        "<style>" + style + "</style>",
        "</head>",
        "<body>",
        "<noscript>This synthetic model tour needs JavaScript to verify its signed data. Nothing has been verified while JavaScript is disabled.</noscript>",
        *('<script id="' + name + '" type="application/octet-stream">' + value + "</script>" for name, value in blocks),
        *("<script>" + text + "</script>" for text in scripts),
        "</body>",
        "</html>",
        "",
    ]
    page = "\n".join(parts)
    forbidden = [".innerHTML", ".outerHTML", "insertAdjacentHTML", "eval(", "new Function(", "document.write("]
    if any(pattern in page for pattern in forbidden):
        raise ValueError("The generated page contains a forbidden DOM or code-execution pattern.")
    if re.search(r"https?://|(?:src|href)\s*=\s*[\"']\s*//", page, re.IGNORECASE):
        raise ValueError("The page must not contain external URLs.")
    return page.encode("utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="check the generated page without changing it")
    args = parser.parse_args()
    output = build()
    destination = ROOT / "app" / "model-hive.html"
    if args.check:
        ok = destination.is_file() and destination.read_bytes() == output
    else:
        destination.write_bytes(output)
        ok = True
    print(json.dumps({
        "ok": ok,
        "file": "app/model-hive.html",
        "bytes": len(output),
        "sha256": hashlib.sha256(output).hexdigest(),
    }))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())

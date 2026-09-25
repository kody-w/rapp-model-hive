# AGENTS.md

This is the **Contoso Model Hive**: a SYNTHETIC, public "model home" for the experimental
frontier draft `rapp-hive/2` (canary ring). Fictional people and devices, public test keys.

## Hard rules

- Never add real data: no real names, emails, account names, home paths, hostnames,
  private repositories, fingerprints, keys or conversation logs. Everything stays fictional.
- Never sign anything real with the model's keys, and never present them as secure.
  Anyone can re-derive them from their published labels.
- `model/`, `tour/` and `app/model-hive.html` are generated. Do not edit them by hand.
- `vendor/` is an exact copy of the reference at the commit in `vendor/PROVENANCE.json`.
  Change it only with `tools/vendor.py`, never by hand.
- The model is display material, not authority. `model/STORY.json` is derived labels only.
- Never create, sign or simulate a RAPP/1 trust anchor (§13.1), a `rapp/1-registry`, or a §13
  registry entry with authority. The Hive's own `rapp-hive/2` anchor, built from the public
  test keys, is part of the model and is not one. `ANCHOR-REQUEST.md` asks the estate owner
  and cites the estate's anchor and registry by public pointer only; only the owner decides.

## Guiding someone through it

Read `tour/CONTEXT.md`, then go room by room (`tour/01-front-door.md` through
`tour/07-timeline.md`). Use plain words and short sentences. Check claims against the
engine instead of guessing:

```sh
cd vendor
python3 -B -m rapp_hive2 status ../model/hive
python3 -B -m rapp_hive2 cross ../model/hive <12 hex of a message> <member slug>
```

`model/before/` is the house before the move. Each frame is stored once, in `model/hive/`:
`python3 -B tools/before.py <new folder>` rebuilds the old house and checks every frame
(`tour/03-renovation.md` shows the whole replay).

A RAPP Brainstem can hotload `agents/model_hive_agent.py` (actions: `tour`, `status`,
`verify`, `cross`, `migrate_demo`, `conformance`). It runs only the engine bytes it pins.

## Changing the repository

1. New reference: `python3 -B tools/vendor.py <rapp-workspace checkout> <commit>`.
2. Rebuild: delete `model/` and `tour/`, then run `python3 -B tools/build.py` and
   `python3 -B tools/build_app.py`.
3. Page sources are `app/src/`. The page must stay one CSP-locked file: no network,
   no `innerHTML`, no `eval`.
4. Verify everything before you finish:

```sh
python3 -B tools/build.py --check
python3 -B tools/build_app.py --check
node tests/parity.mjs
python3 -B -m unittest discover -s tests -v
```

Use a separate git worktree for your changes. Do not push without the owner's approval.

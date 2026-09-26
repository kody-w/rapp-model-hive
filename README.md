# Contoso Model Hive

<!-- rapp1:network-header:start -->
[![RAPP/1](https://kody-w.github.io/rapp-hive-public/portfolio/badges/rapp-model-hive.svg)](https://github.com/kody-w/rapp-hive-public/blob/main/portfolio/repos/rapp-model-hive.md) · **New to RAPP?** [Start here: get your Brainstem →](https://github.com/kody-w/rapp-installer#start-here)
<!-- rapp1:network-header:end -->

**A model Hive, like a model home: everything is furnished so you can walk through it, but nobody lives here.**

> [!WARNING]
> **Everything here is synthetic.** Contoso is a fictional company. Its people and devices are invented, and every signature uses a **public test key** that anyone can re-derive from a published label (see `test_key` in [`vendor/rapp_hive2/sign.py`](vendor/rapp_hive2/sign.py)). Those keys prove nothing about anyone. Never use them, or this Hive, for real data.

This repository shows the **experimental frontier draft `rapp-hive/2`** (canary ring) working end to end, starting from a Hive on the current version (`rapp-hive/1`) and moving it forward without rewriting a single old frame.

| Read the protocol | |
|---|---|
| [`rapp-hive/2` specification](https://github.com/kody-w/rapp-workspace/blob/experimental/frontier-rapp-hive-2/protocols/rapp-hive/2/SPEC.md) | co-equal Hives of sovereign streams |
| [Migration paths](https://github.com/kody-w/rapp-workspace/blob/experimental/frontier-rapp-hive-2/protocols/rapp-hive/2/MIGRATION.md) | from `rapp-hive/1` or a repository-seeded Hive |
| [`rapp-schema/1` specification](https://github.com/kody-w/rapp-workspace/blob/experimental/frontier-rapp-hive-2/protocols/rapp-schema/1/SPEC.md) | the bare shape of a frame, the thing lenses map |
| [RAPP/1](https://github.com/kody-w/rapp-1) | the signed frames everything is made of |

Nothing here is authority: it is a draft on an experimental branch and may change.

## Walk through it

Pick whichever door suits you:

- **In a browser.** Download [`app/model-hive.html`](app/model-hive.html) and open it. It is one self-contained file that works offline, verifies every signature in your browser, and lets you try crossings, tamper with a copy and watch it be refused.
- **As a tour you can read.** Start with [`tour/CONTEXT.md`](tour/CONTEXT.md). There are seven rooms:

  | Room | What you will see |
  |---|---|
  | [1. Front door](tour/01-front-door.md) | what a model Hive is and how to check it yourself |
  | [2. Residents](tour/02-residents.md) | who is in, how they got in, who is waiting |
  | [3. Renovation](tour/03-renovation.md) | the move from `rapp-hive/1` to `rapp-hive/2` |
  | [4. Schemas and lenses](tour/04-schemas-and-lenses.md) | how different app shapes meet in one view |
  | [5. Crossings](tour/05-crossings.md) | one person's message, as another person's app would read it |
  | [6. Agreement](tour/06-agreement.md) | how devices agree without a master copy |
  | [7. Timeline](tour/07-timeline.md) | every signed step, in order |

- **With your AI.** Any assistant can read [`AGENTS.md`](AGENTS.md) and guide you. A RAPP Brainstem can hotload [`agents/model_hive_agent.py`](agents/model_hive_agent.py) and then answer "show me the residents" or "how would Blake's task look on Avery's laptop?".

## What happens in the model

1. **The current version.** Avery owns a `rapp-hive/1` Hive with Blake and Casey, declared as the first frame of its Mother Hive stream and signed by Avery, exactly as `rapp-hive/1` requires. Avery's laptop app and Blake's phone app write tasks in different shapes, and an old onboarding script records Emery's request to join.
2. **The renovation.** Avery accepts a `rapp-hive/2` anchor whose first policy lets only Avery decide, exactly like `rapp-hive/1`. Blake and Casey each sign their own join, and Avery grants them. Emery's old request is carried as a pending request under that first policy.
3. **Co-equal peers.** Policy v2 makes every member a decider: two grants plus a key someone has confirmed. Emery's old request is still decided under v1, so Blake's approval does not count and Avery's alone is enough. Drew gets in with two grants and a confirmed key. Frankie is still waiting, and Frankie's task sits in quarantine until then; quarantined messages never teach the Hive anything.
4. **Schemas and lenses.** A shape that only gains a field is learned automatically. A renamed field needs a lens that people adopt. A careless lens that would change what old tasks mean is refused even though two people signed it. A brand-new "reaction" shape waits for a lens while everything else keeps working.
5. **Crossings.** Blake's task cannot cross to Avery's laptop, because it has no due date and the Hive will not invent one. Avery's task crosses to Blake's phone, and the due date is named as what stays behind.
6. **Agreement.** Three devices sign matching manifests. Blake's phone signed while offline, so it is consistent but behind. There is no master copy to trust.

The Hive's identity (its anchor) is:

```
03972c7e8049b59134681ef9b1d7af369e4b06273d262691c5b28d6c48dcdce8
```

## Check it yourself

You need Python 3.11 or later with `cryptography`, and Node 20 or later for the browser-engine parity check.

```sh
python3 -m pip install "cryptography>=43"

cd vendor
python3 -B -m rapp_hive2 status ../model/hive          # plain language
python3 -B -m rapp_hive2 verify ../model/hive --anchor 03972c7e8049b59134681ef9b1d7af369e4b06273d262691c5b28d6c48dcdce8
python3 -B -m rapp_hive2 cross ../model/hive 29a20deff3bb avery-laptop    # refused: no invented due date
python3 -B -m rapp_hive2 vectors --check ../conformance/vectors.json
cd ..

python3 -B tools/build.py --check        # model/ and tour/ are exactly what the reference builds
python3 -B tools/build_app.py --check    # the page is exactly what its sources build
node tests/parity.mjs                    # the browser engine matches every conformance vector
python3 -B -m unittest discover -s tests -v
```

## What is inside

| Path | What it is |
|---|---|
| `model/hive/` | the migrated Hive: `HIVE.json`, identity records, content-addressed objects and one signed stream per device |
| `model/before/` | the same Hive before migration, on `rapp-hive/1` |
| `model/STORY.json` | labels and narration for the tour and the page (derived, never authority) |
| `tour/` | the rooms, generated from the signed frames |
| `app/model-hive.html` | the single-file browser tour, built from `app/src/` by `tools/build_app.py` |
| `agents/model_hive_agent.py` | a hotloadable RAPP Brainstem agent |
| `vendor/rapp_hive2/` | the reference implementation, copied from an exact commit (see `vendor/PROVENANCE.json`) |
| `conformance/vectors.json` | the protocol's conformance vectors, pinned with the reference |

Everything in `model/`, `tour/` and `app/model-hive.html` is generated. Do not edit it by hand: change the reference or the builders, then rebuild. To follow a newer reference, run `python3 -B tools/vendor.py <rapp-workspace checkout> <commit>`, delete `model/` and `tour/`, and rebuild.

## License

[MIT](LICENSE).

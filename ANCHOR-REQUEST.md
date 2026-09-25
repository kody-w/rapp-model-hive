# Anchor request: the model's signed frames under RAPP/1 §10

> [!IMPORTANT]
> **Status: requested, owner decision pending.** This file asks the estate owner for six registry entries. It is not a RAPP/1 trust anchor (§13.1), a `rapp/1-registry`, a §13 registry entry with authority, or a signature, and nothing in this repository may be turned into one. Only the estate owner can create these entries, by signing the next revision of the estate's registry of record. The machine-readable copy is [`anchor-request.json`](anchor-request.json). When the owner decides, a follow-up commit records the decision here (see [When the owner decides](#when-the-owner-decides)).

Everything in this repository is synthetic: fictional people and devices, signed with public test keys that anyone can re-derive (see [the risk](#the-risk-the-owner-must-weigh)). Real estate facts are cited by public pointer only (repository, commit, file, and heading or JSON pointer). No real rappid is copied here: under RAPP/1 §13.1 a keyed rappid is a self-certifying key fingerprint, and [`AGENTS.md`](AGENTS.md) keeps this repository fictional.

## Why this is needed

rapp-1's own checker, [`rapp_check.py`](https://github.com/kody-w/rapp-1/blob/591e014ad39e223b00ab343ae26e5d9a867ebeee/rapp_check.py) at `591e014`, finds 38 signed frames in `model/hive/streams/`. Every one passes RAPP/1 §7 steps 1–5 (envelope, hashes, chain), and every one is reported as `§10 signature verification unavailable` with status `unverified`. rapp-1's [README](https://github.com/kody-w/rapp-1/blob/591e014ad39e223b00ab343ae26e5d9a867ebeee/README.md) says why: a signed chain without a caller-supplied trusted signature verifier is reported as `DRIFT` with status `unverified`, "never as signed conformance or `CLEAN`".

A trusted verifier needs trusted keys. Under RAPP/1 §10 a verifier resolves each signer's key **from the §13 registry**, and refuses when the registry has none. The six signers here are synthetic `@contoso` device identities that no registry lists, so their frames cannot be verified under §10 today.

The checker's other finding here, four `§7.6 duplicate position`s, is fixed in this repository: `model/before/` no longer stores copies of frames (see `tools/before.py`).

## What is needed: six `spki` entries

One RAPP/1 §13.3 `spki` entry per signer, with exactly the members `rapp_registry.ENTRY_MEMBERS["spki"]` requires: `type`, `rappid`, `spki_der_b64` and `deprecated`. Each value is copied from the model's published identity records, `model/hive/identities/*.json`:

```json
[
 {
  "type": "spki",
  "rappid": "rappid:@contoso/avery-laptop:121f71337e335720c65dc4f7b459c92aea6197460224401810721765fabea47b",
  "spki_der_b64": "MCowBQYDK2VwAyEAhaA219hYB+q+4v+PpPkHj2Xo1HU7WPI8BU1f9ejPziA=",
  "deprecated": false
 },
 {
  "type": "spki",
  "rappid": "rappid:@contoso/blake-phone:dde384494581cfa734485cabf33c0177b40cdc7e88cb4877bc2b67e65fdf4ba0",
  "spki_der_b64": "MCowBQYDK2VwAyEAJTmOAiGcQTtMslUJrH8OfAUCWCPYucr3RT2gyIV3Jx8=",
  "deprecated": false
 },
 {
  "type": "spki",
  "rappid": "rappid:@contoso/casey-tablet:4c27b4d1826f9f50175f2aa907116746fab5a120641bdf3d357f148e60a2c92a",
  "spki_der_b64": "MCowBQYDK2VwAyEAVWPjEZIpntmvfjKba3Ym+lMbT/wTldOeBc3begBtqqY=",
  "deprecated": false
 },
 {
  "type": "spki",
  "rappid": "rappid:@contoso/drew-desktop:9b864ebcdf7b4a3c011fab6b643e595c8f9182f7c98c034b6778c0adcf6273a8",
  "spki_der_b64": "MCowBQYDK2VwAyEAQDCvx5T01lYvfx6/0FPvAleWpyaBIKviwskRM3dM4DQ=",
  "deprecated": false
 },
 {
  "type": "spki",
  "rappid": "rappid:@contoso/emery-kiosk:e3cb6fe1c6629325b3e61a1ae81736198dcb492d4fb6c6f0e1d424fc9e9a64ed",
  "spki_der_b64": "MCowBQYDK2VwAyEAGjUoWTBWlZ1/X0bTUeExfxibiotR7xLWP30CVxTzjLk=",
  "deprecated": false
 },
 {
  "type": "spki",
  "rappid": "rappid:@contoso/frankie-laptop:2a7d96c275540100a5312fa8f10490a5ad2b8cdaafe372704d87ced7d2c322bd",
  "spki_der_b64": "MCowBQYDK2VwAyEAfh3osFpLUAymoABCfvV088Ywfz9rk6bfrbZ+JAq+MZs=",
  "deprecated": false
 }
]
```

| Signer | Frames it signed |
|---|---|
| `@contoso/avery-laptop` | 15 |
| `@contoso/blake-phone` | 8 |
| `@contoso/casey-tablet` | 7 |
| `@contoso/drew-desktop` | 4 |
| `@contoso/emery-kiosk` | 2 |
| `@contoso/frankie-laptop` | 2 |
| **Total** | **38** |

### Checked against every frame (self-consistency, not trust)

With rapp-1's own code at `591e014`:

- each entry passes `rapp_registry.validate_entry`, which also checks that its SPKI hashes to its rappid's tail (§10 key discovery);
- all 38 frames' detached JWS signatures verify against their signer's entry with `rapp.verify_detached_jws`, and none fails;
- the check is not vacuous: no frame verifies with another signer's key, and no frame verifies after one of its fields is changed.

This proves only that the entries match the frames. It says nothing about who holds the keys: anyone can. `AnchorRequestTests` in `tests/test_model_hive.py` re-derives the entries from the identity records and re-verifies every frame on every CI run.

### Not needed for `rapp_check` (optional)

`rapp_check` never checks kind bindings or registered genesis, so neither is part of this request. Both are listed in `anchor-request.json` for completeness:

- **Seven `kind` entries.** RAPP/1 §7.2 binds each kind to a family through the registry (`rapp_registry.Registry.check_frame_binding`). `memory.save` is already registered. `hive.declaration` (body) and six `hive2.*` kinds (memory) are not. With the six `spki` entries alone, a consumer that also runs `check_frame_binding` accepts 10 of the 38 frames; with these kinds added, all 38. The `hive2.*` kinds belong to the experimental draft `rapp-hive/2`, and kinds are an estate-wide, append-only namespace, so registering them is an estate decision beyond this model.
- **17 `genesis` entries.** RAPP/1 §13.3 says every stream registers its creation genesis. There is one entry per stream in `model/hive/streams/`.

## Registry of record and trust anchor

Re-checked on 2026-09-25 from the public repositories. Both are cited by pointer; their values are not copied here.

- **Trust anchor.** The estate owner's rappid, published out of band in [kody-w/rapp-1 `README.md`, "Trust anchor (out-of-band publication, §13.1)"](https://github.com/kody-w/rapp-1/blob/591e014ad39e223b00ab343ae26e5d9a867ebeee/README.md#trust-anchor-out-of-band-publication-131) at `591e014`. Below, `<estate owner>` stands for that rappid.

- **Registry of record.** [kody-w/rapp-map `ecosystem-spec.json`](https://github.com/kody-w/rapp-map/blob/4c8ba6bbe73125cc980d0c3b38c59c99e4b231c0/ecosystem-spec.json), last changed in `4c8ba6b` (rapp-map `main` is `81dd6f0`; git blob `5593780`). It is a signed `rapp/1-registry`, its entries are in the member `entries`, and it is at `registry_seq` 2. Its `estate_owner` entry, at JSON pointer `/entries/0/rappid`, is the trust anchor above. `rapp_registry.load_document(doc, entries_member="entries", trust_anchor=<estate owner>)` at rapp-1 `591e014` reports `verified`. It has no `@contoso` entries.

## The owner's ceremony

Only the estate owner can do this. It adds six entries and changes nothing else.

kody-w/rapp-map carries its own tooling for this, cited at `81dd6f0`:

- [`tools/registry_sign.py`](https://github.com/kody-w/rapp-map/blob/81dd6f05ab0969d11253f3fe7f4834288824d17e/tools/registry_sign.py) (last changed in `95e2f72`), the estate's §13 registry ceremony tool. It needs `cryptography` and imports `rapp` and `rapp_registry` from the kody-w/rapp-1 checkout that `RAPP1_DIR` names (use `591e014`). Its `verify` is `rapp_registry.load_document(doc, entries_member="entries", trust_anchor=..., persisted_seq=...)`, and it refuses to run without an out-of-band trust anchor.
- [`.github/scripts/registry-verify.mjs`](https://github.com/kody-w/rapp-map/blob/81dd6f05ab0969d11253f3fe7f4834288824d17e/.github/scripts/registry-verify.mjs) (last changed in `cac49da`), whose `verifyRegistry` re-checks the published registry's signature with Node built-ins in rapp-map's own gates.

The steps, in a kody-w/rapp-map checkout:

1. Fetch the registry from its `canonical_source`, `https://raw.githubusercontent.com/kody-w/rapp-map/main/ecosystem-spec.json`, and check it against the trust anchor: `python3 tools/registry_sign.py verify --in ecosystem-spec.json --persisted-seq 2 --trust-anchor <estate owner>` must print `verified: ok`.
2. Make the next revision: the same document without `sig`, with `registry_seq` + 1 (3 while it is 2) and the six entries appended to `entries`. The registry is append-only: every existing entry stays, unchanged and in order. Envelope members such as `published_utc` are the owner's to set.
3. The estate owner signs it: `python3 tools/registry_sign.py sign --key <estate owner key file> --in <next revision> --out ecosystem-spec.json`. The tool refuses a key path inside the repository and a key file that group or others can access ("key file must be mode 0600"), and refuses a key whose SPKI does not hash to the `estate_owner` rappid's tail. It signs `canonical(document without sig)` with a §10 detached JWS (`EdDSA`, `kid` = the estate owner's rappid), sets it as `sig`, and writes nothing unless the signed document verifies.
4. Before publishing, check the new revision against the out-of-band anchor and the last verified sequence: `python3 tools/registry_sign.py verify --in ecosystem-spec.json --persisted-seq 2 --trust-anchor <estate owner>` must print `verified: ok`.
5. Publish it at `canonical_source` through kody-w/rapp-map's own process. For `registry_seq` 2 that was one commit, `4c8ba6b`, which changed `ecosystem-spec.json` and the public halves recorded in `RAPP1_OWNER_ACTIONS.json` together. rapp-map's gates require that: `bash .github/scripts/run-offline-gates.sh` (run by its `Drift lint` and `Standing guard` workflows) runs `.github/scripts/standing-guard.mjs local`, which refuses a ledger whose `owner_inputs` disagree with the registry's bytes (`registry_document_sha256`), `sig` or `registry_seq`, and re-verifies the signature with `verifyRegistry`. `verifyRegistry` takes the owner from the document's own `estate_owner` entry, so the check against the out-of-band anchor is step 4.

## How anyone verifies it afterwards

The command line cannot do it (see the next section), so call the API. From a folder that holds a checkout of kody-w/rapp-1 at `591e014` (in `rapp-1/`) and of this repository (in `rapp-model-hive/`), with `cryptography` installed:

```python
import json, re, sys, urllib.request
sys.path.insert(0, "rapp-1")
import rapp_check, rapp_registry

# The trust anchor is the one rappid published in rapp-1's README, section "Trust anchor (out-of-band publication, §13.1)".
readme = open("rapp-1/README.md", encoding="utf-8").read()
section = readme.split("## Trust anchor (out-of-band publication, §13.1)\n", 1)[1].split("\n## ", 1)[0]
(OWNER,) = set(re.findall(r"rappid:@[a-z0-9-]+/[a-z0-9-]+:[0-9a-f]{64}", section))
SOURCE = "https://raw.githubusercontent.com/kody-w/rapp-map/main/ecosystem-spec.json"
doc = json.load(urllib.request.urlopen(SOURCE))  # fetch it fresh: §13.1 calls an older copy stale, not clean
status, reg, why = rapp_registry.load_document(doc, entries_member="entries", trust_anchor=OWNER, persisted_seq=3)
assert status == "verified", why
verdict, findings, evidence = rapp_check.check_repo("rapp-model-hive", signature_verifier=reg.signature_verifier())
print(verdict, len(findings))
```

It reads the anchor where it is published, in rapp-1's README at `591e014`; compare it with your own trusted copy.

Expected after the ceremony: `COMPLIANT 0`, with all 38 frames verified. This was checked in advance with an unsigned draft of that revision. `load_document` reports such a draft only as `draft`, never as authority, and refuses it without `allow_unsigned`. The draft was not kept anywhere.

Before the ceremony this call cannot pass, by design. `persisted_seq=3` refuses today's `registry_seq` 2 as a rollback. With `persisted_seq=2`, the same `check_repo` call reports `DRIFT` with 17 × `§7 frame verification step 6` ("no spki entry for kid (registry absence is refusal)"), one for the first frame of each stream: with a trusted registry, a missing key is a refusal, not a pass.

## The checker's command-line gap

`python3 rapp_check.py <repo> --json` calls `check_repo(root)` with no signature verifier, and it has no option to load a registry or name a trust anchor. So the command line reports every signed frame as `unverified`, and its verdict for this repository stays `DRIFT` (38 × `§10 signature verification unavailable`, zero violations) even after the ceremony. Until rapp-1 closes that gap, the API call above is the verification path. The gap is in the checker, so this repository cannot close it.

## The risk the owner must weigh

These are **public test keys**. Anyone can re-derive each private key from its published label: in `test_key` (`vendor/rapp_hive2/sign.py`) the Ed25519 seed is the SHA-256 of `rapp-hive/2:public-test-key/1`, a newline and `contoso-model-hive/<slug>`. Registering the keys would let anyone sign new frames that the estate registry's verifier accepts for these six `@contoso` signers, at any `utc` a frame declares.

- A tombstone does not close this. Frames declare their own `utc`, so a forger can backdate past any cutoff. Also, at rapp-1 `591e014`, `load_document` refuses a registry that holds any tombstone unless the consumer supplies trusted issuance context (`tombstone_issued_at`), so a tombstone would affect every consumer of the estate registry.
- A `deprecated: true` entry verifies nothing.

## If the owner declines

Then the model's signed frames stay unverified under RAPP/1 §10 by design, and the residual finding (38 × `§10 signature verification unavailable`, status `unverified`, zero violations) should be recorded as accepted. Inside the Hive nothing changes: every frame still verifies under `rapp-hive/2` against the Hive's own identity records and anchor.

```sh
cd vendor
python3 -B -m rapp_hive2 verify ../model/hive --anchor 03972c7e8049b59134681ef9b1d7af369e4b06273d262691c5b28d6c48dcdce8
```

That anchor is the Hive's own identity under `rapp-hive/2`, built from the public test keys. It is part of the model, not a RAPP/1 trust anchor, and confers no §10 trust.

## When the owner decides

Either way, a follow-up commit to this repository records the decision. It updates the status line at the top of this file and `/status` in `anchor-request.json` (for example "declined on <date>; the residual finding is accepted" or "registered at `registry_seq` <n> on <date>"). If the entries are registered, the same commit also updates the sentence under *Why this is needed* that no registry lists the signers, and `/subject/finding` in `anchor-request.json`. Until then, the live facts in this file are as re-checked on 2026-09-25.

## Related gap: G8

[G8, "Hive members are names bound to keys, not RAPPIDs"](https://github.com/kody-w/rapp-hive-public/blob/8904771404d8b9e19fb2b841ac8eb0af9158d211/gaps/G08.md) (proposed; fix: Constitution Part V.4): inside a Hive, a member is a name bound to keys by the Hive's signed history, not a RAPPID in a registry. These six signers are exactly such members. The `spki` entries would be "a RAPPID linked where one is needed"; declining leaves them as G8 describes.

## For the estate lead: flags, not resolved here

This request uses the trust anchor in the kody-w/rapp-1 README and the registry of record in kody-w/rapp-map. It resolves neither flag.

1. **A second owner rappid.** [kody-w/rapp-work](https://github.com/kody-w/rapp-work/tree/29ead23b21645f8d7682ee00414930ffa9ce0ca6) at `29ead23` names a different owner rappid from the trust anchor, in `owner-anchor.json` (`/owner_rappid`) and `registry.json` (`/entries/0/rappid`); both last changed in `4b4fc21`.
2. **rapp-map's documents disagree about `ecosystem-spec.json`.** The kody-w/rapp-1 README at `591e014` names it the estate's registry of record, owner-signed and append-only, and rapp-map's own gates verify it as the owner-signed registry (see [the ceremony](#the-owners-ceremony)). At rapp-map `81dd6f0`:
   - [`README.md`](https://github.com/kody-w/rapp-map/blob/81dd6f05ab0969d11253f3fe7f4834288824d17e/README.md?plain=1#L12-L21) (last changed in `cac49da`) says "The authenticated registry evidence required by section 13 is absent", and that consumers "must refuse it as an authenticated registry". Its own "Local validation" section says the owner has published the signed section 13 registry.
   - [`ECOSYSTEM_SPEC.md`](https://github.com/kody-w/rapp-map/blob/81dd6f05ab0969d11253f3fe7f4834288824d17e/ECOSYSTEM_SPEC.md?plain=1#L9-L12) (last changed in `66dd344`) says it "is quarantined and must be refused as authenticated registry evidence" until the owner action in `RAPP1_OWNER_ACTIONS.md` "is completed and verified".
   - [`RAPP1_OWNER_ACTIONS.md`](https://github.com/kody-w/rapp-map/blob/81dd6f05ab0969d11253f3fe7f4834288824d17e/RAPP1_OWNER_ACTIONS.md?plain=1#L1-L23) (last changed in `66dd344`) says the ledger is "open and non-authoritative", the owner's publication location "unknown", and that the owner inputs "remain `null`" in `RAPP1_OWNER_ACTIONS.json`. That file (last changed in `4c8ba6b`) says `"status": "owner-published"`, with the blocker `closed` and the owner inputs recorded at `registry_seq` 2.
   - [`RAPP1_STATUS.md`](https://github.com/kody-w/rapp-map/blob/81dd6f05ab0969d11253f3fe7f4834288824d17e/RAPP1_STATUS.md?plain=1#L39-L46) (last changed in `cac49da`) says the owner action is closed, but still describes the registry as `registry_seq` 1 (lines 5 and 24). It has been at `registry_seq` 2 since `4c8ba6b`.

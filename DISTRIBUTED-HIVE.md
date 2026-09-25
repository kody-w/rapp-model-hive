# The distributed Hive

**Version 2, experimental** (branch `experimental/hive-md-distributed`). This file is the single source of truth for the
distributed Hive: what a station and a Hive root keep, how a reader finds and checks it, what a resolver writes, and what the
card generator writes. It extends [HIVE-MD.md](HIVE-MD.md). Every example uses the synthetic Contoso network, and the worked
example (section 20) hashes exactly as shown.

## 1. The idea

A Hive is folders and files, and so is a network of repositories. So the network is one Hive:

- Each **station**, a public repository on the network, keeps its member space in its own repository: its card
  `.rapp/member.md` and the files it shares under `.rapp/shared/`. Only its own commits change them.
- A **Hive root**, one Hive's public copy, keeps a **pointer** per station it curates, `members/<station>.md`. A pointer pins
  the station's long-term-support (LTS) commit and the hash of each file the network reads there. Only the curator's signed
  commits in the Hive change pointers.
- A reader finds everything from a seed, with plain static fetches of raw URLs (no server, no API, no search): seed, operator
  beacon, `estate.json` `hives[]`, the root's `PUBLISHED.md`, pointers, station files, and the links on each card.
- One command resolves that graph at the LTS commits into a local snapshot in which every file matched its pinned hash.

Hashes give integrity only. Until the estate that pins a Hive root is anchored by a signature, every result says
`authenticity: unverified`, and nothing is accepted.

## 2. Words

| Word | Meaning |
|---|---|
| station | a public repository on the network |
| Hive root | a Hive's clean public copy: `PUBLISHED.md` and the files it lists, and no `HIVE.md` |
| pointer | `members/<station>.md` in a Hive root: the curator's pin of one station |
| card | `.rapp/member.md` in a station: the station's own description of itself |
| raw base | an absolute URL ending in `/`, to which `<ref>/<path>` is appended: `https://raw.githubusercontent.com/contoso/protocol/` |
| ref | a full 40-hex commit (pinned), or `HEAD` or a branch name (moving) |
| channel | `rapp1-lts`, read at pinned LTS commits, or `newest`, read at `HEAD` |
| operator | a Hive root's owner: the first of the last two path parts of its raw base (`contoso`) |
| locator | a file that says where to look: a seed, a beacon, `estate.json`, a Hive root, a pointer, a card |

## 3. Names

- **Station name.** The repository's name when the Hive root's operator owns it (`protocol`), else `<owner>.<repo>`
  (`fabrikam.weather`). It matches `[A-Za-z0-9][A-Za-z0-9._-]*` and has 1 to 61 characters (HIVE-MD allows 64 per path part,
  and the pointer adds `.md`). It does not end in `.`, is not a Windows reserved name (`con`, `prn`, `aux`, `nul`, `com1` to
  `com9`, `lpt1` to `lpt9`, compared without case on the part before the first dot), and is not named like an AI instruction
  file (`agents`, `claude`, `claude.local`, `gemini`, `skill`, `copilot-instructions`, in any case), because a Hive refuses those
  file names anywhere. A repository with such a name can never be a station. Station names are unique in a Hive root, compared
  without case.
- **Repo.** `<owner>/<repo>`. The owner is a GitHub login, `[A-Za-z0-9](-?[A-Za-z0-9]){0,38}`; the repo name follows the name
  rule above, with at most 100 characters. Repos are compared without case and written as GitHub shows them.
- **Line id.** A subway line: `[a-z0-9](-?[a-z0-9]){0,63}`, such as `contoso-core`.

## 4. Layouts

### 4.1 A Hive root

A public copy holds exactly one room of its Hive, with the room's prefix stripped (HIVE-MD). So the network's folders are
folders of that room:

| In the Hive | In the public copy | What |
|---|---|---|
| `shared/<room>/members/<station>.md` | `members/<station>.md` | one pointer per curated station (section 7) |
| `shared/<room>/former/<station>.md` | `former/<station>.md` | the pointer of a station that left, moved there by a signed commit |
| `shared/<room>/<anything else>` | `<anything else>` | what the curator publishes: a portfolio, a subway map, notices, pulses |

Pointers never go in the Hive's own `members/`, which holds people: their device keys and their votes. The checker refuses a
pointer file there, and only a member's own signed commits may change `members/<name>/`.

### 4.2 A station

```text
README.md          its front door: the network reads it, but never freezes it
rappid.json        its RAPP/1 identity, once one is minted; no tool here writes or mints it
.rapp/member.md    its card (section 8)
.rapp/shared/...   files it shares with the network (optional)
```

`.rapp/` may also hold the RAPP Workspace's own files. The network never fetches, lists, writes or publishes `.rapp/cache/`,
`.rapp/workspace/`, `.rapp/reports/`, `.rapp/bootstrap.json`, `.rapp/bootstrap.py` or `.rapp/bootstrap-managed.json`.

A station joins by publishing its card with `hive:` and `hive_root:`: publishing is the signal. The curator pins it by adding
its pointer. A pointer is curation, not admission, and there is no request file.

## 5. The files the network reads

### 5.1 The readable set

A reader fetches only these station paths, and refuses anything else before any fetch:

- `README.md`, `rappid.json` and `.rapp/member.md`;
- `.rapp/shared/<p>`, where `<p>` has 1 to 4 parts. Each part matches `[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}`, does not end in a
  space or `.`, and is not a Windows reserved name or an instruction-file name (`AGENTS.md`, `CLAUDE.md`, `CLAUDE.local.md`,
  `GEMINI.md`, `SKILL.md`, `copilot-instructions.md`, in any case). The whole path has at most 120 characters and ends in
  `.md`, `.json` or `.txt`.

A raw URL cannot list a folder, so a reader never lists one. The Hive root's files come from `PUBLISHED.md`, a station's files
at LTS from its pointer, and its files at `HEAD` from its card.

### 5.2 Normalized text, and the hash of a station file

Every station file the network reads is **normalized text**: UTF-8, LF line ends only (no CR anywhere), in Unicode NFC, at most
1 MiB, and within HIVE-MD's text rules (no control, bidi, invisible or private-use character except the emoji HIVE-MD allows,
no ```` ```dataviewjs ```` block and no `$=` inline code).

A station file's hash is the **SHA-256 of its bytes**, in lowercase hex. For normalized text that is also HIVE-MD's hash
(SHA-256 of the text after CRLF to LF and NFC), what `sha256sum` prints, and what a RAPP/1 release manifest pins (section 11.4).
A reader refuses a station file whose bytes are not normalized, even when they would normalize to the listed text.

Files that a Hive root lists in `PUBLISHED.md` keep HIVE-MD's hash.

### 5.3 Fetch URLs

A file's URL is `<raw base><ref>/<path>`, with each path part percent-encoded (`urllib.parse.quote(part, safe="")`) because
names may hold spaces: `.rapp/shared/spec summary.md` is fetched as `.rapp/shared/spec%20summary.md`. A reader records that exact
URL.

## 6. The frontmatter grammar

A pointer and a card each start with a line `---`, and their frontmatter ends at the next line that is exactly `---`. Every line
between is either `key: value` or an item `  - item` under a key whose value is empty (`key:`). A key matches
`[a-z][a-z0-9_]*` and appears once. A value, and an item, has at least one character and neither starts nor ends with a
space. Readers refuse any other line, a repeated key, an unknown key, a missing required key, an item list where one value belongs, and one value where
an item list belongs. Lists are sorted by code point (as Python's `sorted` sorts them) and hold no item twice. A file has at
most 64 KB and follows the text rules of section 5.2.

Writers put the keys in the order of the tables below; readers accept any order. This is a strict subset of what HIVE-MD's
frontmatter reader takes, so the Hive agent reads these files the same way.

## 7. The pointer: `members/<station>.md`

| Key | Required | Value |
|---|---|---|
| `station` | yes | its station name (section 3): the file's name without `.md` |
| `repo` | yes | `<owner>/<repo>` |
| `raw` | yes | the raw base it is read from; its last two path parts are `repo`'s owner and name (compared without case) |
| `lts` | with `rapp1-lts` | its LTS commit, 40 lowercase hex; there exactly when `channel` is `rapp1-lts` |
| `newest` | yes | `HEAD`, or a branch name of 1 to 100 of `A-Z a-z 0-9 . _ -` that does not start with `.`, holds no `..` and does not end in `.` or `.lock` |
| `line` | yes | its line id |
| `also_on` | no | the other lines it is on (interchanges): line ids, sorted, without `line` |
| `channel` | yes | `rapp1-lts` or `newest` (section 9) |
| `lifecycle` | yes | `active`, `deprecated`, `superseded` or `archived` (section 9) |
| `superseded_by` | with `superseded` | its successor's `<owner>/<repo>`; allowed with `deprecated` or `archived`, never with `active`, never its own repo |

**The LTS manifest.** Every body line of the form `<64 lowercase hex><two spaces><path>` is a manifest line. With `lts`, the
body has 1 to 200 of them: each path once, sorted by path, no two that differ only by case (after dropping a leading
`.rapp/`), and each hash that file's hash (section 5.2) at the LTS commit. Writers list only paths of the readable set, and
list `.rapp/member.md` whenever it exists at the LTS commit; a reader refuses a listed path outside the readable set before
any fetch (`refused`), so that station fails. Without `lts`, the body has no manifest line. The rest of the body is free
markdown.

The pointer of the worked example (section 20):

```markdown
---
station: protocol
repo: contoso/protocol
raw: https://raw.githubusercontent.com/contoso/protocol/
lts: d48b17f8b64f81e45a0a52f9bf3a7ddbad2c9d15
newest: HEAD
line: contoso-core
channel: rapp1-lts
lifecycle: active
---

# protocol

The Contoso Hive reads this station at its LTS commit `d48b17f8b6`, and at `HEAD` for the newest channel.
At the LTS commit its network files have these SHA-256 hashes (of their bytes: UTF-8 text, LF line ends, NFC):

ff258cda8cfa0d77b9a66e6d6d338f0cfcb90c403d2bcbae0b611e9d1848f8c2  .rapp/member.md
dc0bca70f058bd3c3188828e59db20302fa48e7a37ae33a54273cf6087c5591d  .rapp/shared/spec-summary.md
bbaa29331bf7e54d43b565e772e68844a75a79ad51f420480fc910401549b643  README.md
```

A station that moved on, read on the newest channel only:

```markdown
---
station: fabrikam.weather
repo: fabrikam/weather
raw: https://raw.githubusercontent.com/fabrikam/weather/
newest: HEAD
line: contoso-data
channel: newest
lifecycle: superseded
superseded_by: fabrikam/weather-next
---

# fabrikam.weather

Superseded by fabrikam/weather-next. The Contoso Hive reads it at `HEAD` only.
```

## 8. The card: `.rapp/member.md`

| Key | Required | Value |
|---|---|---|
| `member` | yes | its repository's own name (never `<owner>.<repo>`) |
| `repo` | yes | `<owner>/<repo>`: the repository it is read from |
| `hive` | yes | the id of the Hive it belongs to: 32 lowercase hex |
| `hive_root` | yes | the raw base of that Hive's public copy, ending in `/` |
| `what` | yes | what it is, in one line of 1 to 200 characters |
| `line` | yes | its line id |
| `also_on` | no | as in the pointer |
| `version` | no | its version: 1 to 40 of `A-Z a-z 0-9 . _ + -`, starting with a letter or digit |
| `channel` | no | as in the pointer: the channel the station says it is on |
| `lifecycle` | no | as in the pointer: the lifecycle the station declares; no key declares none |
| `superseded_by` | with `superseded` | as in the pointer |
| `indexable` | no | `false` keeps it out of network indexes; `true`, or no key, lets it in |
| `links` | no | its neighbors, each `<repo>` (of the card's own owner) or `<owner>/<repo>`; sorted |
| `shares` | no | the paths it shares, each a `.rapp/shared/...` path of the readable set; sorted |
| `rappid` | once minted | exactly the `rappid` of its own `rappid.json` at the same commit (a RAPP/1 section 6.1 rappid) |

A reader checks a card this way:

- It follows the grammar. `repo` names the repository it was read from (else the finding `repo-mismatch`), and `member` is that
  repository's name.
- The card says what the station is and who its neighbors are. What the network decides centrally, the channel a station is read
  on and its lifecycle, lives in the pointer and the portfolio, so moving a station to `rapp1-lts` needs no commit in the
  station. A card may state `channel`, `lifecycle` and `version` too; the generator writes only a lifecycle that is not
  `active`, and neither `channel` nor `version`.
- `hive` names the Hive whose root curates it. If not, the finding is `claims-other-hive`: the card is recorded, but not
  counted as a member card of that Hive.
- Every `shares` path is in the readable set (else `share-not-readable`). At LTS, a shared path the pointer does not list is not
  fetched (`unlisted-share`).
- `rappid`, when there, equals the `rappid` of the repository's `rappid.json` at the same ref (else `rappid-mismatch`). No tool
  here mints a rappid or writes `rappid.json`; a card only mirrors one that exists.
- With `indexable: false`, the station is kept only as `{"repo": ..., "indexable": false}` and its links are not followed, as a
  beacon's `discovery.indexable: false` is honored.

The card of the worked example, as the generator writes it (section 18), with `version` and `shares` added by the station's own
commit:

```markdown
---
member: protocol
repo: contoso/protocol
hive: c0a1e5ce0d1e4a6b9f3e2d1c0b9a8f7e
hive_root: https://raw.githubusercontent.com/contoso/hive-public/
what: The Contoso protocol spec.
line: contoso-core
version: 1.2.0
links:
  - installer
shares:
  - .rapp/shared/spec-summary.md
---

# protocol on the RAPP/1 network

The Contoso protocol spec.

- Line: **Contoso Core**, on the [RAPP/1 subway map](https://contoso.example/hive-public/portfolio/subway.html).
- Neighbors: [installer](https://github.com/contoso/installer).
- New to RAPP? [Start here: get your Brainstem](https://github.com/contoso/installer#start-here).

This is this repo's card in the Contoso Hive. Change it with an ordinary commit here; the Hive reads it at this
repo's LTS commit, and at `HEAD` for the newest channel. It was generated from the Contoso Hive's portfolio.
```

## 9. Lifecycle and channel

The lifecycle words are those of a RAPP/1 lifecycle notice (the rev-17 draft of RAPP/1, section 13.6), and the network's
portfolio uses the same ones:

| `lifecycle` | Meaning | `superseded_by` |
|---|---|---|
| `active` | maintained | never |
| `deprecated` | still readable, but new use should not start | may name a recommended successor |
| `superseded` | replaced | names the successor |
| `archived` | kept readable, with no further releases | may name a successor |

| `channel` | Meaning |
|---|---|
| `rapp1-lts` | the RAPP/1 long-term-support channel: read at the pointer's `lts` commit, every file checked |
| `newest` | read at `HEAD` (or at the pointer's `newest` branch), every file unpinned; experiments live here until they graduate |

A pointer's and a card's lifecycle and channel are **copies**. The authority for a lifecycle is a RAPP/1 `lifecycle` entry in the estate's
signed registry (rev-17 draft, section 13.6), whose subject is the station's rappid or, for a station without one, its
repository's URI, `https://github.com/<owner>/<repo>`, spelled as the estate's release manifests spell it. A move of a station
without a rappid is a `superseded` notice naming the new repository. No such entry is signed yet, so a reader reports every
copy as unverified, and never infers a lifecycle from a missing one. When a card states a lifecycle or a channel and its
pointer disagrees on `lifecycle` or `superseded_by` (compared without case), the finding is `lifecycle-differs`; on `channel`,
it is `channel-differs`. A card that states neither disagrees with nothing. The graph reports the pointer's values, the
curator's copy.

Every lifecycle is walked, and `archived` stays readable. A `superseded_by` is an edge of kind `superseded-by`, and the newest
walk follows it like a link.

## 10. Above the Hive root: seed, beacon and `estate.json`

The chain above the root is RAPP's: Constitution Article XLVII, and the seed, beacon and estate walk of RAPP's
`tools/sniff_network.py`. The distributed Hive adds one optional array to `estate.json`, and nothing else.

- **The seed**, `rapp-network-seed/1.0`. A reader reads only its `operators[]`. An entry is a bare GitHub handle, which means
  `https://raw.githubusercontent.com/<handle>/rapp-estate/main/.well-known/rapp-network.json` and
  `https://raw.githubusercontent.com/<handle>/rapp-estate/main/estate.json`, or an object with `github` (or `handle`),
  `beacon_url` and `estate_url`. The seed's top-level `federation_hints` are not read, as `sniff_network.py` does not read them.
- **The beacon**, `rapp-network-beacon/1.0` or `rapp-network-beacon/1.1`, unchanged (Articles XLVII and XLVIII): `schema`,
  `operator_rappid` (an exact RAPP/1 section 6.1 rappid; legacy forms are refused), `estate_url` (which wins over the seed's),
  `discovery.indexable` (consent; no key means `true`) and `discovery.federation_hints` (walked breadth first).
- **`estate.json`** may carry a top-level array `hives[]`. Each entry has exactly these five members:

| Member | Value |
|---|---|
| `hive` | the Hive id: 32 lowercase hex, equal to the `hive:` of the root's `PUBLISHED.md` |
| `name` | a short name for people: 1 to 100 characters on one line, within HIVE-MD's text rules |
| `root` | the raw base of the Hive's public copy, ending in `/` |
| `commit` | the public copy's commit that the LTS walk reads: 40 lowercase hex |
| `published_sha256` | the HIVE-MD hash of `PUBLISHED.md` at that commit: 64 lowercase hex |

An entry with any other member, or with a member of the wrong shape, is skipped with the finding `hive-entry-invalid`.
`estate.json`'s door entries keep their own shape. The worked example's `estate.json`:

```json
{
  "hives": [
    {
      "hive": "c0a1e5ce0d1e4a6b9f3e2d1c0b9a8f7e",
      "name": "contoso-hive",
      "root": "https://raw.githubusercontent.com/contoso/hive-public/",
      "commit": "ca1e0d63f4f02d0e380ec3471a7832625c336caf",
      "published_sha256": "9ddc1ab74f7e054ef30becdc4abc71ba715aaf53d66b7abeb939fb3ca3877851"
    }
  ]
}
```

Nothing is added to the seed or the beacon: a seed entry already has `reference_state.commit_pin` and `sha256`, and the beacon
stays as Articles XLVII and XLVIII define it. For the seed, each beacon and each estate, a reader records the URL, whether it is
pinned (it has a 40-hex commit part) and the SHA-256 of the bytes it read. It checks no hash above the root: hash anchoring
starts at `hives[].published_sha256`.

## 11. The lookup

### 11.1 LTS (the default)

1. **Seed.** Fetch it. If it is not `rapp-network-seed/1.0`, its status is `placeholder` when it has a `document_type`, else
   `invalid`, and the walk stops. Read `operators[]`.
2. **Beacons**, breadth first by hop, at most 3 hops. Fetch each operator's beacon. If it is not a JSON object with one of the
   two beacon schemas, it is `placeholder` (it has a `document_type`) or `invalid`, and that operator stops. With
   `discovery.indexable: false` it is `opted-out` and stops (an audit may walk past it with `--include-private`). With an
   `operator_rappid` that is not an exact rappid it is `invalid-rappid` and stops. Queue `discovery.federation_hints[]` at the
   next hop. The beacon's `estate_url` wins.
3. **Estate.** Fetch `estate.json`. A status document without `hives[]` is a `placeholder`, and the walk stops there. Read
   `hives[]`.
4. **Hive root.** For each entry, fetch `<root><commit>/PUBLISHED.md`. Its hash must equal `published_sha256`, and its `hive:`
   must equal the entry's `hive` (else `mismatch`, and this Hive stops). Refuse the listing whole if it lists `HIVE.md`, a path
   twice, two names that differ only by case, or more than 5,000 files. Fetch each listed `members/<station>.md`, check it
   against its listed hash, and parse it (section 7; a pointer that fails is the finding `pointer-invalid` and is skipped).
   Record each `former/<station>.md` as a former station, and do not walk it.
5. **Stations.** For each pointer with `lts`, fetch every manifest path at `<raw><lts>/<path>` and check it (section 5.2). Read
   the card if the manifest lists it (section 8); if not, the finding is `no-card`: the card is not at the LTS commit yet. A
   pointer without `lts` is `not-pinned` and is not fetched.
6. **Links.** Each card link, and each `superseded_by`, is an edge. A target that no pointer of any Hive reached curates is
   **uncurated**: listed, and not fetched in LTS.

### 11.2 Newest

The same walk at moving refs: the Hive root's `PUBLISHED.md` at `<root>HEAD/` (its hash is recorded, not checked against a pin,
and the files it lists are still checked against it), each pointer's `newest` ref, and `HEAD` for uncurated stations. At a
station it reads `.rapp/member.md` and `README.md`, then `rappid.json` if the card names a `rappid`, then each path the card
`shares`. It follows links and successors into uncurated stations, breadth first (at most 3 hops and 1,000 stations), and
honors `indexable: false`. Every station file is `unpinned`.

### 11.3 Starting anywhere

A walk may start at a beacon, at an estate, or at a Hive root given by its raw base and commit (and, to anchor it, its
`published_sha256`). The stages above the start are `skipped`, and the result says where it started. A root read at a pinned
commit without a `published_sha256` is still read, and the finding `root-not-anchored` says it was trusted on first read.

### 11.4 Checking the walk against a release manifest (RAPP/1 rev-17 draft)

The rev-17 draft of RAPP/1 (on `kody-w/rapp-1`, branch `experimental/rapp1-core-rev17`; section 13.5) pins every component of
one immutable release in a **release manifest**, named by its
`manifest_hash` in an owner-signed `release-pin` entry of the estate's registry. In its words, seeds, beacons, estate catalogs,
Hive indexes and member pointers are **locators**: they may say where to look, content is verified only when a manifest pins
it, and a locator that disagrees with the manifest is a drift finding, never a second opinion.

So a resolver may take a release manifest (`--release-manifest`, with the `manifest_hash` its release pin names), and then:

1. It requires the manifest's bytes to be exactly its RAPP/1 canonical JSON, checks its form by the section 13.5 rules that need
   no registry (the members, the `release` name, `id` and `kind` grammar and order, commits, tags, the section 9.1 path grammar
   and its collisions, digests, sizes, and at most one door-of-record binding per rappid), computes
   `manifest_hash = H("rapp/1:particle", manifest)`, and compares it with the one given (else `mismatch`).
2. For each component whose `repository` is `https://github.com/<owner>/<repo>`, it fetches every pinned file at
   `<release raw prefix><owner>/<repo>/<commit>/<path>` (the prefix is `https://raw.githubusercontent.com/` unless given) and
   checks its length and SHA-256. A file of a component elsewhere is `refused`. When every file matched, each door-of-record
   binding is checked: the `identity_path` file is a JSON object whose `rappid` is the component's and whose `schema`, when
   present, is `rapp/1`. One failed file or binding fails the whole release, and then none of it is kept. A release that pins
   more than 5,000 files is `refused` before any fetch. Without `--manifest-hash`, the manifest is trusted on first read
   (finding `release-not-anchored`).
3. It cross-checks the locators. A curated station on `rapp1-lts` and the component with the same repository must agree on the
   commit and on the hash of every path both list (else `release-drift`). A curated LTS station of a Hive whose root the
   manifest pins, with no component, is `release-missing`. A component that binds a door of record (a `rappid`) must match the
   card's `rappid` of every station read with that repository, where no card counts as no rappid (else `door-of-record-drift`).
   A component whose repository is a Hive root's must pin the commit an LTS walk read that root at (else `release-drift`); a
   newest walk compares stations by their pointers' `lts`, and roots not at all.

These are steps 2 and 3 of the section 13.5 snapshot. Step 1, verifying the owner-signed registry and selecting the release pin,
is left to RAPP/1's reference implementation; this resolver checks no signature. So a checked release is still
`authenticity: unverified`, and it is never called a RAPP/1 verified snapshot.

## 12. Verification states

**Per file:**

| State | Meaning |
|---|---|
| `verified` | read at a pinned commit, and it matches its pinned hash (and, for a release file, its pinned length) |
| `mismatch` | it does not match its pinned hash or length |
| `missing` | the server answered 404 |
| `unreachable` | the retries ran out, the server gave another error answer (not 404), or offline and not in the cache |
| `refused` | outside the transport policy, over its size limit, a redirect, not in the readable set, or against the text rules |
| `unpinned` | read at a moving ref (newest), or at a pinned commit that nothing anchors; its hash is recorded only |

**Per station**, `integrity` is `verified` (every listed file verified), `failed` (any `mismatch`, `missing` or `refused`),
`unreachable`, `not-pinned` (no `lts`, so not read in LTS), or `unpinned` (newest).

**Per chain stage**, `status` is `ok`, `placeholder`, `invalid`, `opted-out`, `invalid-rappid`, `missing`, `mismatch`,
`unreachable`, `outside-policy`, `not-reached` or `skipped`.

**Everywhere**, `authenticity` is `{"state": "unverified", "reason": "estate-not-anchored"}` and `accepted` is `false`: no
signed RAPP/1 section 13 registry anchors any of it yet. Integrity, the hash chain, is all a reader checks.

## 13. Bounds, politeness and the transport policy

- At most 1 MiB per station or root file and 8 MiB per release file, refused before more than the limit and one byte is read;
  200 files per station; 5,000 files per Hive root listing and per release (a larger one is refused before any fetch); 1,000
  stations; 3 hops; 15 seconds per request.
- At most 4 requests at once (at most 8 by choice) and 8 requests a second in all.
- A 429, 500, 502, 503 or 504, a timeout or a reset connection is retried, up to 4 attempts in all, with backoff and jitter
  (0.5 s, 1 s, 2 s), honoring `Retry-After` up to 60 s. A 404 is final (`missing`); any other answer is final.
- A cache keeps one entry per URL. A URL at a 40-hex commit never changes, so a cached copy that matches is used without a
  request; a moving URL is asked again with `If-None-Match` or `If-Modified-Since`.
- Redirects are refused. Requests carry a `User-Agent`, and never credentials or cookies.
- **Transport policy**, as in `sniff_network.py`: allowed are `https://raw.githubusercontent.com` and the start URL's origin, and
  the origins and `file://` folders the user adds. A URL outside the policy is never fetched (`outside-policy`), and neither is a
  URL with a user name, a query, a fragment, a `.` or `..` part, a backslash or a NUL, or a scheme other than `https`, `http`
  or `file`.

## 14. The resolver: commands and exit codes

```text
hive_resolve.py resolve [--seed URL | --beacon URL | --estate URL |
                         --hive-root BASE --hive-commit SHA [--hive-published-sha256 HASH]]
                        [--lts | --newest] [--release-manifest URL|FILE [--manifest-hash HASH]]
                        [--release-raw-prefix BASE] [--out DIR] [--graph FILE] [--cache DIR]
                        [--workers N] [--rate R] [--max-hops N] [--max-stations N]
                        [--allow-origin ORIGIN]... [--allow-file-root DIR]... [--include-private]
                        [--refresh] [--offline] [--json] [--fixed-time UTC] [--root-files members|all]
hive_resolve.py validate card|pointer FILE [--station NAME] [--repo OWNER/REPO] [--json]
hive_resolve.py pulse-payload --graph FILE
hive_resolve.py pulse --graph FILE --stream-rappid RAPPID [--prev FRAME.json] --out FRAME.json
```

- `resolve` walks and writes `graph.json` (section 15) and, with `--out`, a snapshot (section 16). The default start is the
  network's seed. `--offline` reads only the cache, `--refresh` asks again even for pinned URLs, and `--fixed-time` makes the
  output repeat byte for byte.
- `validate` checks one card or pointer file (sections 6 to 8).
- `pulse-payload` and `pulse`: section 17.
- **Exit codes:** `0`, the walk finished with no integrity failure (unverified is not a failure); `1`, a `mismatch`, `missing`
  or `refused` file among the Hive roots or the curated stations, a root that did not match its pin, or a release that did not
  check out; `2`, a usage, policy or output error.

## 15. `graph.json`

Keys sorted, UTF-8, a two-space indent and one final newline. Lists are sorted too, so the same network, flags and
`--fixed-time` give the same bytes. `graph_sha256` is the SHA-256 of the RFC 8785 canonical JSON of every member except
`generated_at` and `graph_sha256`.

| Member | Value |
|---|---|
| `schema` | `rapp-hive-graph/1` |
| `mode` | `lts` or `newest` |
| `accepted` | `false` |
| `authenticity` | `{"state": "unverified", "reason": "estate-not-anchored"}` |
| `started_at` | `{"stage", "url"}`: `seed`, `beacon`, `estate` or `hive-root`, and its URL |
| `chain` | one entry per stage and operator: `{"stage", "url", "status", "sha256", "pinned", "detail"}` |
| `release` | `null`, or the release manifest checked (section 11.4): `{"url", "sha256", "manifest_hash", "expected_manifest_hash", "release_scope", "release", "components", "files", "verified", "state", "detail"}`, where `components`, `files` and `verified` are counts and `state` is `checked`, `failed`, `invalid`, `mismatch`, `missing`, `unreachable` or `refused` |
| `hives` | one per Hive root read: `{"hive", "name", "root", "ref", "published_sha256", "stations", "former"}` |
| `stations` | one per station (below), or `{"repo", "indexable": false}` for a station that opted out |
| `edges` | `{"from", "to", "kind"}`, where `kind` is `link` or `superseded-by` |
| `uncurated` | `{"repo", "linked_from", "fetched"}` for each repository linked or named as a successor that no pointer curates |
| `findings` | the walk's findings, `{"where", "code", "detail"}` (section 21) |
| `totals` | `{"hives", "stations", "verified", "failed", "not_pinned", "unpinned", "uncurated", "files"}` |
| `generated_at` | the RAPP/1 section 7.4 UTC form, `YYYY-MM-DDTHH:MM:SS.mmmZ` |
| `graph_sha256` | as above |

A station has `station`, `repo`, `hive`, `curated`, `line`, `also_on`, `channel`, `lifecycle`, `superseded_by`, `ref`, `raw`,
`integrity`, `files` (each `{"path", "sha256", "state"}`, sorted by path), `card` (`{"present", "what", "version",
"channel", "lifecycle", "superseded_by", "indexable", "links", "shares", "rappid", "claims_hive"}`), `release` (`null`, or
`{"component", "agrees"}`) and `findings`. For a curated station, `line`, `also_on`, `channel`, `lifecycle` and
`superseded_by` are the pointer's; for an uncurated one, the card's (`null` when the card states none). With a manifest whose state is `checked` or `failed`,
every station has `release: {"component": <id or null>, "agrees": <bool>}`, where `agrees` is `false` exactly when the
station has a `release-drift`, `release-missing` or `door-of-record-drift` finding; otherwise `release` is `null`.

The worked example's LTS walk, started at its `estate.json`, with `--fixed-time 2026-09-25T00:00:00.000Z`:

```json
{
  "accepted": false,
  "authenticity": {
    "reason": "estate-not-anchored",
    "state": "unverified"
  },
  "chain": [
    {
      "detail": "the walk started at the estate",
      "pinned": false,
      "sha256": null,
      "stage": "seed",
      "status": "skipped",
      "url": null
    },
    {
      "detail": "the walk started at the estate",
      "pinned": false,
      "sha256": null,
      "stage": "beacon",
      "status": "skipped",
      "url": null
    },
    {
      "detail": "1 Hive(s) listed",
      "pinned": true,
      "sha256": "a62f33377699ad7be4c3616277bc8ee3d90a1ff6fcb1707f10db13d96ae03439",
      "stage": "estate",
      "status": "ok",
      "url": "https://raw.githubusercontent.com/contoso/rapp-estate/0d5a9fc1eee26eb2b85fbadff6bfdf2d4a2fb6d0/estate.json"
    },
    {
      "detail": "Hive c0a1e5ce0d1e4a6b9f3e2d1c0b9a8f7e: 2 file(s) listed, 1 station pointer(s)",
      "pinned": true,
      "sha256": "9ddc1ab74f7e054ef30becdc4abc71ba715aaf53d66b7abeb939fb3ca3877851",
      "stage": "hive-root",
      "status": "ok",
      "url": "https://raw.githubusercontent.com/contoso/hive-public/ca1e0d63f4f02d0e380ec3471a7832625c336caf/PUBLISHED.md"
    }
  ],
  "edges": [
    {
      "from": "contoso/protocol",
      "kind": "link",
      "to": "contoso/installer"
    }
  ],
  "findings": [],
  "generated_at": "2026-09-25T00:00:00.000Z",
  "graph_sha256": "573d3e72d6735c79103f656ce68ad3160ca48a32ea7e87a22c0e82b5f29babd6",
  "hives": [
    {
      "former": [],
      "hive": "c0a1e5ce0d1e4a6b9f3e2d1c0b9a8f7e",
      "name": "contoso-hive",
      "published_sha256": "9ddc1ab74f7e054ef30becdc4abc71ba715aaf53d66b7abeb939fb3ca3877851",
      "ref": "ca1e0d63f4f02d0e380ec3471a7832625c336caf",
      "root": "https://raw.githubusercontent.com/contoso/hive-public/",
      "stations": 1
    }
  ],
  "mode": "lts",
  "release": null,
  "schema": "rapp-hive-graph/1",
  "started_at": {
    "stage": "estate",
    "url": "https://raw.githubusercontent.com/contoso/rapp-estate/0d5a9fc1eee26eb2b85fbadff6bfdf2d4a2fb6d0/estate.json"
  },
  "stations": [
    {
      "also_on": [],
      "card": {
        "channel": null,
        "claims_hive": true,
        "indexable": true,
        "lifecycle": null,
        "links": [
          "contoso/installer"
        ],
        "present": true,
        "rappid": null,
        "shares": [
          ".rapp/shared/spec-summary.md"
        ],
        "superseded_by": null,
        "version": "1.2.0",
        "what": "The Contoso protocol spec."
      },
      "channel": "rapp1-lts",
      "curated": true,
      "files": [
        {
          "path": ".rapp/member.md",
          "sha256": "ff258cda8cfa0d77b9a66e6d6d338f0cfcb90c403d2bcbae0b611e9d1848f8c2",
          "state": "verified"
        },
        {
          "path": ".rapp/shared/spec-summary.md",
          "sha256": "dc0bca70f058bd3c3188828e59db20302fa48e7a37ae33a54273cf6087c5591d",
          "state": "verified"
        },
        {
          "path": "README.md",
          "sha256": "bbaa29331bf7e54d43b565e772e68844a75a79ad51f420480fc910401549b643",
          "state": "verified"
        }
      ],
      "findings": [],
      "hive": "c0a1e5ce0d1e4a6b9f3e2d1c0b9a8f7e",
      "integrity": "verified",
      "lifecycle": "active",
      "line": "contoso-core",
      "raw": "https://raw.githubusercontent.com/contoso/protocol/",
      "ref": "d48b17f8b64f81e45a0a52f9bf3a7ddbad2c9d15",
      "release": null,
      "repo": "contoso/protocol",
      "station": "protocol",
      "superseded_by": null
    }
  ],
  "totals": {
    "failed": 0,
    "files": 3,
    "hives": 1,
    "not_pinned": 0,
    "stations": 1,
    "uncurated": 1,
    "unpinned": 0,
    "verified": 1
  },
  "uncurated": [
    {
      "fetched": false,
      "linked_from": [
        "contoso/protocol"
      ],
      "repo": "contoso/installer"
    }
  ]
}
```

A subway map reads `stations[].line`, `also_on`, `lifecycle` and `edges`. A pulse reads `graph_sha256` and `totals`.

## 16. The snapshot

`resolve --out DIR` writes into a new folder next to `DIR` and swaps it in at the end, so `DIR` is never half written. `DIR` must
be absent, empty, or an earlier snapshot (one that holds `SNAPSHOT.json`). Nothing is written through a link.

```text
DIR/SNAPSHOT.json                          rapp-hive-snapshot/1
DIR/graph.json
DIR/root/<hive>/<path>                     the root's files read: PUBLISHED.md and the pointers (every listed file with --root-files all)
DIR/stations/<owner>/<repo>/<ref>/<path>   station files that verified (LTS) or were read (newest); never a mismatch
DIR/release/manifest.json                  the release manifest's bytes, when the release checked out
DIR/release/<component id>/<path>          every file it pins, only when every one of them verified
```

`SNAPSHOT.json` has `schema`, `mode`, `accepted` (`false`), `authenticity`, `chain`, `release` (as in the graph), `files` (each
`{"path", "url", "sha256", "state", "anchor"}`, where `anchor` names what pinned it: `estate.json hives[] published_sha256`
or `--hive-published-sha256` for `PUBLISHED.md`, `PUBLISHED.md` for the root's other files, `members/<station>.md` for a
station's files, `release manifest` for a release's files, `--manifest-hash` for `release/manifest.json` (or `null`, and `unpinned`, without
one), or `null` when nothing pinned it), `skipped` (files not written, and why; a release that did not check out adds one entry
`release`), `graph_sha256` and `generated_at`.

## 17. Pulses

A walk can be announced as a RAPP/1 section 7 frame of kind `body.pulse`. A stream has one writer, or it forks (RAPP/1 section
7.6), so a resolver offers two commands:

- `pulse-payload --graph FILE` prints the walk's fragment, for the stream's owner to put in the owner's own pulse:
  `{"graph_sha256", "mode", "hives": [{"hive", "ref", "published_sha256"}], "totals"}`, with `hives` sorted by `hive`, `ref`
  and `published_sha256`, as canonical JSON and one newline.
- `pulse --graph FILE --stream-rappid RAPPID [--prev FRAME.json] --out FRAME.json` writes a frame, for a stream the caller owns:
  the next `seq` and `prev` after `--prev` (the previous frame's JSON), `utc` set to the graph's `generated_at`, `payload` set to
  the fragment above, and `prev_wave` and `sig` `null`. The file is the frame's canonical JSON and nothing else.

An unsigned pulse is a valid RAPP/1 frame whose hash chain proves integrity only; it does not speak for the estate. Under the
rev-17 draft (section 13.7), a pulse speaks for the estate only when the estate owner signs it, or when a `stream-signer` entry
grants its signer that stream and kind. Station repositories carry no frames.

## 18. The card generator

The generator writes cards and pointers from a portfolio. It never commits, never pushes, and never writes or mints a
`rappid.json`.

```text
member_cards.py card     --portfolio DIR --family FILE --repo NAME [--checkout DIR] [--check] [--lts-pins FILE]
member_cards.py cards    --portfolio DIR --family FILE --out DIR [--repos a,b] [--clones DIR] [--lts-pins FILE]
member_cards.py pointers --portfolio DIR --family FILE --lts-pins FILE --clones DIR --out DIR [--repos a,b]
member_cards.py plan     --portfolio DIR --family FILE --clones DIR [--out FILE] [--repos a,b] [--lts-pins FILE]
```

Every command also takes the template flags `--owner`, `--hive`, `--hive-root`, `--hive-name`, `--subway-url` and `--start-url`
(and `pointers` takes `--raw-prefix`), which default to the values of the network the tool is built for.

**Inputs.**

- The portfolio folder: a `repos/<repo>.md` per repository, whose frontmatter has `repo` (`<owner>/<repo>`), `family` (the line
  id), `line` (the line's name for people) and `links_to` (its neighbors), and may have `channel`, `lifecycle` and
  `superseded_by` (section 9); and a `lines/<id>.md` per line, with `line: <id>` and `name: <name for people>`. Only
  repositories in the portfolio are ever written.
- The inventory, `family.json`: a list of `{"repo", "family", "also_on", "description", "default_branch", "empty"}`, with
  `archived` when it is known.
- `--lts-pins FILE`: either a RAPP/1 release manifest (`rapp/1-release-manifest`), in which each component whose repository is
  `https://github.com/<owner>/<repo>` pins that repository's LTS commit (it is checked as a value, so it may be pretty-printed);
  or a JSON object mapping `<owner>/<repo>` or `<repo>` to a 40-hex commit or to `{"commit": ...}`, at the top level or under
  `pins`.

**Fields.** `line` is the portfolio's `family`, and the card's body shows the line's name. `what` is the inventory's
`description`, cut to the text rules and to 200 characters on a word boundary (or `A <line name> repository on the RAPP/1
network.`). `lifecycle` and `superseded_by` are the portfolio's, else `archived` when the inventory says archived, else
`active`; nothing is inferred from other files. A card gets them only when the lifecycle is not `active`; a pointer always gets
them, with `channel`, which is `rapp1-lts` exactly when an LTS pin is given. `links` is `links_to` without the repository itself
and without names of instruction files. `rappid` mirrors the `rappid` of a valid `rappid.json` that exists, and nothing else.
The generator writes no `version` and no card `channel`: they would go stale in the station's own files.

**Commands.**

- `card` prints one card, or writes it to `<checkout>/.rapp/member.md`; with `--check` it exits `1` when the file there differs.
- `cards` writes `<out>/<repo>/.rapp/member.md` for many repositories, and `<out>/cards.json` (`rapp-hive-cards/1`).
- `pointers` writes `<out>/members/<station>.md` for each repository in the portfolio, and `<out>/pointers.json`
  (`rapp-hive-pointers/1`). For a pinned repository it lists each readable file at the LTS commit, read with
  `git show <commit>:<path>` from a local clone, with its hash; a file that is not normalized text is left out and named. When
  the pins come from a release manifest, a file both list must have the same hash, else the pointer is refused, and
  `pointers.json` records its `release_manifest_hash`. A repository without a pin gets `channel: newest`, no `lts`, and the
  body `# <station>`, then `[Superseded by <repo>. | Deprecated[; its successor is <repo>]. | Archived[; its successor is
  <repo>]. ]The <hive name> reads it at `HEAD` only.`, as the second example of section 7.
- `plan` writes `rapp-hive-card-plan/1`: `auto` or `hold` for each repository, with the reasons. It holds a repository that pins
  its tracked path set (a tracked file with `tracked_path_count`, `tracked_path_set_sha256`, `path_set_sha256` or
  `tracked_paths`, or a `MANIFEST*` or `*INVENTORY*.json` file that lists at least half of the tracked paths), that has anything
  in `.rapp/` besides the RAPP Workspace's bootstrap files and the card, whose existing card differs, that is empty, that is
  named like an instruction file, that has no local clone, or whose generated card would not validate. `pointers` refuses a
  repository whose portfolio `channel` disagrees with its pin (`rapp1-lts` without a pin, or `newest` with one).

The generated card's body, where `[...]` parts appear only when they apply:

```text
# <repo> on the RAPP/1 network

<what>

- Line: **<line name>**[, also on **<other line name>**]..., on the [RAPP/1 subway map](<subway url>).
[- Neighbors: [<repo>](https://github.com/<owner>/<repo>), [<repo>](https://github.com/<owner>/<repo>)....]
- New to RAPP? [Start here: get your Brainstem](<start url>).

This is this repo's card in the <hive name>. Change it with an ordinary commit here; the Hive reads it at this
repo's LTS commit, and at `HEAD` for the newest channel. It was generated from the <hive name>'s portfolio.
```

## 19. The Hive agent

The Hive agent, `agents/hive_agent.py`, reads the distributed Hive with two actions (HIVE-MD, "Remote member spaces"):

- `reference label=<label> url=<raw base at a commit> [sha256=<hash>]` pins a Hive root's public copy on this device, and never
  commits the pin. The address is `https://<host>/<path>/<40-hex commit>/` (`http` only to `127.0.0.1` or `localhost`), with no
  user name, query or fragment. With `sha256=`, the `published_sha256` of the estate's `hives[]` entry, `PUBLISHED.md` must
  match it or nothing is read.
- `resolve ref=<label>` reads each station the root points to at its pointer's `lts` commit into this device's cache, each file
  checked as section 5.2 says. It replies with the stations verified, those not pinned, every problem, and whether the root was
  anchored by a given hash or trusted on first read. It commits nothing.

Its cache, `.git/rapp-hive/remote/<label>/`, holds the root's listed files at their public-copy paths (with `PUBLISHED.md`),
each station's files at `stations/<station>/<path without a leading .rapp/>`, and a hidden `.origins.json` with the exact raw URL
of each. A root file under `stations/` is left out, and a station's raw base must be on the root's host.

## 20. Worked example

The Contoso operator's `estate.json`, at commit `0d5a9fc1eee26eb2b85fbadff6bfdf2d4a2fb6d0` of `contoso/rapp-estate`, is the one in section 10. It pins
the public copy `contoso/hive-public` at commit `ca1e0d63f4f02d0e380ec3471a7832625c336caf`, whose `PUBLISHED.md` is:

```markdown
---
manifest: 17ab487d8662754746d51f8b08073d7fc3b2a4e8103e83fda6340d23f529ad4e
hive: c0a1e5ce0d1e4a6b9f3e2d1c0b9a8f7e
---

e25afc4979a59be6efaf3a126296df4d4b8251d05b7a49ca9af75f2b5877a497  members/protocol.md
b6b3f5354ec37afb6f605a8dbe920d8632a6cc9484c1cefd4c84e28580a4f24d  portfolio/lines.md
```

Its `portfolio/lines.md`:

```markdown
# Lines

- contoso-core: Contoso Core
```

Its `members/protocol.md` is the pointer in section 7. At the LTS commit `d48b17f8b64f81e45a0a52f9bf3a7ddbad2c9d15` of
`contoso/protocol`, `.rapp/member.md` is the card in section 8, and the other two files are:

`README.md`:

```markdown
# Protocol

The one spec for the Contoso network.
```

`.rapp/shared/spec-summary.md`:

```markdown
# Spec summary

Frames, the wire and eggs.
```

Every hash in this example is the SHA-256 of the file exactly as shown, each ending in one newline. The walk's `graph.json` is
the one in section 15.

## 21. Findings

| Code | Meaning |
|---|---|
| `bad-node` | a seed entry or federation hint names neither a handle nor a beacon URL |
| `hive-entry-invalid` | an `estate.json` `hives[]` entry does not have exactly the five members of section 10 |
| `duplicate-hive` | the same Hive is listed twice |
| `root-not-anchored` | a Hive root was read at a pinned commit without a `published_sha256`: trusted on first read |
| `bad-path` | the root lists a path that is not a portable `.md` path of at most 120 characters, or not a station name |
| `instruction-file-name` | a pointer or a link names a repository named like an AI instruction file |
| `outside-policy` | a URL the transport policy does not allow: never fetched |
| `pointer-invalid` | a listed pointer does not follow section 7 |
| `duplicate-station` | a second pointer for a repository that already has one (a listing with two names that differ only by case is refused whole) |
| `station-name` | a pointer's name is not its repository's station name (section 3) |
| `max-stations` | beyond the station limit: not walked |
| `mismatch`, `missing`, `refused`, `unreachable` | a file in that state (section 12) |
| `no-card` | a pointer's manifest does not list `.rapp/member.md`, or a station has no card at `HEAD` |
| `card-invalid` | a card does not follow section 8 |
| `repo-mismatch` | a card names another repository than the one it was read from |
| `claims-other-hive` | a card names another Hive than the one that curates it |
| `share-not-readable` | a card shares a path outside the readable set |
| `unlisted-share` | at LTS, a card shares a path its pointer does not list: not read |
| `rappid-mismatch` | a card's `rappid` differs from its `rappid.json` |
| `lifecycle-differs`, `channel-differs` | a pointer and its station's card disagree |
| `integrity-failed` | a station that opted out of indexes failed a check (the details stay out of the graph) |
| `release-not-anchored` | a release manifest checked without `--manifest-hash`: trusted on first read |
| `release-drift` | a pointer or a Hive root disagrees with the release manifest |
| `release-missing` | a curated LTS station that the release manifest does not pin |
| `door-of-record-drift` | a release component's door of record disagrees with the station's card |

## 22. The synthetic test network

Tests use only the Contoso cast and never the internet. The operator `contoso` has a seed at
`contoso/RAPP/main/.well-known/rapp-network-seed.json`, a beacon at `contoso/rapp-estate/<commit>/.well-known/rapp-network.json`
and an estate at `contoso/rapp-estate/<commit>/estate.json`. Its Hive, `c0a1e5ce0d1e4a6b9f3e2d1c0b9a8f7e`, has the public copy
`contoso/hive-public`. Its stations: `protocol` and `installer`; `agent-index`, whose card shares files; `notes`, on the newest
channel only; `tampered`, whose file does not match its pointer; `rollout`, whose manifest lists only `README.md` (its card is
not at LTS yet); `odd`, whose pointer lists files the network never reads; and `ledger`, superseded by `ledger-next`. A second
operator, `fabrikam`, is reached through the beacon's federation hints, with its own Hive and the station `fabrikam/weather`,
and an uncurated `fabrikam/drafts` whose card says `indexable: false`. A release manifest pins some of the stations, one of them
at another commit.

A local server on `127.0.0.1` serves `http://127.0.0.1:<port>/<owner>/<repo>/<ref>/<path>`, where `<ref>` is a 40-hex commit or
`HEAD`. It answers `If-None-Match` with 304, can inject a 429 with `Retry-After`, a 500 and slow answers, and counts the most
requests at once. One walk runs over `file://`.

## 23. Known limits

- Integrity only: nothing signs the chain yet. A result is only as honest as the pins above it, and the raw server is trusted
  only as far as the hashes.
- The newest channel reads moving refs, so what it shows can change between two requests.
- A station with a CR in a file, or a file that is not in NFC, cannot list that file until it is normalized.
- A repository named like an instruction file can never be a station.
- A resolver that follows this file checks no signature, so it never verifies a RAPP/1 registry, release pin or lifecycle
  notice; it only reports what those would be checked against.

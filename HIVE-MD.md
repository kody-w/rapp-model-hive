# HIVE-MD: a Hive as a tree of markdown files

A Hive is a folder of markdown files kept in git, which your Brainstem runs for you. Signed commits decide who is in;
folders only organize.

## The tree

```text
HIVE.md                       the rules
.gitattributes                exactly "* text eol=lf", never changed
members/<name>/               a member's space
  keys/<device>.md            their device keys: signed requests, moved in (the roster)
  approvals/<slug>.md         their approvals
  publish/<slug>.md           publication manifests they propose
requests/<name>/<device>.md   requests to join, or to add a device
shared/<room>/...             rooms every member edits
former/<name>[-<n>]/...       folders of members who left or were removed (n from 2 to 99)
```

Who is in: the folders under `members/` holding a key file. Reorganizing is moving files.

## Members, devices and keys

A member is usually a person; a team or an agent with its own keys can be one too. One member has one vote, and a device
is not a member. Each device has its own key for each Hive, so Hives cannot be linked. Keys are never committed: they
live in `<hive>/.git/rapp-hive/`, so copying a whole Hive folder, `.git` included, copies the key. A Hive inside a known
sync folder is refused. Every key sits in exactly one key file. Names are lowercase letters, digits and dashes, at most
32 characters.

Only a member's own signed commits change their space, with two governed exceptions: admission moves the newcomer's own
signed request in, and removal moves the space to `former/`. Devices that verify refuse anything else; a transport still
carries the bytes.

## Files

- **`HIVE.md`**: `hive` (a random id fixed by the first commit), `version` (1 at first; every change sets exactly one
  more, so a text never repeats), `approvals` (at least 1; new Hives start at 2), an optional `fields` hint for tasks of
  different shapes, and optional `previous` (old Hive ids whose requests count).
- **Request**: `request: rapp-hive`, `hive`, `name` (its folder), `device` (its file name), `key: ssh-ed25519 …`, `utc`,
  an optional note, then a ```` ```ssh-signature ```` block: SSHSIG (namespace `rapp-hive-request`, SHA-512) by that key
  over everything before it, normalized to UTF-8, LF and NFC.
- **Carried request**: `request: carried`, `from` (listed in `previous`), `name`, `device`, `spki`, and an old RAPP/1
  frame, byte for byte, in a ```` ```rapp-frame ```` block, checked with RAPP/1's hash and signature math.
- **Approval**: `approve: admit|remove|rules|publish`, the `sha256` of the exact subject, and `member` (remove) or
  `replaces` (rules). The approver's signed commit is its signature. A removal names the member's membership: the request
  moved in when their `keys/` folder was last created. New or retired devices keep it; leaving and coming back changes it.

## The one rule

Every commit after the pinned first commit has one parent and an SSH signature (namespace `git`) by a key that the tree
at its parent lists under `members/<name>/keys/`, in that name. Any other key may only add one request carrying itself.
Judged by the tree at the parent, the signer may change:

- their own folder, except keys: a key arrives only as their own request moved in, and may go while another remains;
- anything in `shared/`; adding a request that verifies, or deleting one;
- **admit**: move a request into `members/<name>/keys/` with *threshold* approvals;
- **leave**: move their whole folder to the first free `former/<name>[-<n>]/`, while at least one member remains;
- **remove**: move someone's folder to `former/`, approved by every other member, at least two;
- **rules**: change `HIVE.md` with max(1, min(max(old, new `approvals`), members)) approvals naming both hashes.

*threshold* = max(1, min(`approvals`, members)), so a founder admits the first member alone. The signer counts once, and
only current members' approvals of the exact hash count. A request that was ever admitted, even for a device retired
since, is never filed again: coming back takes a new request. History is one line: each commit's one parent is the
commit that passed just before it. `hive` and `.gitattributes` never change; `former/` only receives leaving and removal
moves. Everything else is refused, and the first refused commit stops verification.

An edit can be undone by a new signed commit if nothing changed since. Membership and rules change back only through
these rules: undoing an admission is a removal. A publication cannot be recalled from anyone who already copied it.

## Refused anywhere

Links, submodules, executables; ```` ```dataviewjs ```` blocks, also after quote, callout or list markers or an indent,
and Dataview inline JavaScript (inline code starting with `$=`), since note apps run them; text that is not UTF-8 or
holds control, bidi, invisible or private-use characters (a fixed list, so every device agrees; emoji keep the few
invisible marks they need: one variation selector after an emoji, one in a keycap, and a joiner between two emoji);
files over 1 MB (requests: 64 KB), judged by size before they are read; files not ending in `.md`; paths over 120
characters (116 under `members/`, so a move to `former/` fits); names that break on some system; the instruction-file
names `AGENTS.md`, `CLAUDE.md`, `CLAUDE.local.md`, `GEMINI.md`, `SKILL.md` and `copilot-instructions.md`; anything else
at the root; commit headers other than tree, parent, author, committer, gpgsig and `encoding UTF-8`, or any header
twice.

The checker's rules change only with a new version of this convention, and then only tighten. The dataviewjs rule is
new in this experimental version.

## Publishing

A manifest in `members/<name>/publish/` names the public copy and lists `sha256  path` for files of one room. With
*threshold* approvals, the Brainstem copies exactly those files into a separate repository with `PUBLISHED.md`, in one
signed commit. `check-public` checks the committed tree: plain files only, each listed with its hash, nothing else.
With `--hive`, it also checks that every public commit is signed by a current member (a former member's signature is
named as such) and that the files, `to:` and `hive:` are exactly those of a manifest the Hive approved.

## References

A reference is a folder kept in its own shape (an old Hive that does not follow this convention, a note vault, a wiki,
a docs folder), pinned by one device in `.git/rapp-hive/references.json`, never committed. The pin is judged by the
folder's real path, in any case, and nothing on the way may be a link. It is refused for the filesystem root and the
home folder; inside or around the Hives folder or the Brainstem's own folders; a hidden part; `~/Library` on macOS,
except `Mobile Documents` (iCloud Drive) and `CloudStorage`; and a credential folder (`.ssh`, `.gnupg`, `.aws`,
`.config`, `.kube`, `Keychains`) or one that holds it. A reference is read-only and unattributed: nothing in it is
changed, trusted, run or loaded, and what the Brainstem shows from it is fenced raw data. Knowledge enters the Hive only
when a member brings a piece of it in by one signed commit, into `shared/<room>/` or a folder of their own (never
`approvals/`, `keys/`, `rules/` or `publish/`), with `brought_from: <label>/<path>` and `brought_sha256` added to each
file. Names are made portable; a name already taken gets `-2`, `-3`, and links follow. Another Hive is brought from
only through a clean public copy: `PUBLISHED.md`, no `HIVE.md`, and `check-public` finds nothing.

## Remote member spaces

A network of repositories can be one Hive. A **station** is one public repository on it; its member space is its card
`.rapp/member.md` and the files it shares under `.rapp/shared/`, changed by its own commits. The Hive root keeps one
**pointer** per station in its one published room: `shared/<room>/members/<station>.md` in the Hive, `members/<station>.md`
in its public copy (the Hive's own `members/` holds people's spaces, and the checker refuses a pointer there).
[DISTRIBUTED-HIVE.md](DISTRIBUTED-HIVE.md) is the single source of truth for the pointer, the card, the files the network
reads and their hashes, how a reader finds them from a seed, and what the network's tools write. This section says what the
Hive agent does with them.

A **remote reference** is pinned with `url=`: a clean public copy's raw base at a full 40-hex commit
(`https://<host>/<path>/<commit>/`, and on `raw.githubusercontent.com` exactly
`https://raw.githubusercontent.com/<owner>/<repo>/<commit>/`; `http` only to this device; a lowercase host of letters,
digits, `.` and `-`, not ending in `.`; no user name, port on GitHub raw, query or fragment; a pin kept from before a rule
is read no more). It may also be pinned with
`sha256=`, the hash of its PUBLISHED.md (the `published_sha256` of its estate's `hives[]` entry); then a PUBLISHED.md that
does not match it is refused, and nothing of the copy is read. Reading it fetches PUBLISHED.md there, then each file it
lists, never following a redirect; a file is kept only if it is at most 1 MB, passes the text rules above and matches its
listed hash. Anything else is left out and named, nothing unlisted is fetched, and a listing that names `HIVE.md`, a path
twice, names that differ only by case, or more than 5,000 files is refused whole. What passes is kept in
`.git/rapp-hive/remote/<label>/` and read like any reference: raw data, fenced, never run. `bring` marks each copy with
`brought_from:` the exact raw URL of the file at that commit, and `brought_sha256`.

`resolve ref=<label>` reads a Hive root's stations: for each pointer with `lts`, every listed file at `<raw><lts>/<path>`,
into the same cache as `stations/<station>/<path without a leading .rapp/>` (so `.rapp/member.md` becomes
`stations/<station>/member.md`). A station's file is kept only if its bytes are normalized text (LF line ends, NFC) whose
SHA-256 is the one its pointer lists. A pointer is read only when its name is its repo's station name (the repo's name when
the root's owner owns it, else `<owner>.<repo>`), and its `raw` passes the same address rules at the root's origin (the same
scheme, host and port); a root file under `stations/` is left out, and a root that points to more than 1,000 stations is not
resolved. It names the stations verified, those not pinned and every problem, says whether the root was anchored by
`sha256=` or trusted on first read, commits nothing, and fetches only what the cache lacks. The hashes prove integrity only:
authenticity stays unverified until a signed entry of the estate's registry covers this root.

The long-term-support channel is `rapp1-lts`; `newest` moves, and the Brainstem reads only pinned commits. The network
tooling's resolver also walks newest, and the chain above the root: seed, beacon, `estate.json` `hives[]` (RAPP proposal
0020).

## Shared copies

A shared copy is a git remote reached over ssh, https or git, or a folder; no other transport or remote helper is used.
A folder shared copy must be a bare git repository without `objects/info/alternates`, outside synced folders. When the
Brainstem reaches it, git's known config hooks are switched off (hooks, `core.alternateRefsCommand`, `core.fsmonitor`,
`receive.denyCurrentBranch=updateInstead`, automatic gc). Anyone who can write that folder can still stall it, but
cannot sign as a member: devices refuse what they cannot verify.

## Verify it yourself

```text
python agents/hive_agent.py check <hive-folder> [--root <commit from the invitation>]
python agents/hive_agent.py check-public <public-copy> --hive <hive-folder>
git -c gpg.format=ssh -c gpg.ssh.allowedSignersFile=<file> log --show-signature
ssh-keygen -Y verify -f <file> -I <name> -n rapp-hive-request -s <signature> < <signed-text>
curl -s <raw base><commit>/<listed path> | sha256sum
```

Stock tools check signatures (list `<name> namespaces="git,rapp-hive-request" ssh-ed25519 <key>` per key file); only the
checker checks the rule. For a fetched file whose text has LF line ends and is in NFC, `sha256sum` gives the hash that
PUBLISHED.md or a pointer lists.

## Known limits

- With `approvals: 1`, a member can admit a second identity of their own and outvote a lone co-member, so a Hive that
  needs protection keeps `approvals` at 2 or more.
- A two-member Hive cannot remove anyone, and two members who both vanish cannot be removed.
- Whoever holds a member's only key acts as that member until removed. A member who loses every device can only be
  removed and re-admitted by the others.
- A shared device, such as a kiosk, must not hold a member key.
- A plan proposed in one chat tab can be applied from another on the same device. Plain editors check nothing.
- A remote reference is only as honest as the PUBLISHED.md at its pinned commit: the raw server is trusted only as far as
  the listed hashes, and nothing signs that listing until a signed entry of the estate's registry covers the root. A
  public copy that moves is never read; pin a newer commit to see newer files.
- A repository named like an instruction file (`agents`, `claude`, `claude.local`, `gemini`, `skill`,
  `copilot-instructions`, in any case) can never be a station, whoever owns it: `members/agents.md` is refused like any
  `AGENTS.md`, and so is a pointer whose `repo` is `fabrikam/agents`.

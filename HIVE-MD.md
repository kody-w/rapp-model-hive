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
only current members' approvals of the exact hash count. A request that was admitted once is never filed again: coming
back takes a new request. `hive` and `.gitattributes` never change; `former/` only receives leaving and removal moves.
Everything else is refused, and the first refused commit stops verification.

An edit can be undone by a new signed commit if nothing changed since. Membership and rules change back only through
these rules: undoing an admission is a removal. A publication cannot be recalled from anyone who already copied it.

## Refused anywhere

Links, submodules, executables; text that is not UTF-8 or holds control, bidi, invisible or private-use characters (a
fixed list, so every device agrees); files over 1 MB (requests: 64 KB), judged by size before they are read; files not
ending in `.md`; paths over 120 characters (116 under `members/`, so a move to `former/` fits); names that break on
some system; the instruction-file names `AGENTS.md`, `CLAUDE.md`, `CLAUDE.local.md`, `GEMINI.md`, `SKILL.md` and
`copilot-instructions.md`; anything else at the root; commit headers other than tree, parent, author, committer, gpgsig
and `encoding UTF-8`, or any header twice.

## Publishing

A manifest in `members/<name>/publish/` names the public copy and lists `sha256  path` for files of one room. With
*threshold* approvals, the Brainstem copies exactly those files into a separate repository with `PUBLISHED.md`, in one
signed commit. `check-public` checks the committed tree: plain files only, each listed with its hash, nothing else.
With `--hive`, it also checks that every public commit is signed by a member's key and that the manifest was approved.

## Shared copies

A shared copy is any git remote. A folder shared copy must be a bare git repository without `objects/info/alternates`,
outside synced folders. When the Brainstem reaches it, git's known config hooks are switched off (hooks,
`core.alternateRefsCommand`, `core.fsmonitor`, `receive.denyCurrentBranch=updateInstead`, automatic gc). Anyone who can
write that folder can still stall it, but cannot sign as a member: devices refuse what they cannot verify.

## Verify it yourself

```text
python agents/hive_agent.py check <hive-folder> [--root <commit from the invitation>]
python agents/hive_agent.py check-public <public-copy> --hive <hive-folder>
git -c gpg.format=ssh -c gpg.ssh.allowedSignersFile=<file> log --show-signature
ssh-keygen -Y verify -f <file> -I <name> -n rapp-hive-request -s <signature> < <signed-text>
```

Stock tools check signatures (list `<name> namespaces="git,rapp-hive-request" ssh-ed25519 <key>` per key file); only the
checker checks the rule.

## Known limits

- With `approvals: 1`, a member can admit a second identity of their own and outvote a lone co-member, so a Hive that
  needs protection keeps `approvals` at 2 or more.
- A two-member Hive cannot remove anyone, and two members who both vanish cannot be removed.
- Whoever holds a member's only key acts as that member until removed. A member who loses every device can only be
  removed and re-admitted by the others.
- A shared device, such as a kiosk, must not hold a member key.
- A plan proposed in one chat tab can be applied from another on the same device. Plain editors check nothing.

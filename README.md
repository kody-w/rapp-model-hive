# Contoso Model Hive (the tree of markdown files)

**A model Hive, like a model home: everything is furnished so you can walk through it, but nobody lives here.**

> [!WARNING]
> **Everything here is synthetic.** Contoso is a made-up company, and its people and devices are invented. Every key is a
> **public test key** that anyone can re-derive from a published label (`test_key` in
> [`tools/build_example.py`](tools/build_example.py)). Those keys prove nothing. Never use them, or this Hive, for real data.

**Status: experimental.** This branch (`experimental/hive-md`) rebuilds the model as a Hive that is just a tree of markdown
files ([HIVE-MD.md](HIVE-MD.md), one page). This repository's `main` branch (commit `83e039f`) keeps the frozen rapp-hive/2
model as a research record; see [MIGRATION.md](MIGRATION.md).

## The house tour

The house is [`example/contoso-onboarding/`](example/contoso-onboarding/): the team's Hive after the whole story below.
GitHub shows it like any folder. Every change in it is a signed commit, listed in [`example/HISTORY.md`](example/HISTORY.md).

| Room | What you see |
|---|---|
| **Front door**: [`HIVE.md`](example/contoso-onboarding/HIVE.md) | The only rules: the Hive's id, `approvals: 2` (the default), a `fields` hint, and `previous`: the ids of two old Hives whose signed requests are honored. |
| **Residents**: [`members/`](example/contoso-onboarding/members/) | Avery, Casey, Drew and Emery. Each folder is that member's space: only their own signed commits change it, apart from two governed moves (admission moves their own request in; removal moves the folder to `former/`). `keys/` is the roster: a key file is a signed request that was moved in. Avery's keys show her new laptop; Emery's show she moved off the shared kiosk. |
| **Approvals**: `members/*/approvals/` | One small file per approval, naming the exact hash it approves. With `approvals: 2`, one approval plus the signed move of the member who admits makes two. Casey approved Drew's admission and the public page. |
| **The waiting room**: [`requests/frankie/laptop.md`](example/contoso-onboarding/requests/frankie/laptop.md) | Frankie's old rapp-hive/2 join request, carried byte for byte. Nobody admitted him. His note tries to steer your AI; the Brainstem shows it only when asked, fenced as quoted data, and nothing happens without your yes. |
| **The rooms**: [`shared/`](example/contoso-onboarding/shared/) | Tasks from three apps in three shapes. Casey split onboarding into `week-1` and `week-2` and renamed `misc` to `facilities`, just by moving files. Links name files (`[[T-100]]`), so nothing broke. |
| **Library**: [`shared/wiki/`](example/contoso-onboarding/shared/wiki/) | Three notes Drew brought in from his own note vault ([`example/sources/drew-notes/`](example/sources/drew-notes/), pinned on his device as a reference and read there as raw data). Each carries `brought_from` and `brought_sha256` stamps saying where it came from; a note with an em dash in its name was renamed, and the link to it followed. The story adds an `AGENTS.md` to its own copy of the vault (the repo keeps none): shown as data, it stayed out. |
| **Former residents**: [`former/blake/`](example/contoso-onboarding/former/blake/) | Blake left. His folder moved here whole: his card, his approvals, his weekly-summary instructions, and the copy of his checklist edit kept after a conflict. |
| **Proposed rules**: `members/casey/rules/` | Casey's proposed HIVE.md that lists the old onboarding Hive's id; Avery approved it before it took effect. |
| **The public porch**: [`example/contoso-onboarding-public/`](example/contoso-onboarding-public/) | A separate repository. It holds one reviewed page and `PUBLISHED.md`, which lists its hash. |

The story, journey by journey (J1 to J14), with who signed each step, is in [HISTORY.md](example/HISTORY.md).
Avery creates the Hive and admits Blake alone; Casey needs two, so Blake approves her request first. Both join with the
keys they already had. Casey lists the old onboarding Hive in the rules, with Avery's approval, and carries Emery's
request along. Two members admit Drew and Emery. Apps write tasks in their own shapes. Blake shares how he writes the
weekly summary, and Casey adopts it. Blake edits offline while Casey reorganizes, undoes and redoes. Frankie's forged
push is refused and reset. Avery gets a new laptop and publishes a reviewed page. Blake leaves.

## Try it in three commands

You need Python 3.11 or later and git 2.29 or later.

```sh
python -m pip install "cryptography>=43"
python tools/build_example.py --check
python -m unittest discover -s tests -v
```

The second command replays the whole story on real git repositories in a temporary folder, with a fresh agent instance
for every turn, and checks that it rebuilds `example/` byte for byte. The third runs every journey and every attack from
the review, and checks the commits with stock `git verify-commit` and `ssh-keygen -Y verify`.

## How it fits the Brainstem

A Hive needs one file: [`agents/hive_agent.py`](agents/hive_agent.py), about 2,400 lines and at most 1,300
statements, needing only Python, `cryptography` and git. Copy it into your Brainstem's `agents/` folder. It adds
one tool, **Hive**, and then you talk:

- "Start a Contoso Onboarding Hive." "I'd like to join the Hive at this address." "Let Drew in."
- "What's open this week?" "Save" (after moving files around in Finder or Explorer). "Undo that."
- "Adopt Blake's weekly summary." "Publish our checklist page." "I'm leaving the Hive."

Every change is a proposal first, in plain words. It happens only when you say yes in your next message, as one signed
commit. An edit can be undone by a new signed commit if nothing changed since; a membership or rules change only through
the rules (undoing an admission is a removal); and a publication cannot be recalled from anyone who already copied it.

Text read from a Hive is fenced as quoted data. That makes it harder to steer your AI, not impossible; what holds is that
nothing applies until you confirm the exact plan. Nothing in a Hive is ever run or installed: code you want to use, you
copy into `agents/` yourself, after reading it.

A member is usually a person; a team or an agent with its own keys can be one too. One member has one vote, and a device
is not a member. Each device gets its own key for each Hive, so your Hives cannot be linked. Keys are never committed.
They live in `<hive>/.git/rapp-hive/`, so copying a whole Hive folder, `.git` included, copies the key. Hives live in
their own folder (`RAPP_HIVES`, or `Hives` in your home folder), never inside the Brainstem, its agents or its soul. A
Hive inside a known sync folder is refused. The Brainstem's frozen core is untouched.

The shared copy is a git remote (ssh, https or git) or a folder. A folder shared copy must be a bare git repository:
git runs that copy's side of every push and fetch, so the Brainstem switches off git's known config hooks there. Anyone
who can write the folder can still stall it, but cannot sign as a member.

A reference can also be a Hive's public copy on the web, pinned at one commit (`reference url=`). The Brainstem reads its
PUBLISHED.md and only the files it lists, each checked against its hash, into a cache on this device. For a Hive root
whose stations keep their own member spaces, `resolve` reads each station at the commit its pointer pins, the same way.
Nothing is committed until a member brings a piece in. See [Remote member spaces](HIVE-MD.md#remote-member-spaces).

The same file is the checker, with no Brainstem needed:

```sh
python agents/hive_agent.py check <hive-folder> [--root <commit from the invitation>]
python agents/hive_agent.py check-public <public-copy-folder> [--hive <hive-folder>]
```

## What is here

| Path | What it is |
|---|---|
| [`HIVE-MD.md`](HIVE-MD.md) | The convention, on one page |
| [`agents/hive_agent.py`](agents/hive_agent.py) | The Brainstem agent and the checker |
| [`example/`](example/) | The model home, its public copy and its history |
| [`tools/build_example.py`](tools/build_example.py) | Builds `example/` by talking to the agent through journeys J1 to J13 |
| [`tests/`](tests/) | The tests, and old signed frames from `main` for parity |
| [`MIGRATION.md`](MIGRATION.md) | rapp-hive/2 frozen, old Hives brought along, real Hives |

MIT licensed. See [LICENSE](LICENSE).

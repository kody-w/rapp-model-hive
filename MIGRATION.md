# Migration

## rapp-hive/2 is frozen

This repository's `main` branch, at commit `83e039f`, keeps the rapp-hive/2 model home: its page, tour, vendored
reference engine and conformance vectors. It stays there as a research record. Nothing on `main` changes, and old
clients keep reading it.

This branch replaces that model with a Hive that is a tree of markdown files ([HIVE-MD.md](HIVE-MD.md)). It never
rewrites old records: old signed requests are carried byte for byte, and old keys keep working.

## Bringing old Hives along (J12)

Pin the old Hive's folder as a reference (`reference label=<name> path=<folder>`): it stays in its own shape and is read
only as raw data. Then ask your Brainstem to bring its pending requests along. The `import ref=<name>` action:

1. reads the reference's identity records and RAPP/1 frames;
2. finds the signed join requests: `hive2.join` frames, and `join-request` records from old onboarding scripts;
3. checks each one with RAPP/1's hash and signature math (canonical JSON, particle and wave hashes, detached EdDSA JWS)
   under the key its keyed RAPPID commits to. No signed registry holds those old keys, so this checks the old bytes and
   their key; it does not prove who owned the key;
4. if the old Hive's id is not yet in `HIVE.md` `previous:`, proposes that rules change first. Rules changes need the
   rules' approvals, so the other members approve it before it takes effect;
5. once the id is listed, proposes carrying each request, byte for byte, as `requests/<name>/<device>.md`.

Nobody is admitted by an import. Members admit carried requests exactly like new ones. Anything else of the old Hive
(notes, tasks) stays readable in the reference, and a member can `bring` a piece of it into the Hive by a signed copy
marked with where it came from.

- **Your own old request.** Someone who still holds an old key can carry their own old request while joining (`join`
  with `carry`). In the model, Frankie does this with his pending rapp-hive/2 `hive2.join`, and then signs his commit with
  the same key.
- **A rapp-hive/1 declaration** lists members, but it is not a request anyone signed to join. Its members re-request
  with the same key: `create` and `join` accept an existing Ed25519 key file, so the old key becomes the new ssh-ed25519
  signing key. In the model, Avery creates the Hive with her rapp-hive/1 key, and Blake and Casey join with theirs.
- **What old clients see**: the old Hive, unchanged. The new Hive is a separate repository beside it.

## A real repository-seeded Hive

Nothing here uses real data, and no real Hive is described here. To bring a real repository-seeded Hive along, project
it locally and propose; never migrate it in place:

1. On each member's own machine, each member creates or joins a new Hive with their existing key.
2. The old repository is pinned as a reference on each device, never changed. Signed join requests that are still
   waiting are carried byte for byte with `import ref=`, after the old Hive's id is listed in `previous`; members `bring`
   in the other pieces they want, each marked with where it came from.
3. The members review the result together and admit people by the new rules.
4. Nothing is shared or pushed until every member agrees. The old repository stays readable as it is.

Transport never decides who is a member: a repository, an account or a URL only carries the files. Membership, keys, the
rules and anything that leaves a Hive take effect only through signatures that every Brainstem verifies.

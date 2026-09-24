# History of the model Hive

Every commit of `contoso-onboarding/`, oldest first, as `python agents/hive_agent.py check` judges it: each one is signed by a
key listed in the tree at its parent, and changes only what that tree allows. Built by `tools/build_example.py`.

The keys are public test keys: anyone can re-derive them from their labels, so they prove nothing. Never use them for
real data. Times come from a fixed clock and carry no authority.

| # | Commit | Journey | Signer | Key | What | Verified |
|---|---|---|---|---|---|---|
| 1 | `187c6dbe70` | J1 | avery | `SHA256:q18VTrWDieC+…` | Create the Hive Contoso Onboarding | yes |
| 2 | `250cd19719` | J1 | blake | `SHA256:i2Y91a2TrmTw…` | Ask to join (blake, phone) | yes |
| 3 | `5c8deca9bc` | J1 | casey | `SHA256:VmswiJNYLiLa…` | Ask to join (casey, tablet) | yes |
| 4 | `f5483e8a9b` | J1 | avery | `SHA256:q18VTrWDieC+…` | Admit blake (phone) | yes |
| 5 | `e69c8465fa` | J1 | blake | `SHA256:i2Y91a2TrmTw…` | Approve admit cb3ed039b70f | yes |
| 6 | `eaa5bf1059` | J1 | avery | `SHA256:q18VTrWDieC+…` | Admit casey (tablet) | yes |
| 7 | `bbcd2aa8bb` | J1 | avery | `SHA256:q18VTrWDieC+…` | Save 1 change(s) made by hand | yes |
| 8 | `d20e666e16` | J1 | blake | `SHA256:i2Y91a2TrmTw…` | Save 1 change(s) made by hand | yes |
| 9 | `bdb093acdb` | J1 | casey | `SHA256:VmswiJNYLiLa…` | Save 1 change(s) made by hand | yes |
| 10 | `18048f8c27` | J12 | casey | `SHA256:VmswiJNYLiLa…` | Propose new rules | yes |
| 11 | `178cfbc00c` | J12 | avery | `SHA256:q18VTrWDieC+…` | Approve rules 3d3da9d2f0d5 | yes |
| 12 | `23d3acd520` | J12 | casey | `SHA256:VmswiJNYLiLa…` | Change the rules in HIVE.md | yes |
| 13 | `8224edd5b5` | J12 | casey | `SHA256:VmswiJNYLiLa…` | Carry 1 old join request(s) | yes |
| 14 | `d04a4b313f` | J2 | avery | `SHA256:q18VTrWDieC+…` | Save 4 change(s) made by hand | yes |
| 15 | `cf06e8e13c` | J2 | blake | `SHA256:i2Y91a2TrmTw…` | Save 1 change(s) made by hand | yes |
| 16 | `bfb90ab9bd` | J2 | casey | `SHA256:VmswiJNYLiLa…` | Save 2 change(s) made by hand | yes |
| 17 | `8ee48f89f3` | J3 | drew | `SHA256:exrsXu3WTfmM…` | Ask to join (drew, desktop) | yes |
| 18 | `6d2cee460e` | J4 | casey | `SHA256:VmswiJNYLiLa…` | Approve admit 767e7c19b60e | yes |
| 19 | `2f679201f7` | J4 | avery | `SHA256:q18VTrWDieC+…` | Admit drew (desktop) | yes |
| 20 | `a2f6598654` | J4 | blake | `SHA256:i2Y91a2TrmTw…` | Approve admit 3f9f786a2a62 | yes |
| 21 | `fc1a3ded10` | J4 | casey | `SHA256:VmswiJNYLiLa…` | Admit emery (kiosk) | yes |
| 22 | `aea250d39f` | J4 | frankie | `SHA256:ydV5GSVDnWq4…` | Ask to join (frankie, laptop) | yes |
| 23 | `2f9a9fe442` | J2 | drew | `SHA256:exrsXu3WTfmM…` | Save 1 change(s) made by hand | yes |
| 24 | `068ad6518f` | J2 | emery | `SHA256:BhIR0LQblbmp…` | Save 1 change(s) made by hand | yes |
| 25 | `c3409ace8f` | J13 | blake | `SHA256:i2Y91a2TrmTw…` | Save 1 change(s) made by hand | yes |
| 26 | `cc3b7954b9` | J5, J7 | casey | `SHA256:VmswiJNYLiLa…` | Save 9 change(s) made by hand | yes |
| 27 | `61b5fddeef` | J5, J7 | casey | `SHA256:VmswiJNYLiLa…` | Undo cc3b7954b9: Save 9 change(s) made by hand | yes |
| 28 | `c0c3a82606` | J5, J7 | casey | `SHA256:VmswiJNYLiLa…` | Undo 61b5fddeef: Undo cc3b7954b9: Save 9 change(s) made by hand | yes |
| 29 | `5747102aa7` | J8 | blake | `SHA256:i2Y91a2TrmTw…` | Save 2 change(s) made by hand | yes |
| 30 | `08ffc4bd82` | J10 | avery | `SHA256:6Nm/kTA2gh2Y…` | Ask to join (avery, laptop2) | yes |
| 31 | `4d4b2f5561` | J10 | avery | `SHA256:q18VTrWDieC+…` | Add avery's device laptop2 | yes |
| 32 | `937842a8b3` | J10 | avery | `SHA256:6Nm/kTA2gh2Y…` | Retire avery's device laptop | yes |
| 33 | `54a3da11ef` | J10 | emery | `SHA256:baCLFNtKLEHa…` | Ask to join (emery, phone) | yes |
| 34 | `71fdf185e2` | J10 | emery | `SHA256:BhIR0LQblbmp…` | Add emery's device phone | yes |
| 35 | `edd14537ea` | J10 | emery | `SHA256:baCLFNtKLEHa…` | Retire emery's device kiosk | yes |
| 36 | `d1ea6f6514` | J11 | avery | `SHA256:6Nm/kTA2gh2Y…` | Save shared/public-page/how-contoso-onboards.md | yes |
| 37 | `0edbe8fd10` | J11 | avery | `SHA256:6Nm/kTA2gh2Y…` | Propose publishing 1 file(s) | yes |
| 38 | `c65370370f` | J11 | casey | `SHA256:VmswiJNYLiLa…` | Approve publish 1dcfa66f8a50 | yes |
| 39 | `88fdc3a449` | J6 | blake | `SHA256:i2Y91a2TrmTw…` | blake leaves | yes |

## Refused, never part of the history

Frankie pushed this signed commit straight to the shared copy (J9 a). Avery's Brainstem refused it before checkout, as
any verifying device would, and her reset put the shared copy back to the last verified commit.

| Commit | Written as | Key | Rule |
|---|---|---|---|
| `341cff1e98` | frankie | `SHA256:ydV5GSVDnWq4…` | a key that is not a member's may only add one request under `requests/` |

## The public copy

`contoso-onboarding-public/` is a separate repository. Only a publish that two members approved writes to it (J11).

| Commit | Signer | What |
|---|---|---|
| `b96a20d9e4` | avery | Publish 1 file(s) |

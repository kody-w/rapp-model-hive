# History of the model Hive

Every commit of `contoso-onboarding/`, oldest first, as `python agents/hive_agent.py check` judges it: each one is signed by a
member's key listed in the tree at its parent and changes only what that tree allows, or is one request, signed by the key
it carries. Built by `tools/build_example.py`.

The keys are public test keys: anyone can re-derive them from their labels, so they prove nothing. Never use them for
real data. Times come from a fixed clock and carry no authority.

| # | Commit | Journey | Signer | Key | What | Verified |
|---|---|---|---|---|---|---|
| 1 | `f934db89e0` | J1 | avery | `SHA256:q18VTrWDieC+…` | Create the Hive Contoso Onboarding | yes |
| 2 | `731009af96` | J1 | a request from key SHA256:i2Y91a2TrmTwN/G36n97W2UNrkJyaKU88BgrdI3HXZw (asking as blake) | `SHA256:i2Y91a2TrmTw…` | Ask to join (blake, phone) | yes |
| 3 | `0bcd5d1617` | J1 | a request from key SHA256:VmswiJNYLiLakt3WAtc4FkSC+gOgZfB5zaZ95Piof28 (asking as casey) | `SHA256:VmswiJNYLiLa…` | Ask to join (casey, tablet) | yes |
| 4 | `ffc3b6a6b1` | J1 | avery | `SHA256:q18VTrWDieC+…` | Admit blake (phone) | yes |
| 5 | `7c0e00314d` | J1 | blake | `SHA256:i2Y91a2TrmTw…` | Approve admit cb3ed039b70f | yes |
| 6 | `1bed2f7a48` | J1 | avery | `SHA256:q18VTrWDieC+…` | Admit casey (tablet) | yes |
| 7 | `ab7a74a57d` | J1 | avery | `SHA256:q18VTrWDieC+…` | Save 1 change(s) made by hand | yes |
| 8 | `36e9db95c8` | J1 | blake | `SHA256:i2Y91a2TrmTw…` | Save 1 change(s) made by hand | yes |
| 9 | `8800408bca` | J1 | casey | `SHA256:VmswiJNYLiLa…` | Save 1 change(s) made by hand | yes |
| 10 | `156367aa33` | J12 | casey | `SHA256:VmswiJNYLiLa…` | Propose new rules | yes |
| 11 | `3fb227652f` | J12 | avery | `SHA256:q18VTrWDieC+…` | Approve rules d1a024ae0b88 | yes |
| 12 | `8da32177c9` | J12 | casey | `SHA256:VmswiJNYLiLa…` | Change the rules in HIVE.md | yes |
| 13 | `db0b5cc9a9` | J12 | casey | `SHA256:VmswiJNYLiLa…` | Carry 1 old join request(s) | yes |
| 14 | `9df7737ac2` | J2 | avery | `SHA256:q18VTrWDieC+…` | Save 4 change(s) made by hand | yes |
| 15 | `39bca73d17` | J2 | blake | `SHA256:i2Y91a2TrmTw…` | Save 1 change(s) made by hand | yes |
| 16 | `476c84a243` | J2 | casey | `SHA256:VmswiJNYLiLa…` | Save 2 change(s) made by hand | yes |
| 17 | `4a3090624b` | J3 | a request from key SHA256:exrsXu3WTfmMSAOhUB8mPxOLB0681M4K1fwawEF7Of8 (asking as drew) | `SHA256:exrsXu3WTfmM…` | Ask to join (drew, desktop) | yes |
| 18 | `286973179d` | J4 | casey | `SHA256:VmswiJNYLiLa…` | Approve admit 767e7c19b60e | yes |
| 19 | `a115e81000` | J4 | avery | `SHA256:q18VTrWDieC+…` | Admit drew (desktop) | yes |
| 20 | `3f9b0bcc7c` | J4 | blake | `SHA256:i2Y91a2TrmTw…` | Approve admit 3f9f786a2a62 | yes |
| 21 | `f4dbe819b0` | J4 | casey | `SHA256:VmswiJNYLiLa…` | Admit emery (kiosk) | yes |
| 22 | `4c61967460` | J4 | a request from key SHA256:ydV5GSVDnWq4FuONxxUBtirZZTE/RjmviYy4TRXDNEo (asking as frankie) | `SHA256:ydV5GSVDnWq4…` | Ask to join (frankie, laptop) | yes |
| 23 | `0e1483fa68` | J2 | drew | `SHA256:exrsXu3WTfmM…` | Save 1 change(s) made by hand | yes |
| 24 | `43948b2948` | J2 | emery | `SHA256:BhIR0LQblbmp…` | Save 1 change(s) made by hand | yes |
| 25 | `fa151aa961` | J13 | blake | `SHA256:i2Y91a2TrmTw…` | Save 1 change(s) made by hand | yes |
| 26 | `bb490cb578` | J5, J7 | casey | `SHA256:VmswiJNYLiLa…` | Save 9 change(s) made by hand | yes |
| 27 | `5532028921` | J5, J7 | casey | `SHA256:VmswiJNYLiLa…` | Undo bb490cb578: Save 9 change(s) made by hand | yes |
| 28 | `488e69d887` | J5, J7 | casey | `SHA256:VmswiJNYLiLa…` | Undo 5532028921: Undo bb490cb578: Save 9 change(s) made by hand | yes |
| 29 | `a307a9196d` | J8 | blake | `SHA256:i2Y91a2TrmTw…` | Save 2 change(s) made by hand | yes |
| 30 | `247e27aff8` | J10 | a request from key SHA256:6Nm/kTA2gh2YMe4tXXch56r2982pB4AQ0c4H7kBbnhI (asking as avery) | `SHA256:6Nm/kTA2gh2Y…` | Ask to join (avery, laptop2) | yes |
| 31 | `0de638d60a` | J10 | avery | `SHA256:q18VTrWDieC+…` | Add avery's device laptop2 | yes |
| 32 | `f9808d23a5` | J10 | avery | `SHA256:6Nm/kTA2gh2Y…` | Retire avery's device laptop | yes |
| 33 | `12093a90c0` | J10 | a request from key SHA256:baCLFNtKLEHa9DFUuiFL4Ogl+NRgIWTismWLEtZio1o (asking as emery) | `SHA256:baCLFNtKLEHa…` | Ask to join (emery, phone) | yes |
| 34 | `0c1b42e552` | J10 | emery | `SHA256:BhIR0LQblbmp…` | Add emery's device phone | yes |
| 35 | `f6cf39a55f` | J10 | emery | `SHA256:baCLFNtKLEHa…` | Retire emery's device kiosk | yes |
| 36 | `501ceacdb6` | J11 | avery | `SHA256:6Nm/kTA2gh2Y…` | Save shared/public-page/how-contoso-onboards.md | yes |
| 37 | `b242d1c521` | J11 | avery | `SHA256:6Nm/kTA2gh2Y…` | Propose publishing 1 file(s) | yes |
| 38 | `acef781f6a` | J11 | casey | `SHA256:VmswiJNYLiLa…` | Approve publish 1dcfa66f8a50 | yes |
| 39 | `bd510aa5af` | J6 | blake | `SHA256:i2Y91a2TrmTw…` | blake leaves | yes |

## Refused, never part of the history

Frankie pushed this signed commit straight to the shared copy (J9 a). Avery's Brainstem refused it before checkout, as
any verifying device would, and her reset put the shared copy back to the last verified commit.

| Commit | Written as | Key | Rule |
|---|---|---|---|
| `af469f623c` | frankie | `SHA256:ydV5GSVDnWq4…` | a key that is not a member's may only add one request under `requests/` |

## The public copy

`contoso-onboarding-public/` is a separate repository. Only a publish that two members approved writes to it (J11).

| Commit | Signer | What |
|---|---|---|
| `b96a20d9e4` | avery | Publish 1 file(s) |

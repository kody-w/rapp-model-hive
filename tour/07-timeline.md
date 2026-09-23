# 7. Timeline

Every signed step, in the order every engine processes them.

| When (UTC) | Who | What |
|---|---|---|
| 2026-09-20T09:00:00.000Z | Avery (team lead, laptop) | rapp-hive/1 era: Avery, the one owner, declares the Hive as the first frame of its Mother Hive stream (Blake and Casey are members). |
| 2026-09-20T10:00:00.000Z | Avery (team lead, laptop) | Avery's laptop app writes a task. |
| 2026-09-20T10:30:00.000Z | Blake (field engineer, phone) | Blake's phone app writes a task in its own shape. |
| 2026-09-20T11:00:00.000Z | Emery (front-desk kiosk, joined on the old system) | The old onboarding script records Emery's signed request to join. Nobody has approved it yet. |
| 2026-09-21T09:00:00.000Z | Avery (team lead, laptop) | Migration: the rapp-hive/1 owner accepts the rapp-hive/2 anchor as its steward founder. |
| 2026-09-21T09:05:00.000Z | Blake (field engineer, phone) | Migration: a rapp-hive/1 member joins under the steward policy (it mirrors rapp-hive/1). |
| 2026-09-21T09:10:00.000Z | Casey (designer, tablet) | Migration: a rapp-hive/1 member joins under the steward policy (it mirrors rapp-hive/1). |
| 2026-09-21T09:20:00.000Z | Avery (team lead, laptop) | Migration: the steward grants a rapp-hive/1 member, exactly as before. |
| 2026-09-21T09:20:00.001Z | Avery (team lead, laptop) | Migration: the steward grants a rapp-hive/1 member, exactly as before. |
| 2026-09-21T09:30:00.000Z | Avery (team lead, laptop) | Avery adopts lens contoso-tasks v1 for the laptop app's schema. |
| 2026-09-21T09:31:00.000Z | Avery (team lead, laptop) | Avery adopts lens phone-tasks v1 for the phone app's schema. |
| 2026-09-22T09:00:00.000Z | Avery (team lead, laptop) | The steward hands decisions to the peers: under policy v2 every member decides, and joining needs 2 grants and a confirmed key. |
| 2026-09-22T09:10:00.000Z | Blake (field engineer, phone) | Blake approves Emery's old request, but it was made under policy v1, where only Avery decides: Blake's approval does not count. |
| 2026-09-22T09:12:00.000Z | Avery (team lead, laptop) | Avery approves it: under the rules it was made under, the steward's one approval is enough, so Emery is in. |
| 2026-09-22T09:20:00.000Z | Drew (new analyst, desktop) | Drew's desktop asks to join under policy v2. |
| 2026-09-22T09:25:00.000Z | Casey (designer, tablet) | Casey confirms Drew's key fingerprint on a video call. |
| 2026-09-22T09:30:00.000Z | Avery (team lead, laptop) | Avery grants Drew. |
| 2026-09-22T09:35:00.000Z | Casey (designer, tablet) | Casey grants Drew: two grants and a confirmed key, so Drew is in. |
| 2026-09-22T09:40:00.000Z | Frankie (contractor, still waiting) | Frankie asks to join under policy v2. |
| 2026-09-22T09:45:00.000Z | Blake (field engineer, phone) | Blake confirms Frankie's key in person. |
| 2026-09-22T09:50:00.000Z | Blake (field engineer, phone) | Blake grants Frankie. One more grant is needed. |
| 2026-09-22T09:55:00.000Z | Frankie (contractor, still waiting) | Frankie writes a task with an extra 'invoice' field. It waits in quarantine until Frankie is admitted, and a quarantined message never teaches the Hive a new shape. |
| 2026-09-22T13:00:00.000Z | Avery (team lead, laptop) | Same schema as before: it maps instantly. |
| 2026-09-22T13:10:00.000Z | Avery (team lead, laptop) | The laptop app adds a 'priority' field: a new schema that only adds fields, so lens v2 is learned automatically. |
| 2026-09-22T13:20:00.000Z | Drew (new analyst, desktop) | Drew's desktop uses the updated app; lens v2 maps it. |
| 2026-09-22T13:30:00.000Z | Casey (designer, tablet) | Casey's tablet app renamed 'title' to 'summary': a new schema no lens maps yet. It waits. |
| 2026-09-22T14:00:00.000Z | Casey (designer, tablet) | Casey proposes lens v3: it keeps v2's mapping and adds one for the tablet's schema. |
| 2026-09-22T14:10:00.000Z | Avery (team lead, laptop) | Avery agrees: two peers, the laws hold, lens v3 is active and Casey's task maps. |
| 2026-09-22T14:20:00.000Z | Casey (designer, tablet) | Casey's tablet re-sends its proposal after reconnecting. It is stale (v3 is already active), so nothing changes. |
| 2026-09-22T14:30:00.000Z | Blake (field engineer, phone) | Blake proposes a careless v4 that rewrites every task's owner as 'team'. |
| 2026-09-22T14:40:00.000Z | Drew (new analyst, desktop) | Drew signs it too. Two signatures, but it changes what old tasks mean, so the laws refuse it. |
| 2026-09-22T14:45:00.000Z | Blake (field engineer, phone) | Blake's phone signed its manifest before going offline: consistent, just behind. |
| 2026-09-22T15:00:00.000Z | Blake (field engineer, phone) | Blake's phone starts sending 'reactions': a schema no lens understands yet. Only it waits. |
| 2026-09-22T15:10:00.000Z | Emery (front-desk kiosk, joined on the old system) | Emery's kiosk uses the phone app's schema; lens phone-tasks maps it. |
| 2026-09-22T15:20:00.000Z | Avery (team lead, laptop) | Avery vouches for Blake's key too. Vouching is recorded even after admission. |
| 2026-09-23T09:00:00.000Z | Avery (team lead, laptop) | avery-laptop signs its manifest: same heads, same state. |
| 2026-09-23T09:05:00.000Z | Casey (designer, tablet) | casey-tablet signs its manifest: same heads, same state. |
| 2026-09-23T09:10:00.000Z | Drew (new analyst, desktop) | drew-desktop signs its manifest: same heads, same state. |

## Reads
- Every frame in `../model/hive/streams/`.

## Does
Lists the story.

## Writes
Nothing: this room is generated by `tools/build.py` from the signed frames.

## Human check
Times are what signers declared; order is ascending time, then frame hash.

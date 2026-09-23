"""The Contoso model Hive: a fully synthetic "model home" for rapp-hive/2.

Fictional people and devices, signed with PUBLIC test keys (anyone can re-derive
them from their labels, so they prove nothing). It starts on the current version
(a genuine rapp-hive/1 declaration on its Mother Hive body stream, signed by its
owner, plus an old onboarding request), is migrated with the reference migrator,
and then shows everything rapp-hive/2 does: a steward who alone decides until
co-equal peers take over, grandfathered requests, attested admission, schema
lenses (automatic, authored and refused), quarantine, a new schema waiting for a
lens, crossings, and agreeing manifests.
Deterministic: every build is byte-for-byte identical.
"""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Any

from . import hive, lens as lensmod, migrate, rapp1, schema as schemas, sign

OWNER = "contoso"
WORLD = "contoso-model-hive"
NAME = "Contoso Model Hive"
PEOPLE = {
    "avery-laptop": "Avery (team lead, laptop)",
    "blake-phone": "Blake (field engineer, phone)",
    "casey-tablet": "Casey (designer, tablet)",
    "drew-desktop": "Drew (new analyst, desktop)",
    "emery-kiosk": "Emery (front-desk kiosk, joined on the old system)",
    "frankie-laptop": "Frankie (contractor, still waiting)",
    "contoso-hive": "The rapp-hive/1 Mother Hive stream (its owner, Avery, signs it)",
}
TASKS = "contoso-tasks/1"


def signer(slug: str) -> sign.Signer:
    return sign.Signer(sign.test_key(f"contoso-model-hive/{slug}"), OWNER, slug)


def _task_schema_particle(payload: dict[str, Any]) -> str:
    return schemas.particle(schemas.schema_of({"spec": "rapp/1", "kind": "memory.save", "payload": payload}))


def _objects() -> dict[str, Any]:
    view = lensmod.check_view({
        "schema": lensmod.VIEW,
        "id": "contoso-task",
        "version": 1,
        "fields": {"due": ["null", "string"], "owner": "string", "task_id": "string", "title": "string"},
    })
    laptop_v1 = {"profile": TASKS, "operation": "task", "task_id": "x", "title": "x", "owner": "x", "due": "x"}
    phone_v1 = {"profile": TASKS, "operation": "task", "id": "x", "text": "x", "assignee": "x"}
    laptop_v2 = {**laptop_v1, "priority": "x"}
    tablet_v1 = {"profile": TASKS, "operation": "task", "task_id": "x", "summary": "x", "owner": "x", "due": "x"}
    s_l1, s_p1, s_l2, s_t1 = (_task_schema_particle(item) for item in (laptop_v1, phone_v1, laptop_v2, tablet_v1))
    view_particle = rapp1.particle(view)
    laptop_forward = {"due": {"select": "payload.due"}, "owner": {"select": "payload.owner"}, "task_id": {"select": "payload.task_id"}, "title": {"select": "payload.title"}}
    laptop_reverse = {"due": {"select": "due"}, "operation": {"const": "task"}, "owner": {"select": "owner"}, "profile": {"const": TASKS}, "task_id": {"select": "task_id"}, "title": {"select": "title"}}
    contoso_v1 = lensmod.check_lens({
        "schema": lensmod.LENS, "id": "contoso-tasks", "version": 1, "predecessor": None, "view": view_particle,
        "mappings": [{"accepts": [s_l1], "forward": laptop_forward, "reverse": laptop_reverse}],
    })
    phone_v1_lens = lensmod.check_lens({
        "schema": lensmod.LENS, "id": "phone-tasks", "version": 1, "predecessor": None, "view": view_particle,
        "mappings": [{
            "accepts": [s_p1],
            "forward": {"due": {"const": None}, "owner": {"select": "payload.assignee"}, "task_id": {"select": "payload.id"}, "title": {"select": "payload.text"}},
            "reverse": {"assignee": {"select": "owner"}, "id": {"select": "task_id"}, "operation": {"const": "task"}, "profile": {"const": TASKS}, "text": {"select": "title"}},
        }],
    })
    contoso_v2 = lensmod.additive_successor(contoso_v1, 0, s_l2)
    tablet_mapping = {
        "accepts": [s_t1],
        "forward": {"due": {"select": "payload.due"}, "owner": {"select": "payload.owner"}, "task_id": {"select": "payload.task_id"}, "title": {"select": "payload.summary"}},
        "reverse": {"due": {"select": "due"}, "operation": {"const": "task"}, "owner": {"select": "owner"}, "profile": {"const": TASKS}, "summary": {"select": "title"}, "task_id": {"select": "task_id"}},
    }
    contoso_v3 = lensmod.check_lens({
        "schema": lensmod.LENS, "id": "contoso-tasks", "version": 3, "predecessor": lensmod.reference(contoso_v2), "view": view_particle,
        "mappings": [contoso_v2["mappings"][0], tablet_mapping],
    })
    careless = {**laptop_forward, "owner": {"const": "team"}}
    contoso_v4_bad = lensmod.check_lens({
        "schema": lensmod.LENS, "id": "contoso-tasks", "version": 4, "predecessor": lensmod.reference(contoso_v3), "view": view_particle,
        "mappings": [{**contoso_v3["mappings"][0], "forward": careless}, tablet_mapping],
    })
    return {
        "view": view, "contoso_v1": contoso_v1, "phone_v1": phone_v1_lens, "contoso_v2": contoso_v2, "contoso_v3": contoso_v3, "contoso_v4_bad": contoso_v4_bad,
    }


DEFAULTS = {"migrate_pending": "keep-pinned", "attest_drew": True, "divergent_manifest": False, "adversarial": False, "double_request": False}


def build(**options: Any) -> dict[str, Any]:
    """Build the legacy snapshot and the migrated model; returns {before, hive, story} (files are exact bytes).

    Options produce conformance variants: ``migrate_pending="re-decide"``, ``attest_drew=False``,
    ``divergent_manifest=True`` (a newer divergent manifest on a second stream), ``adversarial=True``
    (signed but malformed or misplaced governance and manifests, refused without effect) and
    ``double_request=True`` (Emery's old script filed twice; admission closes both requests).
    """
    unknown = set(options) - set(DEFAULTS)
    if unknown:
        raise ValueError(f"unknown model options: {sorted(unknown)}")
    options = {**DEFAULTS, **options}
    people = {slug: signer(slug) for slug in PEOPLE}
    avery, blake, casey, drew, emery, frankie, legacy_hive = (people[key] for key in PEOPLE)
    objects = _objects()
    heads: dict[str, dict[str, Any]] = {}
    frames: list[dict[str, Any]] = []
    story: list[dict[str, Any]] = []

    def keep(who: sign.Signer, frame: dict[str, Any], note: str) -> dict[str, Any]:
        heads[frame["stream_id"]] = frame
        frames.append(frame)
        story.append({"utc": frame["utc"], "who": who.slug, "wave": frame["frame_hash"], "note": note})
        return frame

    def write(who: sign.Signer, kind: str, instance: str, payload: dict[str, Any], utc: str, note: str) -> dict[str, Any]:
        return keep(who, who.frame(kind, instance, payload, utc, heads.get(who.stream(instance))), note)

    def body(who: sign.Signer, kind: str, stream: str, payload: dict[str, Any], utc: str, note: str) -> dict[str, Any]:
        return keep(who, who.body_frame(kind, stream, payload, utc, heads.get(stream)), note)

    def task(who: sign.Signer, utc: str, payload: dict[str, Any], note: str) -> dict[str, Any]:
        return write(who, "memory.save", "tasks", {"profile": TASKS, "operation": "task", **payload}, utc, note)

    # ---- The current version: a rapp-hive/1 declaration, tasks, and an old onboarding request.
    member = lambda who, role, area: {"rappid": who.rappid, "role": role, "area": area}  # noqa: E731
    team = sorted([member(avery, "owner", "members/avery"), member(blake, "member", "members/blake"), member(casey, "member", "members/casey")], key=lambda item: item["rappid"])
    declaration = body(avery, "hive.declaration", legacy_hive.rappid, {
        "schema": "rapp-hive/1-declaration",
        "hive_rappid": legacy_hive.rappid,
        "world_id": WORLD,
        "created_utc": "2026-09-20T09:00:00.000Z",
        "authority_channel_id": "model",
        "members": team,
        "rooms": [{"id": "team", "area": "rooms/team", "members": sorted(item["rappid"] for item in team), "access": "repository"}],
        "channels": [{"id": "model", "kind": "local", "role": "authority", "locator": "model-hive/legacy", "writeback": True}],
        "policy": {"godd_sharing": "explicit", "default_godd_scope": "local-only", "external_publication": "disabled", "conflict_mode": "explicit", "default_transfer": "copy"},
    }, "2026-09-20T09:00:00.000Z", "rapp-hive/1 era: Avery, the one owner, declares the Hive as the first frame of its Mother Hive stream (Blake and Casey are members).")
    first_task = task(avery, "2026-09-20T10:00:00.000Z", {"task_id": "T-100", "title": "Draft the onboarding checklist", "owner": "avery", "due": "2026-09-30"}, "Avery's laptop app writes a task.")
    phone_task = task(blake, "2026-09-20T10:30:00.000Z", {"id": "T-101", "text": "Photograph the site walk-through", "assignee": "blake"}, "Blake's phone app writes a task in its own shape.")
    legacy_request = write(emery, "memory.save", "onboarding", {
        "profile": "contoso-onboarding/1", "operation": "join-request", "hive": rapp1.particle(declaration["payload"]), "device": "front-desk kiosk",
    }, "2026-09-20T11:00:00.000Z", "The old onboarding script records Emery's signed request to join. Nobody has approved it yet.")
    legacy_requests = [legacy_request["frame_hash"]]
    if options["double_request"]:
        legacy_requests.append(write(emery, "memory.save", "onboarding", {
            "profile": "contoso-onboarding/1", "operation": "join-request", "hive": rapp1.particle(declaration["payload"]), "device": "front-desk kiosk (retried)",
        }, "2026-09-20T11:05:00.000Z", "The old script retries and records a second signed request from Emery.")["frame_hash"])
    identities = sorted((who.identity() for who in people.values() if who is not legacy_hive), key=lambda item: item["rappid"])
    before = sign.carrier_files(None, [item for item in identities if item["rappid"] in {avery.rappid, blake.rappid, casey.rappid, emery.rappid}], [], frames)

    # ---- Migration (Path A + B) with the reference migrator, each identity signing only its own steps.
    with tempfile.TemporaryDirectory() as scratch:
        folder = Path(scratch) / "hive"
        from . import store

        store.write_new_tree(folder, dict(before))
        carried = hive.load(folder)
        records = hive.verify_frames(carried)
        plan = migrate.plan_from_rapp_hive_1(carried, records, declaration["frame_hash"], name=NAME, legacy_requests=legacy_requests)
        for who, phase, utc in ((avery, 1, "2026-09-21T09:00:00.000Z"), (blake, 1, "2026-09-21T09:05:00.000Z"), (casey, 1, "2026-09-21T09:10:00.000Z"), (avery, 2, "2026-09-21T09:20:00.000Z")):
            migrate.apply(plan, folder, who, phase=phase, utc=utc)
        migrated = hive.load(folder)
        for record in hive.verify_frames(migrated):
            if record.wave not in {frame["frame_hash"] for frame in frames}:
                frames.append(record.frame)
                if record.stream not in heads or record.seq > heads[record.stream]["seq"]:
                    heads[record.stream] = record.frame
                story.append({"utc": record.utc, "who": record.owner.split("/", 1)[1].split(":", 1)[0], "wave": record.wave, "note": {
                    "hive2.accept": "Migration: the rapp-hive/1 owner accepts the rapp-hive/2 anchor as its steward founder.",
                    "hive2.join": "Migration: a rapp-hive/1 member joins under the steward policy (it mirrors rapp-hive/1).",
                    "hive2.grant": "Migration: the steward grants a rapp-hive/1 member, exactly as before.",
                }[record.kind]})
    anchor_object, steward = plan["objects"]
    anchor = plan["anchor"]
    story.sort(key=lambda item: (item["utc"], item["wave"]))

    def governance(who: sign.Signer, kind: str, payload: dict[str, Any], utc: str, note: str) -> dict[str, Any]:
        return write(who, kind, "hive", {"anchor": anchor, **payload}, utc, note)

    def adopt(who: sign.Signer, value: dict[str, Any], predecessor: str | None, utc: str, note: str) -> dict[str, Any]:
        return governance(who, "hive2.adopt", {"schema": "rapp-hive/2-adopt", "object": rapp1.particle(value), "predecessor": predecessor}, utc, note)

    view = objects["view"]
    adopt(avery, objects["contoso_v1"], None, "2026-09-21T09:30:00.000Z", "Avery adopts lens contoso-tasks v1 for the laptop app's schema.")
    adopt(avery, objects["phone_v1"], None, "2026-09-21T09:31:00.000Z", "Avery adopts lens phone-tasks v1 for the phone app's schema.")

    # ---- Co-equal peers; requests already made keep the rules they were made under.
    peers = migrate.co_equal_policy(rapp1.particle(steward), 2, 2, attested=True, data={"carried_from": "rapp-hive/1", "privacy": steward["data"]["privacy"]})
    if options["migrate_pending"] != "keep-pinned":
        peers = hive.check_policy({**peers, "migrate_pending": options["migrate_pending"]})
    adopt(avery, peers, rapp1.particle(steward), "2026-09-22T09:00:00.000Z", "The steward hands decisions to the peers: under policy v2 every member decides, and joining needs 2 grants and a confirmed key.")
    governance(blake, "hive2.grant", {"schema": "rapp-hive/2-grant", "member": emery.rappid, "request": legacy_request["frame_hash"]}, "2026-09-22T09:10:00.000Z", "Blake approves Emery's old request, but it was made under policy v1, where only Avery decides: Blake's approval does not count.")
    governance(avery, "hive2.grant", {"schema": "rapp-hive/2-grant", "member": emery.rappid, "request": legacy_request["frame_hash"]}, "2026-09-22T09:12:00.000Z", "Avery approves it: under the rules it was made under, the steward's one approval is enough, so Emery is in.")
    drew_join = governance(drew, "hive2.join", {"schema": "rapp-hive/2-join", "policy": rapp1.particle(peers)}, "2026-09-22T09:20:00.000Z", "Drew's desktop asks to join under policy v2.")
    if options["attest_drew"]:
        governance(casey, "hive2.attest", {"schema": "rapp-hive/2-attest", "subject": drew.rappid, "claim": hive.KEY_CONFIRMED, "method": "video call"}, "2026-09-22T09:25:00.000Z", "Casey confirms Drew's key fingerprint on a video call.")
    governance(avery, "hive2.grant", {"schema": "rapp-hive/2-grant", "member": drew.rappid, "request": drew_join["frame_hash"]}, "2026-09-22T09:30:00.000Z", "Avery grants Drew.")
    governance(casey, "hive2.grant", {"schema": "rapp-hive/2-grant", "member": drew.rappid, "request": drew_join["frame_hash"]}, "2026-09-22T09:35:00.000Z", "Casey grants Drew: two grants and a confirmed key, so Drew is in.")
    frankie_join = governance(frankie, "hive2.join", {"schema": "rapp-hive/2-join", "policy": rapp1.particle(peers)}, "2026-09-22T09:40:00.000Z", "Frankie asks to join under policy v2.")
    governance(blake, "hive2.attest", {"schema": "rapp-hive/2-attest", "subject": frankie.rappid, "claim": hive.KEY_CONFIRMED, "method": "in person"}, "2026-09-22T09:45:00.000Z", "Blake confirms Frankie's key in person.")
    governance(blake, "hive2.grant", {"schema": "rapp-hive/2-grant", "member": frankie.rappid, "request": frankie_join["frame_hash"]}, "2026-09-22T09:50:00.000Z", "Blake grants Frankie. One more grant is needed.")
    task(frankie, "2026-09-22T09:55:00.000Z", {"task_id": "T-199", "title": "Invoice for week one", "owner": "frankie", "due": "2026-10-01", "invoice": "INV-7"}, "Frankie writes a task with an extra 'invoice' field. It waits in quarantine until Frankie is admitted, and a quarantined message never teaches the Hive a new shape.")

    # ---- Schemas: automatic, authored, refused, waiting.
    task(avery, "2026-09-22T13:00:00.000Z", {"task_id": "T-102", "title": "Book the kickoff room", "owner": "avery", "due": "2026-09-25"}, "Same schema as before: it maps instantly.")
    task(avery, "2026-09-22T13:10:00.000Z", {"task_id": "T-103", "title": "Order badges", "owner": "avery", "due": "2026-09-26", "priority": "high"}, "The laptop app adds a 'priority' field: a new schema that only adds fields, so lens v2 is learned automatically.")
    task(drew, "2026-09-22T13:20:00.000Z", {"task_id": "T-104", "title": "Pull last quarter's numbers", "owner": "drew", "due": "2026-09-29", "priority": "low"}, "Drew's desktop uses the updated app; lens v2 maps it.")
    tablet_task = task(casey, "2026-09-22T13:30:00.000Z", {"task_id": "T-105", "summary": "Sketch the welcome poster", "owner": "casey", "due": "2026-09-27"}, "Casey's tablet app renamed 'title' to 'summary': a new schema no lens maps yet. It waits.")
    adopt(casey, objects["contoso_v3"], rapp1.particle(objects["contoso_v2"]), "2026-09-22T14:00:00.000Z", "Casey proposes lens v3: it keeps v2's mapping and adds one for the tablet's schema.")
    adopt(avery, objects["contoso_v3"], rapp1.particle(objects["contoso_v2"]), "2026-09-22T14:10:00.000Z", "Avery agrees: two peers, the laws hold, lens v3 is active and Casey's task maps.")
    adopt(casey, objects["contoso_v3"], rapp1.particle(objects["contoso_v2"]), "2026-09-22T14:20:00.000Z", "Casey's tablet re-sends its proposal after reconnecting. It is stale (v3 is already active), so nothing changes.")
    adopt(blake, objects["contoso_v4_bad"], rapp1.particle(objects["contoso_v3"]), "2026-09-22T14:30:00.000Z", "Blake proposes a careless v4 that rewrites every task's owner as 'team'.")
    adopt(drew, objects["contoso_v4_bad"], rapp1.particle(objects["contoso_v3"]), "2026-09-22T14:40:00.000Z", "Drew signs it too. Two signatures, but it changes what old tasks mean, so the laws refuse it.")
    behind = {stream: {"seq": frame["seq"], "frame_hash": frame["frame_hash"]} for stream, frame in heads.items()}
    write(blake, "memory.save", "tasks", {"profile": TASKS, "operation": "reaction", "id": "T-100", "emoji": "thumbs-up"}, "2026-09-22T15:00:00.000Z", "Blake's phone starts sending 'reactions': a schema no lens understands yet. Only it waits.")
    task(emery, "2026-09-22T15:10:00.000Z", {"id": "T-106", "text": "Restock visitor badges", "assignee": "emery"}, "Emery's kiosk uses the phone app's schema; lens phone-tasks maps it.")
    governance(avery, "hive2.attest", {"schema": "rapp-hive/2-attest", "subject": blake.rappid, "claim": hive.KEY_CONFIRMED, "method": "in person"}, "2026-09-22T15:20:00.000Z", "Avery vouches for Blake's key too. Vouching is recorded even after admission.")

    # ---- Manifests: three devices agree; Blake's phone was offline and is behind, not forked.
    all_objects = [anchor_object, steward, peers, view, objects["contoso_v1"], objects["phone_v1"], objects["contoso_v3"], objects["contoso_v4_bad"]]
    work = sign.carrier_files(anchor, identities, all_objects, frames)
    with tempfile.TemporaryDirectory() as scratch:
        from . import store

        folder = Path(scratch) / "hive"
        store.write_new_tree(folder, work)
        carried = hive.load(folder)
        records = hive.verify_frames(carried)
        current = {stream: {"seq": frame["seq"], "frame_hash": frame["frame_hash"]} for stream, frame in heads.items()}
        state_now = hive.Evaluation(carried, records, anchor).state_particle
        state_behind = hive.Evaluation(carried, hive._at_heads(records, behind), anchor).state_particle
    for who, utc in ((avery, "2026-09-23T09:00:00.000Z"), (casey, "2026-09-23T09:05:00.000Z"), (drew, "2026-09-23T09:10:00.000Z")):
        write(who, "hive2.manifest", "manifest", {"schema": "rapp-hive/2-manifest", "anchor": anchor, "heads": current, "state": state_now}, utc, f"{who.slug} signs its manifest: same heads, same state.")
    write(blake, "hive2.manifest", "manifest", {"schema": "rapp-hive/2-manifest", "anchor": anchor, "heads": behind, "state": state_behind}, "2026-09-22T14:45:00.000Z", "Blake's phone signed its manifest before going offline: consistent, just behind.")
    if options["divergent_manifest"]:
        write(drew, "hive2.manifest", "manifest-backup", {"schema": "rapp-hive/2-manifest", "anchor": anchor, "heads": current, "state": "0" * 64}, "2026-09-23T09:30:00.000Z", "Drew's backup stream signs a newer manifest claiming a state its heads do not produce: it is Drew's newest, so Drew is divergent.")
    if options["adversarial"]:
        v3 = objects["contoso_v3"]
        relabelled = lensmod.check_lens({**v3, "version": 99, "predecessor": {"id": v3["id"], "version": 98, "particle": rapp1.particle(v3)}})
        all_objects.append(relabelled)
        adopt(blake, relabelled, rapp1.particle(v3), "2026-09-23T10:00:00.000Z", "Blake adopts a copy of lens v3 relabelled v99 with a v98 predecessor: stale, because a successor pins the active version exactly.")
        governance(avery, "hive2.grant", {"schema": "rapp-hive/2-grant", "member": frankie.rappid, "request": []}, "2026-09-23T10:05:00.000Z", "A buggy app signs a grant whose request is a list: refused as malformed; nothing crashes.")
        governance(avery, "hive2.adopt", {"schema": "rapp-hive/2-adopt", "object": {}, "predecessor": None}, "2026-09-23T10:10:00.000Z", "A buggy app signs an adoption whose object is an empty object: refused as malformed.")
        body(avery, "hive2.grant", legacy_hive.rappid, {"schema": "rapp-hive/2-grant", "anchor": anchor, "member": frankie.rappid, "request": frankie_join["frame_hash"]}, "2026-09-23T10:15:00.000Z", "Avery signs a grant onto the old Mother Hive stream: governance on a body stream never counts.")
        write(avery, "hive2.manifest", "manifest", {"schema": "rapp-hive/2-manifest", "anchor": anchor, "heads": {next(iter(current)): {"seq": [], "frame_hash": "0" * 64}}, "state": state_now}, "2026-09-23T10:20:00.000Z", "A buggy manifest names a head whose sequence is a list: unverifiable, and nothing crashes.")
        write(casey, "hive2.manifest", "manifest", {"schema": "not-a-manifest", "anchor": anchor, "heads": current, "state": state_now}, "2026-09-23T10:25:00.000Z", "Casey's newest manifest carries the wrong schema: malformed, whatever it claims.")
        first_drew = next(frame for frame in frames if frame["stream_id"] == drew.stream("manifest") and frame["seq"] == 0)
        write(drew, "hive2.manifest", "manifest", {"schema": "rapp-hive/2-manifest", "anchor": anchor, "heads": {first_drew["stream_id"]: {"seq": 0, "frame_hash": first_drew["frame_hash"]}}, "state": state_now}, "2026-09-23T10:30:00.000Z", "Drew's newest manifest names a manifest as a head: unverifiable, because heads exclude manifests.")
    story.sort(key=lambda item: (item["utc"], item["wave"]))
    files = sign.carrier_files(anchor, identities, all_objects, frames)
    return {
        "before": before,
        "hive": files,
        "anchor": anchor,
        "plan": plan,
        "people": {signer_.rappid: {"slug": slug, "label": PEOPLE[slug]} for slug, signer_ in people.items()},
        "story": story,
        "crossings": [
            {"what": "Blake's phone task, as Avery's laptop app would read it", "source": phone_task["frame_hash"], "member": "avery-laptop"},
            {"what": "Avery's laptop task, as Blake's phone app would read it", "source": first_task["frame_hash"], "member": "blake-phone"},
            {"what": "Casey's tablet task, as Avery's laptop app would read it", "source": tablet_task["frame_hash"], "member": "avery-laptop"},
        ],
    }

"""Migration into rapp-hive/2 (experimental frontier) from the versions people run today.

Nothing is rewritten: legacy frames stay exactly as they are and keep working
with their own engines. A migration is a plan (data anyone can review) plus new
frames that each identity signs with its own key. A signer can only ever apply
its own steps; the tool never signs for anyone else.

Path A  rapp-hive/1 -> rapp-hive/2: the one owner becomes the steward founder and
        the policy mirrors rapp-hive/1 (the steward is its only decider), so nothing
        changes until the steward adopts a co-equal policy successor.
Path B  repository-seeded Hives with signed join requests: the exact requests that
        exist at migration are listed in the anchor and are decided under the
        Hive's first policy, so no request is ever stranded.
Path C  a new Hive: no legacy at all.
"""

from __future__ import annotations

import datetime as _dt
from pathlib import Path
from typing import Any

from . import hive, rapp1, sign, store
from .rapp1 import Refusal

PLAN = "rapp-hive/2-migration-plan"
PLAN_KINDS = ("hive2.accept", "hive2.join", "hive2.grant")


def _format(moment: _dt.datetime) -> str:
    return moment.strftime("%Y-%m-%dT%H:%M:%S.") + f"{moment.microsecond // 1000:03d}Z"


def utc_now() -> str:
    return _format(_dt.datetime.now(_dt.timezone.utc))


def later(utc: str, milliseconds: int) -> str:
    """RAPP UTC plus a few milliseconds: each frame a signer writes in one step gets its own time."""
    if not rapp1.utc_valid(utc):
        raise Refusal("REFUSE_FRAME_TIME", "RAPP/1 requires a real UTC moment with exactly three milliseconds.")
    moment = _dt.datetime.strptime(utc, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=_dt.timezone.utc)
    return _format(moment + _dt.timedelta(milliseconds=milliseconds))


def steward_policy(steward: str, privacy: dict[str, Any] | None = None) -> dict[str, Any]:
    """Version 1 that behaves like rapp-hive/1: the steward alone admits, adopts and changes policy."""
    return hive.check_policy(
        {
            "schema": hive.POLICY,
            "version": 1,
            "predecessor": None,
            "deciders": [steward],
            "admit": {"quorum": 1, "attested": False},
            "change_policy": {"quorum": 1},
            "adopt_lens": {"new": {"quorum": 1}, "additive": "automatic", "successor": {"quorum": 1}},
            "migrate_pending": "keep-pinned",
            "data": {"carried_from": "rapp-hive/1", "privacy": privacy or {}},
        }
    )


def co_equal_policy(predecessor: str | None, version: int, quorum: int, *, attested: bool, data: dict[str, Any] | None = None) -> dict[str, Any]:
    """Peers decide together; requests already pending keep the rules they were made under."""
    return hive.check_policy(
        {
            "schema": hive.POLICY,
            "version": version,
            "predecessor": predecessor,
            "deciders": hive.ALL_MEMBERS,
            "admit": {"quorum": quorum, "attested": attested},
            "change_policy": {"quorum": quorum},
            "adopt_lens": {"new": {"quorum": 1}, "additive": "automatic", "successor": {"quorum": quorum}},
            "migrate_pending": "keep-pinned",
            "data": data or {},
        }
    )


def _plan(source: str, anchor: dict[str, Any], policy: dict[str, Any], steps: list[dict[str, Any]], notes: list[str]) -> dict[str, Any]:
    anchor_particle = rapp1.particle(hive.check_anchor(anchor))
    body = {
        "schema": PLAN,
        "from": source,
        "anchor": anchor_particle,
        "objects": [anchor, policy],
        "steps": steps,
        "notes": notes,
        "reversible": "Stop using the rapp-hive/2 frames; every legacy frame and engine is untouched.",
    }
    return {**body, "plan_particle": rapp1.particle(body)}


def _draft(kind: str, payload: dict[str, Any]) -> dict[str, Any]:
    return {"kind": kind, "instance": "hive", "payload": payload}


def plan_from_rapp_hive_1(carried: hive.Carried, records: list[hive.Record], declaration: str, *, name: str, legacy_requests: list[str] | None = None) -> dict[str, Any]:
    """Path A. ``declaration`` is the frame hash of the verified rapp-hive/1 declaration to carry over."""
    record = next((item for item in records if item.wave == declaration), None)
    if record is None:
        raise Refusal("REFUSE_LEGACY", "Name a verified rapp-hive/1 declaration frame.")
    declared = hive.check_legacy_declaration(record)
    owners, members, viewers = [declared["owner"]], [item for item in declared["members"] if item != declared["owner"]], declared["viewers"]
    policy = steward_policy(declared["owner"], declared["privacy"])
    policy_particle = rapp1.particle(policy)
    anchor = {
        "schema": hive.ANCHOR,
        "name": name,
        "world_id": declared["world_id"],
        "founders": owners,
        "policy": policy_particle,
        "legacy": {"from": "rapp-hive/1", "declaration": declaration, "join": {"requests": sorted(legacy_requests)} if legacy_requests else None},
    }
    anchor_particle = rapp1.particle(anchor)
    steps = [{"signer": owners[0], "phase": 1, "drafts": [_draft("hive2.accept", {"schema": "rapp-hive/2-accept", "anchor": anchor_particle})]}]
    for member in members:
        steps.append({"signer": member, "phase": 1, "drafts": [_draft("hive2.join", {"schema": "rapp-hive/2-join", "anchor": anchor_particle, "policy": policy_particle})]})
    if members:
        steps.append({
            "signer": owners[0],
            "phase": 2,
            "drafts": [_draft("hive2.grant", {"schema": "rapp-hive/2-grant", "anchor": anchor_particle, "member": member, "request": {"join_of": member}}) for member in members],
        })
    notes = [
        "The rapp-hive/1 owner becomes the steward founder; the version 1 policy names the steward as its only decider, exactly like rapp-hive/1.",
        "Members keep their membership by joining and being granted by the steward; no one signs for anyone else.",
        "Rooms, sealed eggs, GODD slices and the rapp-hive/1 privacy policy are unchanged; the policy's data carries the privacy settings.",
        "When the members are ready, a co-equal policy successor (keep-pinned) moves decisions to peer quorum without stranding pending requests.",
    ]
    if viewers:
        notes.append(f"{len(viewers)} viewer identities are not admitted as members; they can still read carried copies.")
    return _plan("rapp-hive/1", anchor, policy, steps, notes)


def plan_from_join_requests(records: list[hive.Record], *, name: str, world_id: str, founders: list[str], requests: list[str], quorum: int, source: str) -> dict[str, Any]:
    """Path B. The exact legacy request frames are listed; founders accept, then approve each request they vouch for."""
    by_wave = {item.wave: item for item in records}
    if any(wave not in by_wave for wave in requests):
        raise Refusal("REFUSE_LEGACY", "Every carried-over request must be a verified frame.")
    founders = sorted(set(founders))
    policy = co_equal_policy(None, 1, quorum, attested=False, data={"carried_from": source})
    policy_particle = rapp1.particle(policy)
    anchor = {
        "schema": hive.ANCHOR,
        "name": name,
        "world_id": world_id,
        "founders": founders,
        "policy": policy_particle,
        "legacy": {"from": source, "declaration": None, "join": {"requests": sorted(requests)}},
    }
    anchor_particle = rapp1.particle(anchor)
    steps = [{"signer": founder, "phase": 1, "drafts": [_draft("hive2.accept", {"schema": "rapp-hive/2-accept", "anchor": anchor_particle})]} for founder in founders]
    for founder in founders:
        steps.append({
            "signer": founder,
            "phase": 2,
            "optional": True,
            "drafts": [
                _draft("hive2.grant", {"schema": "rapp-hive/2-grant", "anchor": anchor_particle, "member": by_wave[wave].owner, "request": wave})
                for wave in sorted(requests)
            ],
        })
    notes = [
        f"{len(requests)} signed requests made on the old system are carried over exactly and decided under this Hive's first policy.",
        "Each founder signs only the approvals they vouch for; no one-owner override exists.",
    ]
    return _plan(source, anchor, policy, steps, notes)


def check_plan(plan: Any) -> dict[str, Any]:
    """A plan is data from someone else: it must reproduce its particle and may only ask for governance of its own anchor."""
    if type(plan) is not dict or plan.get("schema") != PLAN:
        raise Refusal("REFUSE_TAMPER", "This is not a rapp-hive/2 migration plan.")
    body = {key: value for key, value in plan.items() if key != "plan_particle"}
    if rapp1.particle(body) != plan.get("plan_particle"):
        raise Refusal("REFUSE_TAMPER", "The migration plan does not reproduce its particle.")
    objects, steps = plan.get("objects"), plan.get("steps")
    if type(objects) is not list or len(objects) != 2 or type(steps) is not list or not steps:
        raise Refusal("REFUSE_TAMPER", "A plan carries its anchor, its policy and its steps.")
    anchor, policy = objects
    hive.check_anchor(anchor)
    hive.check_policy(policy)
    if rapp1.particle(anchor) != plan.get("anchor") or anchor["policy"] != rapp1.particle(policy):
        raise Refusal("REFUSE_TAMPER", "The plan's anchor and policy do not match.")
    for step in steps:
        if type(step) is not dict or not {"signer", "phase", "drafts"} <= set(step) <= {"signer", "phase", "drafts", "optional"}:
            raise Refusal("REFUSE_TAMPER", "A plan step is {signer, phase, drafts} (optionally optional).")
        rapp1.check_rappid(step["signer"])
        if type(step["phase"]) is not int or step["phase"] < 1 or type(step.get("optional", False)) is not bool or type(step["drafts"]) is not list or not step["drafts"]:
            raise Refusal("REFUSE_TAMPER", "A plan step has a positive phase and at least one draft.")
        for draft in step["drafts"]:
            if type(draft) is not dict or set(draft) != {"kind", "instance", "payload"} or draft["kind"] not in PLAN_KINDS or draft["instance"] != "hive":
                raise Refusal("REFUSE_TAMPER", "A plan only drafts accept, join and grant frames on the hive stream.")
            if type(draft["payload"]) is not dict or draft["payload"].get("anchor") != plan["anchor"]:
                raise Refusal("REFUSE_TAMPER", "Every drafted frame names the plan's own anchor.")
    return plan


def _resolve(payload: dict[str, Any], records: list[hive.Record], anchor: str) -> dict[str, Any] | None:
    """A draft's exact payload; ``{"join_of": R}`` becomes R's newest join frame for this anchor (None until R has joined)."""
    request = payload.get("request")
    if type(request) is dict and set(request) == {"join_of"}:
        joins = [item for item in records if item.kind == "hive2.join" and not item.legacy and item.owner == request["join_of"] and item.frame["payload"].get("anchor") == anchor]
        return {**payload, "request": joins[-1].wave} if joins else None
    return dict(payload)


def _applied(step: dict[str, Any], records: list[hive.Record], anchor: str, refused: set[str]) -> list[hive.Record] | None:
    """The effective frames that carry every draft of the step (signed by its signer on its own stream), or None."""
    found = []
    for draft in step["drafts"]:
        payload = _resolve(draft["payload"], records, anchor)
        match = None if payload is None else next(
            (item for item in records if item.owner == step["signer"] and not item.legacy and item.kind == draft["kind"] and item.wave not in refused and rapp1.json_equal(item.frame["payload"], payload)),
            None,
        )
        if match is None:
            return None
        found.append(match)
    return found


def apply(plan: dict[str, Any], folder: Path, signer: sign.Signer, *, phase: int, utc: str) -> list[str]:
    """Sign and add this signer's own drafts for one phase. Existing files are never overwritten."""
    check_plan(plan)
    carried = hive.load(Path(folder))
    records = hive.verify_frames(carried)
    if carried.anchor not in (None, plan["anchor"]):
        raise Refusal("REFUSE_CONFLICT", "This folder already carries a different Hive.")
    steps = [step for step in plan["steps"] if step["phase"] == phase and step["signer"] == signer.rappid]
    if not steps:
        raise Refusal("REFUSE_NOT_YOURS", "This plan has no steps for this identity in that phase.")
    refused: set[str] = set()
    if plan["anchor"] in carried.objects:
        refused = {item["wave"] for item in hive.Evaluation(carried, records, plan["anchor"]).refusals}
    earlier = [_applied(step, records, plan["anchor"], refused) for step in plan["steps"] if step["phase"] < phase and not step.get("optional", False)]
    if any(found is None for found in earlier):
        raise Refusal("REFUSE_ORDER", "Every earlier phase must be applied (and in effect) first.")
    if all(_applied(step, records, plan["anchor"], refused) is not None for step in steps):
        raise Refusal("REFUSE_ALREADY_APPLIED", "These steps are already signed, carried and in effect.")
    floor = max((item.utc for found in earlier for item in found), default=None)
    if floor is not None and later(utc, 0) <= floor:
        raise Refusal("REFUSE_FRAME_TIME", f"Sign these steps after the steps they depend on (after {floor}).")
    heads: dict[str, dict[str, Any]] = {}
    for record in records:
        if record.stream.startswith(signer.rappid + ":") and (record.stream not in heads or record.seq > heads[record.stream]["seq"]):
            heads[record.stream] = record.frame
    frames = []
    drafts = [draft for step in steps for draft in step["drafts"]]
    for offset, draft in enumerate(drafts):
        payload = _resolve(draft["payload"], records, plan["anchor"])
        if payload is None:
            raise Refusal("REFUSE_ORDER", "That member has not signed their join request yet (apply phase 1 first).")
        stream = signer.stream(draft["instance"])
        previous = heads.get(stream)
        moment = later(utc, offset)
        if previous is not None and moment < previous["utc"]:
            raise Refusal("REFUSE_FRAME_TIME", "A new frame cannot be older than its stream's head.")
        frame = signer.frame(draft["kind"], draft["instance"], payload, moment, previous)
        heads[stream] = frame
        frames.append(frame)
    anchor, policy = plan["objects"]
    files = sign.carrier_files(None, [signer.identity()], [anchor, policy], frames)
    fresh: dict[str, bytes] = {}
    for path, data in files.items():
        try:
            existing = store.read_inside(Path(folder), path, limit=hive.MAX_OBJECT_BYTES)
        except Refusal as error:
            if error.code != "REFUSE_FOLDER_INCOMPLETE":
                raise
            fresh[path] = data
            continue
        if existing != data:
            raise Refusal("REFUSE_CONFLICT", f"{path} already exists with different bytes.")
    if carried.anchor is None:
        fresh["HIVE.json"] = rapp1.canonical({"schema": "rapp-hive/2-carrier", "anchor": plan["anchor"]})
    store.write_new_tree(Path(folder), fresh, require_empty=False)
    return sorted(fresh)

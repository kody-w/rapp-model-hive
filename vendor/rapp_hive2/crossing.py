"""Crossing dimensions: one member's message in another member's schema, through a shared view.

Forward through the message's own lens, then back through the newest lens version
whose reverse mapping reproduces the target schema exactly. The result is an
unsigned proposal: it names what could not cross and never invents a field; only
the receiving owner can sign it into their own stream.
"""

from __future__ import annotations

from typing import Any

from . import lens as lensmod, rapp1, schema as schemas
from .hive import Evaluation
from .rapp1 import Refusal

CROSSING = "rapp-hive/2-crossing"


def _leaves(value: Any, at: tuple[Any, ...]) -> set[tuple[Any, ...]]:
    node = value
    for part in at:
        node = node[part]
    if type(node) is dict and node:
        return set().union(*(_leaves(value, at + (key,)) for key in node))
    return {at}


def _covered(leaf: tuple[Any, ...], used: set[tuple[Any, ...]]) -> bool:
    return any(leaf[: len(path)] == path for path in used)


def dropped_fields(payload: dict[str, Any], used: set[tuple[Any, ...]]) -> list[str]:
    """Source payload leaves the forward render did not actually read (string tags are matched by the schema)."""
    leaves: set[tuple[Any, ...]] = set()
    for key in payload:
        if key in schemas.TAG_KEYS and type(payload[key]) is str:
            continue
        leaves |= _leaves(payload, (key,))
    return sorted(".".join(str(part) for part in leaf) for leaf in leaves if not _covered(("payload", *leaf), used))


def cross(evaluation: Evaluation, source_wave: str, target_schema: str) -> dict[str, Any]:
    entry = next((item for item in evaluation.views if item["source"] == source_wave), None)
    if entry is None:
        raise Refusal("REFUSE_CROSSING", "Only a mapped message of a member can cross.")
    record = next(item for item in evaluation.content if item.wave == source_wave)
    source_lens = evaluation.lens_objects[entry["lens"]["particle"]]
    index = lensmod.mapping_for(source_lens, entry["schema"])
    view = evaluation._view(source_lens)
    forward_trace = lensmod.new_trace()
    value, view_particle = lensmod.forward(source_lens, index, record.frame, view, forward_trace)
    target = evaluation.schemas.get(target_schema)
    if target is None:
        raise Refusal("REFUSE_CROSSING", "The target schema is not known to this Hive.")
    fits: dict[str, tuple[dict[str, Any], dict[str, Any], dict[str, Any]]] = {}
    for particle in sorted(evaluation.history, key=lambda item: (evaluation.lens_objects[item]["id"], -evaluation.lens_objects[item]["version"])):
        candidate = evaluation.lens_objects[particle]
        if candidate["id"] in fits or candidate["view"] != source_lens["view"]:
            continue
        target_index = lensmod.mapping_for(candidate, target_schema)
        if target_index is None:
            continue
        backward = lensmod.new_trace()
        try:
            payload = lensmod.reverse(candidate, target_index, value, backward)
        except lensmod.LensExhaust:
            continue
        envelope = {"spec": target["spec"], "kind": target["kind"], "payload": payload}
        if schemas.particle(schemas.schema_of(envelope)) == target_schema:
            fits[candidate["id"]] = (candidate, payload, backward)
    if len(fits) > 1:
        raise Refusal("REFUSE_LENS_COLLISION", "More than one lens can express this message in the target schema; refusing to guess.")
    if not fits:
        raise Refusal("REFUSE_CROSSING", "No lens version expresses this message in the target schema exactly; the Hive will not invent missing fields.")
    candidate, payload, backward = next(iter(fits.values()))
    produced = set().union(*(_leaves(value, at) for at in forward_trace["produced"])) if forward_trace["produced"] else set()
    missing = sorted(".".join(str(part) for part in leaf) for leaf in produced if not _covered(leaf, backward["used"]))
    dropped = dropped_fields(record.frame["payload"], forward_trace["used"])
    return {
        "schema": CROSSING,
        "authority": False,
        "signed": False,
        "from": {"source": source_wave, "owner": record.owner, "schema": entry["schema"]},
        "to_schema": target_schema,
        "through": {"forward": lensmod.reference(source_lens), "view": view_particle, "reverse": lensmod.reference(candidate)},
        "payload": payload,
        "payload_particle": rapp1.particle(payload),
        "dropped_by_forward_lens": dropped,
        "not_expressible_in_target": missing,
        "lossless": not dropped and not missing,
        "note": "An unsigned proposal in the target schema; only the receiving owner can sign it.",
    }


def cross_to_member(evaluation: Evaluation, source: str, member: str) -> dict[str, Any]:
    """Cross a message (8+ hex of its wave or particle) into the newest schema a member writes."""
    needle = source.strip().lower()
    if len(needle) < 8:
        raise Refusal("REFUSE_UNKNOWN_TARGET", "Name the message by at least 8 hex characters.")
    found = [item for item in (*evaluation.content, *evaluation.quarantine) if item.wave.startswith(needle) or item.particle.startswith(needle)]
    if len(found) != 1:
        raise Refusal("REFUSE_UNKNOWN_TARGET", "That names no carried message, or more than one.")
    owners = [rappid for rappid in evaluation.members if rappid == member or rappid.split("/", 1)[1].split(":", 1)[0] == member]
    if len(owners) != 1:
        raise Refusal("REFUSE_UNKNOWN_TARGET", "Name the receiving member by RAPPID or slug.")
    targets: list[str] = []
    for record in reversed(evaluation.content):
        if record.owner == owners[0]:
            particle = evaluation._schema(record)
            if particle not in targets:
                targets.append(particle)
    last: Refusal | None = None
    for target in targets:
        try:
            return cross(evaluation, found[0].wave, target)
        except Refusal as error:
            last = error
    raise last or Refusal("REFUSE_CROSSING", "The receiving member has written nothing to cross into.")

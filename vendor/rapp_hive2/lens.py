"""rapp-hive/2 views and lenses: declarative data that maps schemas into a shared view and back.

A lens never runs code. Each mapping names the exact schema particles it
accepts, a ``forward`` expression from a message payload into the view, and an
optional ``reverse`` expression from the view back into that schema.
"""

from __future__ import annotations

import copy
import re
from typing import Any

from . import rapp1, schema as schemas
from .rapp1 import Refusal

VIEW = "rapp-hive/2-view"
LENS = "rapp-hive/2-lens"
TYPES = ("array", "boolean", "integer", "null", "object", "string")
ID_RE = re.compile(r"[a-z0-9]+(?:[-./][a-z0-9]+)*\Z")
HEX_RE = re.compile(r"[0-9a-f]{64}\Z")


class LensExhaust(Exception):
    """A lens could not map a message. Retryable: it can teach a successor."""

    def __init__(self, code: str, locus: str, detail: dict[str, Any] | None = None) -> None:
        super().__init__(f"{code} at {locus}")
        self.code, self.locus, self.detail = code, locus, detail or {}


def _identifier(value: Any, what: str) -> str:
    if type(value) is not str or not 0 < len(value) <= 100 or ID_RE.fullmatch(value) is None:
        raise Refusal("REFUSE_LENS", f"{what} must be a lowercase identifier.")
    return value


def _version(value: Any, what: str) -> int:
    if type(value) is not int or not 1 <= value <= rapp1.MAX_SAFE_INTEGER:
        raise Refusal("REFUSE_LENS", f"{what} must be a positive integer.")
    return value


def _particles(value: Any, what: str) -> list[str]:
    if type(value) is not list or not value or any(type(item) is not str or HEX_RE.fullmatch(item) is None for item in value):
        raise Refusal("REFUSE_LENS", f"{what} must be a nonempty list of particles.")
    if value != sorted(set(value)):
        raise Refusal("REFUSE_LENS", f"{what} must be sorted and unique.")
    return value


def json_type(value: Any) -> str:
    if type(value) is dict:
        return "object"
    if type(value) is list:
        return "array"
    return schemas.shape(value)


def check_view(view: Any) -> dict[str, Any]:
    if type(view) is not dict or set(view) != {"schema", "id", "version", "fields"} or view["schema"] != VIEW:
        raise Refusal("REFUSE_LENS", "A view is exactly {schema, id, version, fields}.")
    _identifier(view["id"], "view.id")
    _version(view["version"], "view.version")
    fields = view["fields"]
    if type(fields) is not dict or not fields:
        raise Refusal("REFUSE_LENS", "A view declares at least one field.")
    for name, allowed in fields.items():
        options = allowed if type(allowed) is list else [allowed]
        if not options or any(type(option) is not str or option not in TYPES for option in options) or options != sorted(set(options)) or (type(allowed) is list and len(options) < 2):
            raise Refusal("REFUSE_LENS", f"view.fields.{name} must be a type name or a sorted list of two or more.")
    return view


def conforms(value: Any, view: dict[str, Any]) -> bool:
    fields = view["fields"]
    if type(value) is not dict or set(value) != set(fields):
        return False
    return all(json_type(value[name]) in (allowed if type(allowed) is list else [allowed]) for name, allowed in fields.items())


def _check_expression(expression: Any, *, prefix: str | None, where: str) -> None:
    if type(expression) is dict and set(expression) == {"first"}:
        options = expression["first"]
        if type(options) is not list or not options:
            raise Refusal("REFUSE_LENS", f"'first' needs a nonempty list (at {where}).")
        for index, option in enumerate(options):
            _check_expression(option, prefix=prefix, where=f"{where}.first[{index}]")
        return
    if type(expression) is dict and set(expression) == {"select"}:
        path = expression["select"]
        if type(path) is not str or not path or any(part == "" for part in path.split(".")):
            raise Refusal("REFUSE_LENS", f"Invalid select path at {where}.")
        if prefix is not None and path != prefix and not path.startswith(prefix + "."):
            raise Refusal("REFUSE_LENS", f"Forward mappings may only select {prefix}.* (at {where}).")
        return
    if type(expression) is dict and set(expression) == {"const"}:
        rapp1.canonical(expression["const"])
        return
    if type(expression) is dict:
        for key, value in expression.items():
            _check_expression(value, prefix=prefix, where=f"{where}.{key}")
        return
    if type(expression) is list:
        for index, value in enumerate(expression):
            _check_expression(value, prefix=prefix, where=f"{where}[{index}]")
        return
    raise Refusal("REFUSE_LENS", f"Lens leaves must be explicit select/const expressions (at {where}).")


def check_lens(lens: Any) -> dict[str, Any]:
    keys = {"schema", "id", "version", "predecessor", "view", "mappings"}
    if type(lens) is not dict or set(lens) != keys or lens["schema"] != LENS:
        raise Refusal("REFUSE_LENS", "A lens is exactly {schema, id, version, predecessor, view, mappings}.")
    lens_id = _identifier(lens["id"], "lens.id")
    version = _version(lens["version"], "lens.version")
    predecessor = lens["predecessor"]
    if version == 1:
        if predecessor is not None:
            raise Refusal("REFUSE_LENS", "Version 1 of a lens has no predecessor.")
    elif (
        type(predecessor) is not dict
        or set(predecessor) != {"id", "version", "particle"}
        or predecessor["id"] != lens_id
        or type(predecessor["version"]) is not int
        or predecessor["version"] != version - 1
        or type(predecessor["particle"]) is not str
        or HEX_RE.fullmatch(predecessor["particle"]) is None
    ):
        raise Refusal("REFUSE_LENS", "A successor pins its exact predecessor {id, version, particle}.")
    if type(lens["view"]) is not str or HEX_RE.fullmatch(lens["view"]) is None:
        raise Refusal("REFUSE_LENS", "lens.view is the particle of a view.")
    mappings = lens["mappings"]
    if type(mappings) is not list or not mappings:
        raise Refusal("REFUSE_LENS", "A lens has at least one mapping.")
    seen: set[str] = set()
    for index, mapping in enumerate(mappings):
        if type(mapping) is not dict or set(mapping) != {"accepts", "forward", "reverse"}:
            raise Refusal("REFUSE_LENS", f"mappings[{index}] is exactly {{accepts, forward, reverse}}.")
        accepts = _particles(mapping["accepts"], f"mappings[{index}].accepts")
        if seen & set(accepts):
            raise Refusal("REFUSE_LENS", "A schema is accepted by at most one mapping of a lens.")
        seen |= set(accepts)
        _check_expression(mapping["forward"], prefix="payload", where=f"mappings[{index}].forward")
        if type(mapping["forward"]) is not dict or set(mapping["forward"]) & {"select", "const", "first"} == set(mapping["forward"]):
            raise Refusal("REFUSE_LENS", "A forward mapping builds a view object.")
        if mapping["reverse"] is not None:
            _check_expression(mapping["reverse"], prefix=None, where=f"mappings[{index}].reverse")
    return lens


def reference(lens: dict[str, Any]) -> dict[str, Any]:
    return {"id": lens["id"], "version": lens["version"], "particle": rapp1.particle(lens)}


def new_trace() -> dict[str, set[tuple[Any, ...]]]:
    """What a render actually used: select paths read (``used``) and where they landed (``produced``)."""
    return {"used": set(), "produced": set()}


def _select(value: Any, path: str) -> Any:
    current = value
    for part in path.split("."):
        if type(current) is not dict or part not in current:
            raise LensExhaust("missing-field", path, {"missing": part})
        current = current[part]
    return current


def render(expression: Any, scope: Any, trace: dict[str, set[tuple[Any, ...]]] | None = None, at: tuple[Any, ...] = ()) -> Any:
    if type(expression) is dict and set(expression) == {"first"}:
        last: LensExhaust | None = None
        for option in expression["first"]:
            attempt = None if trace is None else new_trace()
            try:
                value = render(option, scope, attempt, at)
            except LensExhaust as error:
                last = error
                continue
            if trace is not None and attempt is not None:
                trace["used"] |= attempt["used"]
                trace["produced"] |= attempt["produced"]
            return value
        assert last is not None
        raise last
    if type(expression) is dict and set(expression) == {"select"}:
        value = copy.deepcopy(_select(scope, expression["select"]))
        if trace is not None:
            trace["used"].add(tuple(expression["select"].split(".")))
            trace["produced"].add(at)
        return value
    if type(expression) is dict and set(expression) == {"const"}:
        return copy.deepcopy(expression["const"])
    if type(expression) is dict:
        return {key: render(expression[key], scope, trace, at + (key,)) for key in rapp1.utf16_sorted(expression)}
    if type(expression) is list:
        return [render(value, scope, trace, at + (index,)) for index, value in enumerate(expression)]
    raise Refusal("REFUSE_LENS", "Invalid lens expression.")


def mapping_for(lens: dict[str, Any], schema_particle: str) -> int | None:
    for index, mapping in enumerate(lens["mappings"]):
        if schema_particle in mapping["accepts"]:
            return index
    return None


def forward(lens: dict[str, Any], index: int, frame: dict[str, Any], view: dict[str, Any], trace: dict[str, set[tuple[Any, ...]]] | None = None) -> tuple[dict[str, Any], str]:
    """Map one message into the view; the result must conform to the view's declared fields."""
    value = render(lens["mappings"][index]["forward"], {"payload": frame["payload"]}, trace)
    if not conforms(value, view):
        raise LensExhaust("view-shape", "forward", {"view": view["id"]})
    return value, rapp1.particle(value)


def reverse(lens: dict[str, Any], index: int, value: dict[str, Any], trace: dict[str, set[tuple[Any, ...]]] | None = None) -> dict[str, Any]:
    expression = lens["mappings"][index]["reverse"]
    if expression is None:
        raise LensExhaust("no-reverse", f"mappings[{index}].reverse")
    payload = render(expression, value, trace)
    if type(payload) is not dict:
        raise LensExhaust("no-reverse", f"mappings[{index}].reverse", {"reason": "not an object"})
    return payload


def _selects(expression: Any) -> list[str]:
    if type(expression) is dict and set(expression) == {"first"}:
        return [path for option in expression["first"] for path in _selects(option)]
    if type(expression) is dict and set(expression) == {"select"}:
        return [expression["select"]]
    if type(expression) is dict and set(expression) == {"const"}:
        return []
    if type(expression) is dict:
        return [path for value in expression.values() for path in _selects(value)]
    if type(expression) is list:
        return [path for value in expression for path in _selects(value)]
    return []


def loss(lens: dict[str, Any], index: int, schema: dict[str, Any]) -> dict[str, list[str]]:
    """Which payload fields a mapping may carry, only matches on (tags), or always drops: a property of the
    schema alone. A field read only by an untaken ``first`` branch counts as carried here; crossings report
    what one message actually lost from the forward trace instead."""
    selects = _selects(lens["mappings"][index]["forward"])
    present = set(schema["payload"])
    referenced = set(present) if "payload" in selects else {path.split(".")[1] for path in selects if path.startswith("payload.")}
    matched = set(schemas.TAG_KEYS) & present - referenced
    return {
        "carried": sorted(referenced & present),
        "matched": sorted(matched),
        "dropped": sorted(present - referenced - matched),
    }


def additive_successor(lens: dict[str, Any], index: int, schema_particle: str) -> dict[str, Any]:
    """Deterministic: the same lens, one version up, whose mapping also accepts an additive schema."""
    mappings = copy.deepcopy(lens["mappings"])
    mappings[index]["accepts"] = sorted({*mappings[index]["accepts"], schema_particle})
    return check_lens(
        {
            "schema": LENS,
            "id": lens["id"],
            "version": lens["version"] + 1,
            "predecessor": reference(lens),
            "view": lens["view"],
            "mappings": mappings,
        }
    )

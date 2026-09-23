"""rapp-hive/2 reference command line (experimental frontier).

    python3 -m rapp_hive2 verify <folder> [--anchor P]      the derived verdict (JSON)
    python3 -m rapp_hive2 status <folder>                   plain language
    python3 -m rapp_hive2 cross <folder> <message> <member> an unsigned crossing proposal
    python3 -m rapp_hive2 model <new-folder>                build the synthetic Contoso model Hive
    python3 -m rapp_hive2 migrate plan-hive1 <folder> --declaration H --name N [--legacy-request H ...] --out plan.json
    python3 -m rapp_hive2 migrate plan-joins <folder> --name N --world W --founder R ... --request H ... --quorum K --from LABEL --out plan.json
    python3 -m rapp_hive2 migrate apply <folder> <plan.json> --key key.pem --owner O --slug S --phase N [--utc U]
    python3 -m rapp_hive2 vectors (--write PATH | --check PATH)
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from . import crossing, hive, migrate, model, rapp1, sign, store, vectors
from .rapp1 import Refusal


def _print(value: Any) -> None:
    sys.stdout.write(json.dumps(value, indent=2, ensure_ascii=False) + "\n")


def _short(rappid: str) -> str:
    return rappid.split("/", 1)[1].split(":", 1)[0] if rappid.startswith("rappid:@") else rappid[:16]


def status_lines(evaluation: hive.Evaluation, verdict: dict[str, Any]) -> list[str]:
    anchor = evaluation.anchor
    policy = evaluation.policy
    deciders = "every member decides" if policy["deciders"] == hive.ALL_MEMBERS else " and ".join(_short(item) for item in policy["deciders"]) + (" decides" if len(policy["deciders"]) == 1 else " decide")
    lines = [f"{anchor['name']} (world {anchor['world_id']}), policy v{policy['version']}: {deciders}; {policy['admit']['quorum']} grant(s){' and a confirmed key' if policy['admit']['attested'] else ''} to join."]
    lines.append("Members: " + ", ".join(f"{_short(key)}{' (from the old system)' if value.get('legacy') else ''}" for key, value in sorted(evaluation.members.items())) + ".")
    for key, request in sorted(evaluation.pending.items()):
        pinned = evaluation._policy(request["pinned"])
        rule = pinned["admit"]
        grants = len({granter for granter in request["grants"] if evaluation._decides(pinned, granter)})
        lines.append(f"Waiting: {_short(request['requester'])} has {grants} of {rule['quorum']} grant(s){'; needs a confirmed key' if rule['attested'] and not evaluation.attested.get(request['requester']) else ''}.")
    for lens_id, particle in sorted(evaluation.active.items()):
        lines.append(f"Lens {lens_id} v{evaluation.lens_objects[particle]['version']} maps {sum(len(m['accepts']) for m in evaluation.lens_objects[particle]['mappings'])} schema(s).")
    for exhaust in evaluation.exhausts:
        lines.append(f"A schema waits for a lens ({exhaust['code']}): {len(exhaust['waiting'])} message(s).")
    if evaluation.quarantined:
        lines.append(f"{len(evaluation.quarantined)} message(s) from identities not yet admitted are quarantined.")
    for refusal in evaluation.refusals:
        lines.append(f"Refused ({refusal['code']}): {refusal['reason']}")
    for item in verdict["manifests"]:
        lines.append(f"Manifest {item['wave'][:12]}: {item['verdict']}, {item['position']}.")
    return lines


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="rapp_hive2", description="rapp-hive/2 reference (experimental frontier)")
    sub = parser.add_subparsers(dest="command", required=True)
    verify = sub.add_parser("verify")
    verify.add_argument("folder")
    verify.add_argument("--anchor")
    status = sub.add_parser("status")
    status.add_argument("folder")
    cross = sub.add_parser("cross")
    cross.add_argument("folder")
    cross.add_argument("message")
    cross.add_argument("member")
    build = sub.add_parser("model")
    build.add_argument("folder")
    migrating = sub.add_parser("migrate").add_subparsers(dest="step", required=True)
    plan1 = migrating.add_parser("plan-hive1")
    plan1.add_argument("folder")
    plan1.add_argument("--declaration", required=True)
    plan1.add_argument("--name", required=True)
    plan1.add_argument("--legacy-request", action="append", default=[])
    plan1.add_argument("--out", required=True)
    planb = migrating.add_parser("plan-joins")
    planb.add_argument("folder")
    planb.add_argument("--name", required=True)
    planb.add_argument("--world", required=True)
    planb.add_argument("--founder", action="append", required=True)
    planb.add_argument("--request", action="append", required=True)
    planb.add_argument("--quorum", type=int, required=True)
    planb.add_argument("--from", dest="source", required=True)
    planb.add_argument("--out", required=True)
    applying = migrating.add_parser("apply")
    applying.add_argument("folder")
    applying.add_argument("plan")
    applying.add_argument("--key", required=True)
    applying.add_argument("--owner", required=True)
    applying.add_argument("--slug", required=True)
    applying.add_argument("--phase", type=int, required=True)
    applying.add_argument("--utc")
    vector = sub.add_parser("vectors")
    group = vector.add_mutually_exclusive_group(required=True)
    group.add_argument("--write")
    group.add_argument("--check")
    args = parser.parse_args(argv)
    try:
        if args.command in ("verify", "status", "cross"):
            _carried, records, evaluation, verdict = hive.evaluate_folder(Path(args.folder), getattr(args, "anchor", None))
            if args.command == "verify":
                result: Any = {"ok": True, "frames_verified": len(records), "state_particle": evaluation.state_particle, "verdict": verdict}
            elif args.command == "status":
                result = {"ok": True, "summary": status_lines(evaluation, verdict)}
            else:
                result = {"ok": True, **crossing.cross_to_member(evaluation, args.message, args.member)}
        elif args.command == "model":
            built = model.build()
            target = Path(args.folder)
            store.write_new_tree(target / "hive", built["hive"])
            store.write_new_tree(target / "before", built["before"])
            result = {"ok": True, "hive": str(target / "hive"), "before": str(target / "before"), "anchor": built["anchor"], "note": "SYNTHETIC model; public test keys."}
        elif args.command == "migrate":
            if args.step in ("plan-hive1", "plan-joins"):
                carried = hive.load(Path(args.folder))
                records = hive.verify_frames(carried)
                if args.step == "plan-hive1":
                    plan = migrate.plan_from_rapp_hive_1(carried, records, args.declaration, name=args.name, legacy_requests=args.legacy_request)
                else:
                    plan = migrate.plan_from_join_requests(records, name=args.name, world_id=args.world, founders=args.founder, requests=args.request, quorum=args.quorum, source=args.source)
                store.write_new_tree(Path(args.out).parent, {Path(args.out).name: rapp1.canonical(plan)}, require_empty=False)
                result = {"ok": True, "plan": args.out, "plan_particle": plan["plan_particle"], "steps": [{"signer": _short(step["signer"]), "phase": step["phase"], "frames": len(step["drafts"])} for step in plan["steps"]], "notes": plan["notes"]}
            else:
                plan = rapp1.parse(store.read_bounded(Path(args.plan), limit=rapp1.MAX_JSON_BYTES))
                signer = sign.Signer(sign.load_key(Path(args.key)), args.owner, args.slug)
                written = migrate.apply(plan, Path(args.folder), signer, phase=args.phase, utc=args.utc or migrate.utc_now())
                result = {"ok": True, "written": written}
        else:
            if args.write:
                data = vectors.encode(vectors.generate())
                store.write_new_tree(Path(args.write).parent, {Path(args.write).name: data}, require_empty=False)
                result = {"ok": True, "written": args.write, "bytes": len(data)}
            else:
                outcome = vectors.check(json.loads(store.read_bounded(Path(args.check), limit=256 * 1024 * 1024)))
                result = {"ok": not outcome["failed"], **outcome}
    except Refusal as error:
        _print({"ok": False, "refusal": {"code": error.code, "message": error.message}})
        return 2
    except OSError as error:
        _print({"ok": False, "refusal": {"code": "REFUSE_IO", "message": f"{type(error).__name__}: {error.strerror or error}"}})
        return 2
    _print(result)
    return 0 if result.get("ok", True) else 1


if __name__ == "__main__":
    raise SystemExit(main())

"""Оркестрация стадий: collect → build → reconcile → report."""
from __future__ import annotations

from collections import Counter, defaultdict

from . import merge, servicemodel
from .attribution import Engine, flatten, host_view
from .cmdb import CONFIRMABLE, CMDB
from .collectors import run_collect
from .util import iso, read_jsonl, write_json


def collect(cfg, only=None) -> dict:
    return run_collect(cfg, only)


def load_observations(cfg) -> dict[str, list[dict]]:
    by_kind = defaultdict(list)
    for path in sorted(cfg.staging_dir.glob("*.jsonl")):
        for o in read_jsonl(path):
            by_kind[o["kind"]].append(o)
    return by_kind


def _register_git_services(cfg, services: list[dict]) -> None:
    for o in services:
        a = o["attrs"]
        name, _ = cfg.normalize("service", a["name"])
        spec = {"owner_team": cfg.normalize("owner_team", a.get("owner_team"))[0],
                "criticality": cfg.normalize("criticality", a.get("criticality"))[0],
                "k8s_namespaces": a.get("k8s_namespaces") or [], "repo": a.get("repo"),
                "description": a.get("description"), "lifecycle": a.get("lifecycle")}
        cfg.add_service(name, {k: v for k, v in spec.items() if v}, origin=o["ref"])


def _confirmations(cfg, cis, obs, cmdb) -> tuple[dict, list[str]]:
    """Сопоставить подтверждения (CSV/NetBox) с CI; поверх — подтверждения из `rsm confirm`."""
    by_key = {}
    for ci in cis:
        by_key[f"rsm_id:{ci['id']}"] = ci["id"]
        for k in ci["identity_keys"]:
            if k.startswith(("host:", "ip:")):
                by_key.setdefault(k, ci["id"])
    out: dict[str, dict] = defaultdict(dict)
    unmatched = []
    for o in obs:
        keys = [f"rsm_id:{x}" for x in o["keys"].get("rsm_id", [])]
        keys += [f"host:{cfg.host_key(x)}" for x in o["keys"].get("host", []) if cfg.host_key(x)]
        keys += [f"ip:{x}" for x in o["keys"].get("ip", [])]
        cid = next((by_key[k] for k in keys if k in by_key), None)
        if not cid:
            unmatched.append(f"подтверждение {o['ref']} не сопоставлено ни с одним хостом")
            continue
        for f in CONFIRMABLE:
            v = cfg.normalize(f, o["attrs"].get(f))[0]
            if v:
                out[cid][f] = {"value": v, "by": o["attrs"].get("confirmed_by"),
                               "at": o["attrs"].get("confirmed_at"), "origin": o["attrs"].get("origin")}
    for cid, fields in cmdb.confirmations().items():
        out[cid].update(fields)
    return out, unmatched


def build(cfg, now) -> dict:
    by_kind = load_observations(cfg)
    _register_git_services(cfg, by_kind.get("service", []))
    engine = Engine(cfg)
    cmdb = CMDB(cfg.cmdb_path)

    cis, merge_conflicts = merge.resolve(by_kind.get("host", []), cfg, now)
    merge.identify(cis, cmdb.key_index())
    confirmed, unmatched = _confirmations(cfg, cis, by_kind.get("confirmation", []), cmdb)
    for ci in cis:
        flatten(ci, engine.evaluate(host_view(ci), "host", confirmed.get(ci["id"])))
    model = servicemodel.build(cfg, engine, cis, by_kind)

    notes = Counter(n for ci in cis for n in ci["attribution"]["notes"])
    notes.update(n for ns in model["namespaces"] for n in ns["attribution"]["notes"])
    snapshot = {
        "generated_at": iso(now),
        "resources": cis,
        **model,
        "merge_conflicts": merge_conflicts,
        "notes": [{"note": n, "count": c} for n, c in notes.most_common()] + [{"note": u, "count": 1} for u in unmatched],
        "observations": {k: len(v) for k, v in by_kind.items()},
    }
    write_json(cfg.snapshot_path, snapshot)
    return snapshot


def reconcile(cfg, snapshot, now) -> dict:
    return CMDB(cfg.cmdb_path).reconcile(snapshot, now, cfg)

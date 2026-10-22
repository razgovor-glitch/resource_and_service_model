"""CLI: python -m rsm <команда>. Справка: python -m rsm -h"""
from __future__ import annotations

import argparse
import csv
import json
import sys
import time

from . import fetch as fetchmod
from . import netbox, pipeline, policy, report
from .cmdb import CMDB
from .config import Config
from .util import iso, now_utc, parse_time, read_json

STATUS_ICON = {"confirmed": "✔", "auto": "●", "needs-confirmation": "?", "conflict": "!", "unknown": "–", "unowned": "–"}


def _now(args):
    t = parse_time(args.now) if getattr(args, "now", None) else now_utc()
    if t is None:
        sys.exit(f"не понял --now {args.now!r} (нужен ISO-8601, например 2026-10-22T06:00:00Z)")
    return t


def _snapshot(cfg):
    snap = read_json(cfg.snapshot_path)
    if not snap:
        sys.exit("нет data/model/snapshot.json — сначала `rsm build` (или `rsm run`)")
    return snap


def _print_run(stage, data):
    print(f"  {stage:<10} {json.dumps(data, ensure_ascii=False)}")


# ---------------------------------------------------------------- стадии
def cmd_collect(cfg, args):
    _print_run("collect", pipeline.collect(cfg, args.only.split(",") if args.only else None))


def cmd_build(cfg, args):
    snap = pipeline.build(cfg, _now(args))
    st = {}
    for ci in snap["resources"]:
        st[ci["owner_status"]] = st.get(ci["owner_status"], 0) + 1
    _print_run("build", {"resources": len(snap["resources"]), "owner_status": st,
                         "namespaces": len(snap["namespaces"]), "services": len(snap["services"])})
    return snap


def cmd_reconcile(cfg, args, snap=None):
    stats = pipeline.reconcile(cfg, snap or _snapshot(cfg), _now(args))
    _print_run("reconcile", stats)


def cmd_report(cfg, args, snap=None):
    cov = report.generate(cfg, snap or _snapshot(cfg))
    _print_run("report", {"owner_reliable_pct": cov["owner_reliable_pct"], "owner_status": cov["owner_status"],
                          "stale": cov["stale"], "decommission_candidates": cov["decommission_candidates"]})
    print(f"  → {cfg.reports_dir / 'index.html'}")


def cmd_run(cfg, args):
    t0 = time.time()
    print(f"[rsm] прогон на {iso(_now(args))}, данные: {cfg.data_dir}")
    if not args.skip_collect:
        cmd_collect(cfg, argparse.Namespace(only=None))
    snap = cmd_build(cfg, args)
    cmd_reconcile(cfg, args, snap)
    cmd_report(cfg, args, snap)
    print(f"[rsm] готово за {time.time() - t0:.1f} с")


# ---------------------------------------------------------------- просмотр
def _fmt_field(name, a):
    icon = STATUS_ICON.get(a.get("status"), " ")
    val = a.get("value") or (f"({a.get('suggestion')}?)" if a.get("suggestion") else "—")
    line = f"  {icon} {name:<13} {val:<26} {a.get('status', ''):<19} {a.get('confidence', '')}"
    ev = "".join(f"\n        · {x}" for x in a.get("evidence", [])[:4])
    alts = ", ".join(f"{x['value']} ({x['confidence']})" for x in a.get("alternatives", []))
    return line + ev + (f"\n        альтернативы: {alts}" if alts else "")


def cmd_show(cfg, args):
    rows = CMDB(cfg.cmdb_path).find(args.host)
    if not rows:
        sys.exit(f"'{args.host}' не найден в CMDB")
    for ci in rows:
        print(f"\n{ci['hostname']}  [{ci['id']}]  lifecycle={ci['lifecycle']}  presence={ci['presence']}  "
              f"last_alive={ci.get('last_alive') or '—'}")
        print(f"  fqdn={ci.get('fqdn') or '—'}  ips={', '.join(ci['ips']) or '—'}  os={ci.get('os') or '—'}")
        kind = "VM" if ci.get("virtual") else ("железо" if ci.get("virtual") is False else "?")
        print(f"  тип={kind} platform={ci.get('platform') or '—'} cpu={ci.get('cpu') or '—'} "
              f"mem={ci.get('memory_mb') or '—'}MB vcenter={ci.get('vcenter_cluster') or '—'} "
              f"k8s={ci.get('k8s_cluster') or '—'}/{ci.get('k8s_role') or '—'}")
        srcs = ", ".join("{}({})".format(o["source"], o["ref"]) for o in ci["observations"])
        print(f"  источники: {srcs}")
        print("  владение:")
        for f in ("owner_team", "service", "environment", "criticality", "support_model", "role"):
            print(_fmt_field(f, ci["attribution"][f]))
        team = cfg.team_info(ci.get("owner_team"))
        if team:
            print(f"  контакты команды: on-call {team.get('oncall', '—')}, lead {team.get('lead', '—')}")
        if ci.get("k8s_consumers"):
            print("  нагрузки на ноде (доля CPU requests):")
            for c in ci["k8s_consumers"][:8]:
                print(f"    {c['share']:>6.1%}  {c['namespace']:<32} {c['owner_team'] or '—':<10} {c['service'] or '—'}")
        for c in ci.get("conflicts", []):
            print(f"  ! {c['type']}: {c['detail']}")
        for n in ci["attribution"].get("notes", []):
            print(f"  · {n}")


def cmd_query(cfg, args):
    where, params = [], []
    for col, val in (("owner_team", args.team), ("service", args.service), ("owner_status", args.status),
                     ("lifecycle", args.lifecycle), ("environment", args.environment)):
        if val:
            where.append(f"{col} = ?")
            params.append(val)
    rows = CMDB(cfg.cmdb_path).rows(" AND ".join(where) or "1=1", tuple(params))
    cols = ("hostname", "ips", "owner_team", "service", "environment", "criticality", "owner_status",
            "owner_confidence", "lifecycle")
    if args.format == "json":
        print(json.dumps([{c: r.get(c) for c in cols + ("id",)} for r in rows], ensure_ascii=False, indent=1))
        return
    if args.format == "csv":
        w = csv.writer(sys.stdout)
        w.writerow(cols)
        for r in rows:
            w.writerow([", ".join(r[c]) if isinstance(r.get(c), list) else r.get(c) for c in cols])
        return
    print(f"{'hostname':<30}{'ip':<15}{'team':<10}{'service':<24}{'env':<12}{'crit':<8}{'status':<20}{'lifecycle'}")
    for r in rows:
        print(f"{r['hostname']:<30}{(r['ips'] or [''])[0]:<15}{r.get('owner_team') or '—':<10}"
              f"{r.get('service') or '—':<24}{r.get('environment') or '—':<12}{r.get('criticality') or '—':<8}"
              f"{r['owner_status']:<20}{r['lifecycle']}")
    print(f"— {len(rows)} шт.")


def cmd_confirm(cfg, args):
    db = CMDB(cfg.cmdb_path)
    rows = db.find(args.host)
    if len(rows) != 1:
        sys.exit(f"'{args.host}': найдено {len(rows)} CI — уточните (id из `rsm show`)")
    fields = {}
    for f in ("owner_team", "service", "environment", "criticality"):
        raw = getattr(args, f)
        if raw:
            val, known = cfg.normalize(f, raw)
            if not known:
                sys.exit(f"{f}='{raw}' нет в словаре/каталоге — сначала добавьте его в config/")
            fields[f] = val
    if not fields:
        sys.exit("укажите хотя бы --team/--service/--environment/--criticality")
    db.confirm(rows[0]["id"], fields, args.by, iso(_now(args)))
    print(f"подтверждено для {rows[0]['hostname']} [{rows[0]['id']}]: {fields} (by {args.by}). "
          f"Применится при следующем `rsm run`.")


def cmd_tasks(cfg, args):
    tasks = CMDB(cfg.cmdb_path).tasks(args.status)
    tasks = [t for t in tasks if (not args.assignee or t["assignee"] == args.assignee)
             and (not args.type or t["type"] == args.type)]
    for t in tasks:
        print(f"{t['type']:<20}{t['assignee'] or '—':<10}{t['summary']}")
    print(f"— {len(tasks)} задач ({args.status})")


# ---------------------------------------------------------------- интеграции
def cmd_fetch(cfg, args):
    if args.target == "k8s":
        done = fetchmod.fetch_k8s(cfg, args.context or [], args.kubeconfig, args.name)
        print(f"выгружены кластеры: {', '.join(done)} → {cfg.raw('k8s')}")
    elif args.target == "zabbix":
        print(f"Zabbix: {fetchmod.fetch_zabbix(cfg)} хостов → {cfg.raw('zabbix', 'hosts.json')}")
    elif args.target == "nmap":
        if not args.targets:
            sys.exit("укажите подсети: rsm fetch nmap 10.0.0.0/16 192.168.1.0/24")
        print(f"nmap → {fetchmod.fetch_nmap(cfg, args.targets, args.ports, args.name or 'scan')}")
    elif args.target == "ansible":
        if not args.inventory:
            sys.exit("укажите инвентори: rsm fetch ansible -i inventories/prod")
        print(f"ansible → {fetchmod.fetch_ansible(cfg, args.inventory, args.limit)}")


def cmd_netbox(cfg, args):
    nb = netbox.client(cfg, args.apply)
    if args.action == "pull":
        print(f"подтверждённых объектов: {netbox.pull_confirmed(cfg, nb)} → {cfg.raw('netbox', 'confirmed.json')}")
        return
    stats = netbox.bootstrap(cfg, nb) if args.action == "bootstrap" else netbox.sync(cfg, nb)
    print(json.dumps(stats, ensure_ascii=False))
    print(f"план: {netbox.write_plan(cfg, nb)}")
    if not nb.apply:
        print("это dry-run; для записи добавьте --apply" + (" и задайте NETBOX_URL/NETBOX_TOKEN" if nb.offline else ""))


def cmd_policy(cfg, args):
    violations = policy.check_paths(cfg, args.paths)
    for v in violations:
        print(f"✗ {v}")
    print(f"{'OK' if not violations else 'FAIL'}: нарушений {len(violations)}")
    sys.exit(1 if violations else 0)


def cmd_demo(cfg, args):
    from . import demo
    demo.prepare_dir(cfg.data_dir)
    fleet = demo.Fleet(args.seed, args.dev_vms)
    print(f"[demo] сгенерирован парк: {len(fleet.hosts)} хостов (вкл. зомби и shadow IT), данные → {cfg.data_dir}")
    snap = None
    for day, ts in demo.DAYS.items():
        fleet.write_raw(cfg.raw(), day)
        print(f"\n[demo] день {day}: {ts}")
        run_args = argparse.Namespace(now=ts, skip_collect=False)
        cmd_collect(cfg, argparse.Namespace(only=None))
        snap = cmd_build(cfg, run_args)
        cmd_reconcile(cfg, run_args, snap)
        if day == 1:
            print("[demo] команды подтверждают владельцев: svn01 → platform, redmine → web")
            for host, team, svc, by in (("svn01", "platform", "legacy-devtools", "a.smirnov"),
                                        ("redmine", "web", "legacy-devtools", "k.volkov")):
                cmd_confirm(cfg, argparse.Namespace(host=host, owner_team=team, service=svc, environment="production",
                                                    criticality=None, by=by, now=ts))
    cmd_report(cfg, argparse.Namespace(), snap)
    ev = demo.evaluate(snap, cfg.raw("_ground_truth.json"))
    print("\n[demo] качество атрибуции против «правды» генератора:")
    for k, v in sorted(ev["stats"].items(), key=lambda x: -x[1]):
        print(f"  {v:>4}  {k}")
    for w in ev["wrong"][:15]:
        print(f"        {w}")
    print(f"\nДальше:\n  python -m rsm --data-dir {cfg.data_dir} show prod-billing-app-05\n"
          f"  python -m rsm --data-dir {cfg.data_dir} query --status unowned\n"
          f"  open {cfg.reports_dir / 'index.html'}")


# ---------------------------------------------------------------- argparse
def main(argv=None):
    p = argparse.ArgumentParser(prog="rsm", description="Ресурсно-сервисная модель: discovery → владельцы → CMDB")
    p.add_argument("--config", default="config", help="каталог конфигурации (по умолчанию ./config)")
    p.add_argument("--data-dir", help="каталог данных (по умолчанию из rsm.yaml: ./data)")
    sub = p.add_subparsers(dest="cmd", required=True)

    def with_now(sp):
        sp.add_argument("--now", help="время прогона ISO-8601 (по умолчанию сейчас)")
        return sp

    sp = sub.add_parser("demo", help="сгенерировать демо-парк и прогнать 3 дня discovery")
    sp.add_argument("--seed", type=int, default=7)
    sp.add_argument("--dev-vms", type=int, default=90)
    sp.set_defaults(fn=cmd_demo)

    sp = sub.add_parser("fetch", help="выгрузить сырые данные из живых систем в data/raw")
    sp.add_argument("target", choices=["k8s", "zabbix", "nmap", "ansible"])
    sp.add_argument("targets", nargs="*", help="nmap: подсети/хосты")
    sp.add_argument("--context", action="append", help="k8s: kube-context (можно несколько; без него — все)")
    sp.add_argument("--kubeconfig")
    sp.add_argument("--name", help="k8s: имя кластера в модели; nmap: имя файла скана")
    sp.add_argument("--ports", help="nmap: список портов")
    sp.add_argument("-i", "--inventory", help="ansible: инвентори")
    sp.add_argument("--limit", help="ansible: --limit")
    sp.set_defaults(fn=cmd_fetch)

    sp = sub.add_parser("collect", help="разобрать data/raw → data/staging")
    sp.add_argument("--only", help="только эти источники, через запятую")
    sp.set_defaults(fn=cmd_collect)
    with_now(sub.add_parser("build", help="склейка + атрибуция + сервисный слой → snapshot")).set_defaults(fn=cmd_build)
    with_now(sub.add_parser("reconcile", help="snapshot → CMDB: изменения, lifecycle, задачи")).set_defaults(fn=cmd_reconcile)
    sub.add_parser("report", help="отчёты в data/reports").set_defaults(fn=cmd_report)
    sp = with_now(sub.add_parser("run", help="collect → build → reconcile → report"))
    sp.add_argument("--skip-collect", action="store_true")
    sp.set_defaults(fn=cmd_run)

    sp = sub.add_parser("show", help="карточка сервера с уликами")
    sp.add_argument("host", help="hostname / FQDN / IP / id")
    sp.set_defaults(fn=cmd_show)

    sp = sub.add_parser("query", help="список серверов с фильтрами")
    sp.add_argument("--team")
    sp.add_argument("--service")
    sp.add_argument("--environment")
    sp.add_argument("--status", help="confirmed|auto|needs-confirmation|conflict|unowned")
    sp.add_argument("--lifecycle", help="active|stale|decommission-candidate")
    sp.add_argument("--format", choices=["table", "csv", "json"], default="table")
    sp.set_defaults(fn=cmd_query)

    sp = with_now(sub.add_parser("confirm", help="подтвердить владельца (приоритет над правилами)"))
    sp.add_argument("host")
    sp.add_argument("--team", dest="owner_team")
    sp.add_argument("--service")
    sp.add_argument("--environment")
    sp.add_argument("--criticality")
    sp.add_argument("--by", required=True, help="кто подтвердил (логин)")
    sp.set_defaults(fn=cmd_confirm)

    sp = sub.add_parser("tasks", help="задачи по наведению порядка")
    sp.add_argument("--assignee")
    sp.add_argument("--type")
    sp.add_argument("--status", default="open")
    sp.set_defaults(fn=cmd_tasks)

    sp = sub.add_parser("netbox", help="публикация в NetBox")
    sp.add_argument("action", choices=["bootstrap", "sync", "pull"])
    sp.add_argument("--apply", action="store_true", help="реально писать (иначе dry-run)")
    sp.set_defaults(fn=cmd_netbox)

    sp = sub.add_parser("policy", help="policy-as-code для CI")
    sp.add_argument("action", choices=["check"])
    sp.add_argument("paths", nargs="+", help="файлы/каталоги; '-' = stdin")
    sp.set_defaults(fn=cmd_policy)

    args = p.parse_args(argv)
    cfg = Config(args.config, args.data_dir)
    try:
        args.fn(cfg, args)
    except RuntimeError as err:
        sys.exit(f"ошибка: {err}")


if __name__ == "__main__":
    main()

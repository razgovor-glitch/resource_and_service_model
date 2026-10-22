"""Отчёты: CSV-реестры + единый HTML (data/reports/index.html) + задачи (tasks.jsonl)."""
from __future__ import annotations

import csv
import html
from collections import Counter

from .cmdb import CMDB
from .util import write_json, write_jsonl

STATUS_ORDER = ("confirmed", "auto", "needs-confirmation", "conflict", "unowned")
STATUS_LABEL = {"confirmed": "подтверждён", "auto": "авто", "needs-confirmation": "нужно подтвердить",
                "conflict": "конфликт", "unowned": "ничейный"}
LIFECYCLE_LABEL = {"active": "active", "stale": "stale", "decommission-candidate": "на вывод"}

RESOURCE_COLUMNS = ("id", "hostname", "fqdn", "ips", "os", "virtual", "platform", "vcenter_cluster", "k8s_cluster",
                    "k8s_role", "role", "owner_team", "service", "environment", "criticality", "support_model",
                    "owner_status", "owner_confidence", "lifecycle", "last_alive", "sources", "evidence")


def _cell(v):
    if isinstance(v, list):
        return ", ".join(map(str, v))
    return "" if v is None else v


def _write_csv(path, rows, columns):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(columns)
        for r in rows:
            w.writerow([_cell(r.get(c)) for c in columns])


def _evidence(ci, n=3):
    return " | ".join(ci.get("attribution", {}).get("owner_team", {}).get("evidence", [])[:n])


def generate(cfg, snapshot: dict) -> dict:
    cmdb = CMDB(cfg.cmdb_path)
    out = cfg.reports_dir
    out.mkdir(parents=True, exist_ok=True)
    rows = cmdb.rows()
    for r in rows:
        r["evidence"] = _evidence(r)
    active = [r for r in rows if r["lifecycle"] == "active"]
    unowned = [r for r in active if r["owner_status"] == "unowned"]
    confirm = [r for r in active if r["owner_status"] == "needs-confirmation"]
    conflict_rows = [r for r in active if r["owner_status"] == "conflict"]
    stale = [r for r in rows if r["lifecycle"] != "active"]
    tech_conflicts = [{"hostname": r["hostname"], "id": r["id"], **c} for r in active for c in r.get("conflicts", [])]
    namespaces = snapshot["namespaces"]
    ns_unowned = [n for n in namespaces if n["owner_status"] in ("unowned", "conflict", "needs-confirmation")]
    tasks = cmdb.tasks("open")

    _write_csv(out / "resources.csv", rows, RESOURCE_COLUMNS)
    _write_csv(out / "unowned-assets.csv", unowned, ("id", "hostname", "ips", "role", "owner_suggestion",
                                                     "owner_confidence", "sources", "evidence"))
    _write_csv(out / "needs-confirmation.csv", confirm, ("id", "hostname", "ips", "owner_team", "service",
                                                         "environment", "owner_confidence", "evidence"))
    _write_csv(out / "conflicts.csv", conflict_rows + tech_conflicts,
               ("id", "hostname", "owner_status", "owner_team", "type", "detail", "evidence"))
    _write_csv(out / "stale-assets.csv", stale, ("id", "hostname", "ips", "owner_team", "service", "lifecycle",
                                                 "presence", "last_alive", "first_seen", "sources"))
    _write_csv(out / "k8s-namespaces.csv", namespaces, ("id", "cluster", "name", "owner_team", "service", "environment",
                                                        "criticality", "owner_status", "owner_confidence", "cpu_m"))
    _write_csv(out / "services.csv", [{**s, "hosts": len(s["hosts"]), "namespaces": len(s["namespaces"]),
                                       "k8s_nodes": len(s["k8s_nodes"])} for s in snapshot["services"]],
               ("name", "owner_team", "criticality", "registered", "origin", "hosts", "namespaces", "workloads",
                "k8s_nodes", "clusters", "repo"))
    _write_csv(out / "teams.csv", snapshot["teams"], ("team", "known", "oncall", "servers", "services",
                                                      "namespaces", "k8s_cpu_cores"))
    write_jsonl(out / "tasks.jsonl", tasks)

    status = Counter(r["owner_status"] for r in active)
    n = len(active) or 1
    coverage = {
        "generated_at": snapshot["generated_at"],
        "resources_total": len(rows), "resources_active": len(active),
        "owner_status": {s: status.get(s, 0) for s in STATUS_ORDER},
        "owner_reliable_pct": round(100 * (status["confirmed"] + status["auto"]) / n, 1),
        "field_coverage_pct": {f: round(100 * sum(1 for r in active if r.get(f)) / n, 1)
                               for f in ("owner_team", "service", "environment", "criticality", "role")},
        "sources": dict(Counter(s for r in active for s in r["sources"]).most_common()),
        "single_source": sum(1 for r in active if len(r["sources"]) == 1),
        "nmap_only": sum(1 for r in active if r["sources"] == ["nmap"]),
        "stale": sum(1 for r in stale if r["lifecycle"] == "stale"),
        "decommission_candidates": sum(1 for r in stale if r["lifecycle"] == "decommission-candidate"),
        "k8s_namespaces": len(namespaces), "k8s_namespaces_without_owner": len(ns_unowned),
        "unregistered_services": [s["name"] for s in snapshot["services"] if not s["registered"]],
        "open_tasks": dict(Counter(t["type"] for t in tasks)),
    }
    write_json(out / "coverage.json", coverage)
    (out / "index.html").write_text(_html(snapshot, coverage, rows, active, unowned, confirm, conflict_rows,
                                          tech_conflicts, stale, ns_unowned, tasks), encoding="utf-8")
    return coverage


# ---------------------------------------------------------------- HTML
def e(v) -> str:
    return html.escape(str(_cell(v)))


def _badge(status):
    return f'<span class="b b-{e(status)}">{e(STATUS_LABEL.get(status, status))}</span>'


def _table(tid, headers, body_rows, empty="Пусто — отлично."):
    if not body_rows:
        return f'<p class="empty">{e(empty)}</p>'
    head = "".join(f"<th>{e(h)}</th>" for h in headers)
    body = "".join("<tr>" + "".join(f"<td>{c}</td>" for c in r) + "</tr>" for r in body_rows)
    return (f'<input class="filter" placeholder="Фильтр…" data-table="{tid}">'
            f'<div class="scroll"><table id="{tid}"><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>')


def _ev_cell(ci):
    ev = ci.get("attribution", {}).get("owner_team", {}).get("evidence", [])
    if not ev:
        return '<span class="muted">нет улик</span>'
    first = e(ev[0])
    if len(ev) == 1:
        return f'<span class="ev">{first}</span>'
    rest = "".join(f"<li>{e(x)}</li>" for x in ev[1:])
    return f'<details><summary class="ev">{first}</summary><ul class="ev">{rest}</ul></details>'


def _html(snap, cov, rows, active, unowned, confirm, conflict_rows, tech_conflicts, stale, ns_unowned, tasks):
    st = cov["owner_status"]
    total = max(sum(st.values()), 1)
    bar = "".join(f'<div class="seg s-{s}" style="width:{100 * st[s] / total:.2f}%" title="{STATUS_LABEL[s]}: {st[s]}"></div>'
                  for s in STATUS_ORDER if st[s])
    legend = "".join(f'<span><i class="dot s-{s}"></i>{STATUS_LABEL[s]} · {st[s]}</span>' for s in STATUS_ORDER)
    fields = "".join(
        f'<div class="fc"><span>{e(f)}</span><div class="track"><div style="width:{p}%"></div></div><b>{p}%</b></div>'
        for f, p in cov["field_coverage_pct"].items())
    sources = "".join(f'<span class="chip">{e(s)} · {c}</span>' for s, c in cov["sources"].items())
    kpis = [("Серверов (active)", cov["resources_active"], ""),
            ("Владелец определён", f"{cov['owner_reliable_pct']}%", "авто + подтверждено"),
            ("Подтвердить", st["needs-confirmation"], "нужно решение команды"),
            ("Ничейные", st["unowned"], "назначить через триаж"),
            ("Конфликты", st["conflict"] + len(tech_conflicts), "владельца / IP / UUID"),
            ("Stale / на вывод", f"{cov['stale']} / {cov['decommission_candidates']}", "не видны в discovery"),
            ("NS без владельца", f"{cov['k8s_namespaces_without_owner']} / {cov['k8s_namespaces']}", "Kubernetes"),
            ("Открытых задач", len(tasks), "")]
    kpi_html = "".join(f'<div class="kpi"><div class="kl">{e(a)}</div><div class="kv">{e(b)}</div>'
                       f'<div class="ks">{e(c)}</div></div>' for a, b, c in kpis)

    res_rows = [[f'<b>{e(r["hostname"])}</b><div class="muted mono">{e(r["id"])}</div>', e(r["ips"][:2]),
                 e(r.get("role")), e(r.get("owner_team")), e(r.get("service")), e(r.get("environment")),
                 e(r.get("criticality")), _badge(r["owner_status"]), e(r.get("owner_confidence")),
                 e(LIFECYCLE_LABEL.get(r["lifecycle"], r["lifecycle"])),
                 f'<span class="mono">{e(r["sources"])}</span>', _ev_cell(r)] for r in rows]
    unowned_rows = [[f'<b>{e(r["hostname"])}</b>', e(r["ips"][:2]), e(r.get("role")), e(r.get("owner_suggestion")),
                     e(r.get("owner_confidence")), f'<span class="mono">{e(r["sources"])}</span>', _ev_cell(r)]
                    for r in unowned]
    confirm_rows = [[f'<b>{e(r["hostname"])}</b>', e(r.get("owner_team")), e(r.get("service")),
                     e(r.get("environment")), e(r.get("owner_confidence")), _ev_cell(r)] for r in confirm]
    conflict_html = [[f'<b>{e(r["hostname"])}</b>', "владелец",
                      e(f"{r['owner_team']} ({r['owner_confidence']}) vs " + ", ".join(
                          f"{a['value']} ({a['confidence']})" for a in r["attribution"]["owner_team"]["alternatives"])),
                      _ev_cell(r)] for r in conflict_rows]
    conflict_html += [[f'<b>{e(c["hostname"])}</b>', e(c["type"]), e(c["detail"]), ""] for c in tech_conflicts]
    stale_rows = [[f'<b>{e(r["hostname"])}</b>', e(r["ips"][:2]), e(r.get("owner_team")), e(r.get("service")),
                   e(LIFECYCLE_LABEL.get(r["lifecycle"])), e(r["presence"]), e(r.get("last_alive") or "никогда"),
                   f'<span class="mono">{e(r["sources"])}</span>'] for r in stale]
    svc_rows = [[f'<b>{e(s["name"])}</b>' + ("" if s["registered"] else ' <span class="b b-conflict">нет в каталоге</span>'),
                 e(s.get("owner_team")), e(s.get("criticality")), len(s["hosts"]), len(s["namespaces"]),
                 s["workloads"], len(s["k8s_nodes"]), e(s["clusters"]), f'<span class="muted">{e(s.get("origin"))}</span>']
                for s in snap["services"]]
    team_rows = [[f'<b>{e(t["team"])}</b>' + ("" if t["known"] else ' <span class="b b-conflict">нет в словаре</span>'),
                  e(t.get("oncall")), t["servers"], e(t["services"]), t["namespaces"], t["k8s_cpu_cores"]]
                 for t in snap["teams"]]
    ns_rows = [[f'<b>{e(n["id"])}</b>', e(n.get("owner_team")), e(n.get("service")), e(n.get("environment")),
                _badge(n["owner_status"]), e(n.get("owner_suggestion")), round(n["cpu_m"] / 1000, 1),
                e(", ".join(n["workloads"][:4]))] for n in snap["namespaces"]]
    task_rows = [[e(t["type"]), e(t["assignee"]), e(t["summary"]), f'<span class="muted">{e(t["created_at"])}</span>']
                 for t in tasks]
    note_rows = [[e(n["note"]), n["count"]] for n in snap.get("notes", [])]

    sections = [
        ("unowned", "Ничейные серверы", "Нет надёжных улик о владельце. Задача «assign-owner» уходит триаж-команде.",
         _table("t-unowned", ["Хост", "IP", "Роль", "Подсказка", "Увер.", "Источники", "Улики"], unowned_rows)),
        ("confirm", "Требуют подтверждения", "Владелец угадан с умеренной уверенностью — команда подтверждает одной командой.",
         _table("t-confirm", ["Хост", "Команда", "Сервис", "Окружение", "Увер.", "Улики"], confirm_rows)),
        ("conflicts", "Конфликты", "Источники противоречат друг другу (владелец, IP, UUID).",
         _table("t-conflicts", ["Хост", "Тип", "Детали", "Улики"], conflict_html)),
        ("stale", "Stale и кандидаты на вывод", "Не подают признаков жизни дольше порога. Автоматически не удаляются.",
         _table("t-stale", ["Хост", "IP", "Команда", "Сервис", "Статус", "В discovery", "Последний раз жив", "Источники"], stale_rows)),
        ("services", "Сервисы", "Сервисный слой: каталог + Git + обнаруженное в разметке.",
         _table("t-services", ["Сервис", "Команда", "Критичность", "Хостов", "NS", "Workloads", "K8s-нод", "Кластеры", "Откуда"], svc_rows)),
        ("teams", "Команды", "Showback: серверы, сервисы и CPU requests в Kubernetes.",
         _table("t-teams", ["Команда", "On-call", "Серверов", "Сервисы", "NS", "K8s CPU, ядер"], team_rows)),
        ("ns", "Kubernetes namespaces", "Владелец namespace = владелец нагрузок; ноды принадлежат платформе.",
         _table("t-ns", ["Namespace", "Команда", "Сервис", "Окружение", "Статус", "Кандидат", "CPU req, ядер", "Workloads"], ns_rows)),
        ("tasks", "Открытые задачи", "Выгружаются в tasks.jsonl для заведения в трекер.",
         _table("t-tasks", ["Тип", "Кому", "Что сделать", "Создана"], task_rows)),
        ("notes", "Пополнить словари", "Значения, которые встречаются в источниках, но неизвестны словарям.",
         _table("t-notes", ["Заметка", "Сколько раз"], note_rows)),
        ("all", "Реестр серверов", "Полный реестр: какой сервер чей, с уликами.",
         _table("t-all", ["Хост", "IP", "Роль", "Команда", "Сервис", "Окр.", "Крит.", "Статус", "Увер.", "Lifecycle", "Источники", "Улики"], res_rows)),
    ]
    nav = "".join(f'<a href="#{sid}">{e(title)}</a>' for sid, title, _, _ in sections)
    body = "".join(f'<section id="{sid}"><h2>{e(title)}</h2><p class="muted">{e(desc)}</p>{content}</section>'
                   for sid, title, desc, content in sections)
    return TEMPLATE.format(generated=e(snap["generated_at"]), kpis=kpi_html, bar=bar, legend=legend, fields=fields,
                           sources=sources, nav=nav, body=body, nmap_only=cov["nmap_only"],
                           single=cov["single_source"])


TEMPLATE = """<!doctype html>
<html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Ресурсно-сервисная модель</title>
<style>
:root{{--bg:#f7f7f5;--panel:#fff;--text:#1d1d1b;--muted:#6b6b66;--line:#e4e3de;--accent:#2f6fde;
--ok:#2e8b57;--auto:#4f9d69;--warn:#d08a1c;--bad:#c6453b;--none:#8a8a85;--chip:#efeee9}}
@media (prefers-color-scheme:dark){{:root:not([data-theme=light]){{--bg:#151514;--panel:#1e1e1c;--text:#ecebe6;
--muted:#9b9a94;--line:#33332f;--accent:#7aa7ff;--ok:#5cc38a;--auto:#7cc596;--warn:#e7a948;--bad:#ef6f63;--none:#77776f;--chip:#2a2a27}}}}
:root[data-theme=dark]{{--bg:#151514;--panel:#1e1e1c;--text:#ecebe6;--muted:#9b9a94;--line:#33332f;--accent:#7aa7ff;
--ok:#5cc38a;--auto:#7cc596;--warn:#e7a948;--bad:#ef6f63;--none:#77776f;--chip:#2a2a27}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--text);font:14px/1.45 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}}
header,main{{max-width:1280px;margin:0 auto;padding:16px}}h1{{font-size:22px;margin:8px 0 2px}}h2{{font-size:17px;margin:0 0 2px}}
.muted{{color:var(--muted)}}.mono{{font-family:ui-monospace,Menlo,monospace;font-size:12px}}
nav{{display:flex;flex-wrap:wrap;gap:6px 14px;margin:10px 0 0}}nav a{{color:var(--accent);text-decoration:none}}
.kpis{{display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:10px;margin:14px 0}}
.kpi,section,.panel{{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:12px 14px}}
.kl{{color:var(--muted);font-size:12px}}.kv{{font-size:24px;font-weight:650;margin-top:2px}}.ks{{color:var(--muted);font-size:11px}}
.grid2{{display:grid;grid-template-columns:1fr 1fr;gap:10px}}@media (max-width:760px){{.grid2{{grid-template-columns:1fr}}}}
.bar{{display:flex;height:14px;border-radius:7px;overflow:hidden;background:var(--chip);margin:8px 0}}.seg{{height:100%}}
.legend{{display:flex;flex-wrap:wrap;gap:4px 14px;font-size:12px}}.dot{{display:inline-block;width:9px;height:9px;border-radius:50%;margin-right:5px}}
.s-confirmed{{background:var(--ok)}}.s-auto{{background:var(--auto)}}.s-needs-confirmation{{background:var(--warn)}}
.s-conflict{{background:var(--bad)}}.s-unowned{{background:var(--none)}}
.fc{{display:grid;grid-template-columns:110px 1fr 52px;align-items:center;gap:8px;margin:5px 0;font-size:13px}}
.track{{height:8px;background:var(--chip);border-radius:4px;overflow:hidden}}.track div{{height:100%;background:var(--accent)}}
.chip{{display:inline-block;background:var(--chip);border-radius:6px;padding:2px 8px;margin:2px 4px 2px 0;font-size:12px}}
section{{margin:12px 0}}.scroll{{overflow-x:auto}}table{{border-collapse:collapse;width:100%;font-size:13px}}
th,td{{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top}}th{{position:sticky;top:0;background:var(--panel);font-weight:600}}
.b{{display:inline-block;border-radius:5px;padding:0 6px;font-size:11px;font-weight:600;color:#fff;white-space:nowrap}}
.b-confirmed{{background:var(--ok)}}.b-auto{{background:var(--auto)}}.b-needs-confirmation{{background:var(--warn)}}
.b-conflict{{background:var(--bad)}}.b-unowned{{background:var(--none)}}
.ev{{font-size:12px;color:var(--muted)}}ul.ev{{margin:4px 0 0 16px;padding:0}}summary{{cursor:pointer}}
.filter{{width:100%;max-width:320px;padding:6px 9px;margin:8px 0;border:1px solid var(--line);border-radius:7px;background:var(--bg);color:var(--text)}}
.empty{{color:var(--ok)}}
</style></head><body>
<header><h1>Ресурсно-сервисная модель</h1><div class="muted">Срез от {generated} · кто владеет каждым сервером, сервисом и namespace</div>
<nav>{nav}</nav></header>
<main>
<div class="kpis">{kpis}</div>
<div class="grid2">
 <div class="panel"><b>Статус владения (active)</b><div class="bar">{bar}</div><div class="legend">{legend}</div></div>
 <div class="panel"><b>Заполненность атрибутов</b>{fields}</div>
</div>
<div class="panel" style="margin-top:10px"><b>Источники discovery</b>
 <div style="margin-top:6px">{sources}</div>
 <div class="muted" style="margin-top:6px">Видны только одному источнику: {single}; только в nmap (shadow IT): {nmap_only}</div></div>
{body}
</main>
<script>
document.querySelectorAll('input.filter').forEach(function(inp){{
  inp.addEventListener('input',function(){{
    var q=inp.value.toLowerCase(),t=document.getElementById(inp.dataset.table);
    t.querySelectorAll('tbody tr').forEach(function(tr){{tr.style.display=tr.textContent.toLowerCase().indexOf(q)>=0?'':'none';}});
  }});
}});
</script></body></html>"""

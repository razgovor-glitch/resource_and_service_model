"""Локальная CMDB (SQLite): история CI, жизненный цикл, подтверждения, задачи.

В проде источником истины становится NetBox (см. rsm/netbox.py), но локальная база
нужна и там: она хранит историю изменений, ключи идентичности и очередь задач.

Жизненный цикл (никогда не удаляем автоматически):
  active                  CI жив (по свежему liveness-сигналу) или в пределах stale_after_days
  stale                   не жив дольше stale_after_days
  decommission-candidate  не жив дольше decommission_after_days → задача владельцу
"""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from .util import days_between, iso, parse_time, stable_id

SCHEMA = """
CREATE TABLE IF NOT EXISTS ci (
  id TEXT PRIMARY KEY, hostname TEXT, lifecycle TEXT, presence TEXT,
  owner_team TEXT, service TEXT, environment TEXT, criticality TEXT, owner_status TEXT,
  first_seen TEXT, last_seen TEXT, last_alive TEXT, data TEXT);
CREATE TABLE IF NOT EXISTS ci_key (key TEXT, ci_id TEXT, PRIMARY KEY (key, ci_id));
CREATE TABLE IF NOT EXISTS confirmation (
  ci_id TEXT, field TEXT, value TEXT, confirmed_by TEXT, confirmed_at TEXT, PRIMARY KEY (ci_id, field));
CREATE TABLE IF NOT EXISTS change (run_id TEXT, ci_id TEXT, change TEXT, field TEXT, old TEXT, new TEXT);
CREATE TABLE IF NOT EXISTS run (run_id TEXT PRIMARY KEY, stats TEXT);
CREATE TABLE IF NOT EXISTS task (
  id TEXT PRIMARY KEY, subject TEXT, type TEXT, assignee TEXT, status TEXT,
  created_at TEXT, updated_at TEXT, summary TEXT);
CREATE INDEX IF NOT EXISTS ci_hostname ON ci (hostname);
"""
TRACKED = ("hostname", "os", "ips", "owner_team", "service", "environment", "criticality",
           "owner_status", "cpu", "memory_mb", "role", "k8s_cluster", "power_state")
CONFIRMABLE = ("owner_team", "service", "environment", "criticality")
# Аппаратные факты не «забываются», если хост остался виден только DNS/nmap/Zabbix.
STICKY = ("virtual", "platform", "vcenter_cluster", "datacenter", "vendor", "model", "serial", "uuid",
          "cpu", "memory_mb", "os", "k8s_cluster", "k8s_role")


class CMDB:
    def __init__(self, path: Path):
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(path)
        self.db.row_factory = sqlite3.Row
        self.db.executescript(SCHEMA)

    # ---------- чтение ----------
    def key_index(self) -> dict[str, list[str]]:
        idx: dict[str, list[str]] = {}
        for r in self.db.execute("SELECT key, ci_id FROM ci_key ORDER BY ci_id"):
            idx.setdefault(r["key"], []).append(r["ci_id"])
        return idx

    def confirmations(self) -> dict[str, dict]:
        out: dict[str, dict] = {}
        for r in self.db.execute("SELECT * FROM confirmation"):
            out.setdefault(r["ci_id"], {})[r["field"]] = {
                "value": r["value"], "by": r["confirmed_by"], "at": r["confirmed_at"], "origin": "rsm confirm"}
        return out

    def rows(self, where: str = "1=1", params=()) -> list[dict]:
        out = []
        for r in self.db.execute(f"SELECT * FROM ci WHERE {where} ORDER BY hostname", params):
            d = json.loads(r["data"])
            d.update({k: r[k] for k in ("lifecycle", "presence", "first_seen", "last_seen", "last_alive")})
            out.append(d)
        return out

    def find(self, term: str) -> list[dict]:
        t = term.strip().lower()
        ids = {r["ci_id"] for r in self.db.execute(
            "SELECT ci_id FROM ci_key WHERE key IN (?, ?, ?)", (f"host:{t.split('.')[0]}", f"ip:{t}", f"mac:{t}"))}
        ids |= {r["id"] for r in self.db.execute("SELECT id FROM ci WHERE id = ? OR hostname = ?", (t, t))}
        if not ids:  # FQDN, имя ВМ, IP вне ключей и т.п.
            ids = {r["id"] for r in self.db.execute("SELECT id FROM ci WHERE data LIKE ?", (f'%"{t}"%',))}
        return [row for i in sorted(ids) for row in self.rows("id = ?", (i,))]

    def tasks(self, status: str = "open") -> list[dict]:
        return [dict(r) for r in self.db.execute(
            "SELECT * FROM task WHERE status = ? ORDER BY type, assignee, subject", (status,))]

    def changes(self, run_id: str) -> list[dict]:
        return [dict(r) for r in self.db.execute("SELECT * FROM change WHERE run_id = ?", (run_id,))]

    # ---------- запись ----------
    def confirm(self, ci_id: str, fields: dict, by: str, at: str) -> None:
        for f, v in fields.items():
            if v:
                self.db.execute("INSERT OR REPLACE INTO confirmation VALUES (?,?,?,?,?)", (ci_id, f, v, by, at))
        self.db.commit()

    def reconcile(self, snapshot: dict, now, cfg) -> dict:
        run_id = iso(now)
        existing = {r["id"]: dict(r) for r in self.db.execute("SELECT * FROM ci")}
        stats = {"created": 0, "updated": 0, "unchanged": 0, "missing": 0, "lifecycle_changed": 0}
        seen = set()
        for ci in snapshot["resources"]:
            cid = ci["id"]
            seen.add(cid)
            old = existing.get(cid)
            old_data = json.loads(old["data"]) if old else {}
            for f in STICKY:
                if ci.get(f) is None and old_data.get(f) is not None:
                    ci[f] = old_data[f]
            first_seen = old["first_seen"] if old else run_id
            last_alive = run_id if ci["alive"] else (old["last_alive"] if old else None)
            lifecycle = self._lifecycle(cfg, now, last_alive or first_seen, ci["alive"])
            if not old:
                stats["created"] += 1
                self._change(run_id, cid, "created", None, None, ci["hostname"])
            else:
                diffs = [(f, old_data.get(f), ci.get(f)) for f in TRACKED if old_data.get(f) != ci.get(f)]
                for f, a, b in diffs:
                    self._change(run_id, cid, "updated", f, a, b)
                stats["updated" if diffs else "unchanged"] += 1
                if old["lifecycle"] != lifecycle:
                    stats["lifecycle_changed"] += 1
                    self._change(run_id, cid, "lifecycle", "lifecycle", old["lifecycle"], lifecycle)
            self.db.execute(
                "INSERT OR REPLACE INTO ci VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (cid, ci["hostname"], lifecycle, "seen", ci.get("owner_team"), ci.get("service"),
                 ci.get("environment"), ci.get("criticality"), ci.get("owner_status"),
                 first_seen, run_id, last_alive, json.dumps(ci, ensure_ascii=False, default=str)))
            has_host = any(k.startswith("host:") for k in ci["identity_keys"])
            for key in ci["identity_keys"]:
                if not key.startswith("ip:") or not has_host:
                    self.db.execute("INSERT OR IGNORE INTO ci_key VALUES (?, ?)", (key, cid))

        for cid, old in existing.items():
            if cid in seen:
                continue
            stats["missing"] += 1
            lifecycle = self._lifecycle(cfg, now, old["last_alive"] or old["first_seen"], False)
            if lifecycle != old["lifecycle"] or old["presence"] != "missing":
                if lifecycle != old["lifecycle"]:
                    stats["lifecycle_changed"] += 1
                    self._change(run_id, cid, "lifecycle", "lifecycle", old["lifecycle"], lifecycle)
                self.db.execute("UPDATE ci SET lifecycle = ?, presence = 'missing' WHERE id = ?", (lifecycle, cid))

        stats["tasks"] = self._sync_tasks(snapshot, now, cfg)
        self.db.execute("INSERT OR REPLACE INTO run VALUES (?, ?)", (run_id, json.dumps(stats)))
        self.db.commit()
        return stats

    @staticmethod
    def _lifecycle(cfg, now, ref: str | None, alive: bool) -> str:
        if alive:
            return "active"
        age = days_between(now, parse_time(ref))
        if age < cfg.lifecycle["stale_after_days"]:
            return "active"
        if age < cfg.lifecycle["decommission_after_days"]:
            return "stale"
        return "decommission-candidate"

    def _change(self, run_id, ci_id, change, field, old, new):
        dump = lambda v: v if isinstance(v, str) or v is None else json.dumps(v, ensure_ascii=False)
        self.db.execute("INSERT INTO change VALUES (?,?,?,?,?,?)", (run_id, ci_id, change, field, dump(old), dump(new)))

    # ---------- задачи (workflow назначения владельцев) ----------
    def _desired_tasks(self, snapshot, now, cfg) -> dict:
        triage = cfg.main.get("triage_team", "platform")
        required = cfg.main.get("required_fields", list(CONFIRMABLE))
        want = {}

        def add(subject, typ, assignee, summary):
            # неизвестная словарю команда не может получить задачу — она уходит на триаж
            want[(subject, typ)] = (assignee if assignee in cfg.teams else triage, summary)

        for ci in self.rows():
            host, cid = ci["hostname"], ci["id"]
            subj = f"ci:{cid}"
            if ci["lifecycle"] in ("stale", "decommission-candidate"):
                days = int(days_between(now, parse_time(ci["last_alive"] or ci["first_seen"])))
                add(subj, "verify-decommission", ci.get("owner_team"),
                    f"{host}: не подаёт признаков жизни {days} дн. ({ci['lifecycle']}) — подтвердить вывод или вернуть в работу")
                continue
            st = ci.get("owner_status")
            if st == "unowned":
                hint = f"; подсказка: {ci['owner_suggestion']}" if ci.get("owner_suggestion") else ""
                add(subj, "assign-owner", triage, f"{host}: владелец не определён (источники: {', '.join(ci['sources'])}){hint}")
            elif st == "needs-confirmation":
                add(subj, "confirm-owner", ci.get("owner_team"),
                    f"{host}: подтвердите владение → {ci['owner_team']} / {ci.get('service') or '?'} (уверенность {ci['owner_confidence']})")
            elif st == "conflict":
                alts = ", ".join(f"{a['value']} ({a['confidence']})" for a in ci["attribution"]["owner_team"]["alternatives"])
                add(subj, "resolve-conflict", triage,
                    f"{host}: противоречивые данные о владельце: {ci['owner_team']} ({ci['owner_confidence']}) vs {alts}")
            elif st in ("auto", "confirmed"):
                missing = [f for f in required if not ci.get(f)]
                if missing:
                    add(subj, "fill-attributes", ci.get("owner_team"), f"{host}: заполнить {', '.join(missing)}")
            for c in ci.get("conflicts", []):
                add(subj, f"fix-{c['type']}", triage, f"{host}: {c['detail']}")
        for s in snapshot["services"]:
            if not s["registered"]:
                add(f"service:{s['name']}", "register-service", s.get("owner_team"),
                    f"сервис '{s['name']}' встречается в разметке ({len(s['hosts'])} хостов, "
                    f"{len(s['namespaces'])} ns), но его нет в каталоге")
        for ns in snapshot["namespaces"]:
            if ns["owner_status"] in ("unowned", "conflict", "needs-confirmation"):
                add(f"ns:{ns['id']}", "label-namespace", ns.get("owner_team"),
                    f"namespace {ns['id']}: проставить labels team/service/env (сейчас: {ns['owner_status']}"
                    + (f", кандидат {ns['owner_suggestion']}" if ns.get("owner_suggestion") else "") + ")")
        return want

    def _sync_tasks(self, snapshot, now, cfg) -> dict:
        ts = iso(now)
        want = self._desired_tasks(snapshot, now, cfg)
        current = {(r["subject"], r["type"]): dict(r) for r in self.db.execute("SELECT * FROM task")}
        stats = {"opened": 0, "resolved": 0, "open": len(want)}
        for (subject, typ), (assignee, summary) in want.items():
            cur = current.get((subject, typ))
            if not cur:
                stats["opened"] += 1
                self.db.execute("INSERT INTO task VALUES (?,?,?,?,?,?,?,?)",
                                (stable_id("task", subject, typ), subject, typ, assignee, "open", ts, ts, summary))
            else:
                if cur["status"] != "open":
                    stats["opened"] += 1
                self.db.execute("UPDATE task SET status='open', assignee=?, summary=?, updated_at=? WHERE id=?",
                                (assignee, summary, ts, cur["id"]))
        for key, cur in current.items():
            if key not in want and cur["status"] == "open":
                stats["resolved"] += 1
                self.db.execute("UPDATE task SET status='resolved', updated_at=? WHERE id=?", (ts, cur["id"]))
        return stats

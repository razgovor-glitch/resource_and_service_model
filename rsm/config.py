"""Загрузка конфигурации и словарей нормализации."""
from __future__ import annotations

import ipaddress
import re
from pathlib import Path

import yaml

from .util import as_list, norm_hostname, norm_token

# Поля, значения которых приводятся к словарю.
DICT_FIELDS = ("owner_team", "environment", "criticality", "service")


def load_yaml(path: Path, default=None):
    if not path.exists():
        return default if default is not None else {}
    with path.open(encoding="utf-8") as f:
        return yaml.safe_load(f) or (default if default is not None else {})


class Config:
    def __init__(self, config_dir="config", data_dir=None):
        self.dir = Path(config_dir)
        self.main = load_yaml(self.dir / "rsm.yaml")
        self.data_dir = Path(data_dir or self.main.get("data_dir", "data"))
        self.dictionary = load_yaml(self.dir / "dictionary.yaml")
        self.rules = load_yaml(self.dir / "attribution_rules.yaml").get("rules", [])
        self.catalog = dict(load_yaml(self.dir / "service_catalog.yaml").get("services") or {})
        self.catalog_origin = {name: "service_catalog.yaml" for name in self.catalog}
        people = load_yaml(self.dir / "people.yaml").get("people") or {}
        self.people = {norm_token(k): norm_token(v) for k, v in people.items()}
        self.overrides_csv = self.dir / "ownership_overrides.csv"

        self.thresholds = {"auto": 0.8, "needs_confirmation": 0.4, "conflict_margin": 0.25,
                           **(self.main.get("thresholds") or {})}
        self.lifecycle = {"stale_after_days": 7, "decommission_after_days": 30, "freshness_hours": 48,
                          **(self.main.get("lifecycle") or {})}
        self._host_blacklist = [re.compile(p, re.I) for p in self.main.get("hostname_blacklist", [])]
        self._ip_ignore = [ipaddress.ip_network(c, strict=False) for c in self.main.get("ip_ignore", [])]
        self._ip_conflict_ignore = [ipaddress.ip_network(c, strict=False)
                                    for c in self.main.get("ip_conflict_ignore", [])]
        self._build_aliases()

    # ---------- пути ----------
    def raw(self, *parts) -> Path:
        return self.data_dir.joinpath("raw", *parts)

    @property
    def staging_dir(self) -> Path:
        return self.data_dir / "staging"

    @property
    def snapshot_path(self) -> Path:
        return self.data_dir / "model" / "snapshot.json"

    @property
    def cmdb_path(self) -> Path:
        return self.data_dir / "cmdb.sqlite"

    @property
    def reports_dir(self) -> Path:
        return self.data_dir / "reports"

    def source_enabled(self, name: str) -> bool:
        return (self.main.get("sources", {}).get(name) or {}).get("enabled", True)

    # ---------- идентичность ----------
    def host_key(self, name) -> str | None:
        n = norm_hostname(name)
        if not n:
            return None
        short = n.split(".")[0]
        if any(p.fullmatch(short) or p.fullmatch(n) for p in self._host_blacklist):
            return None
        return short if self.main.get("hostname_key", "short") == "short" else n

    def ip_usable(self, ip) -> bool:
        try:
            a = ipaddress.ip_address(str(ip).strip())
        except ValueError:
            return False
        if a.is_loopback or a.is_link_local or a.is_unspecified or a.is_multicast:
            return False
        return not any(a in net for net in self._ip_ignore)

    def ip_conflict_ignored(self, ip) -> bool:
        a = ipaddress.ip_address(ip)
        return any(a in net for net in self._ip_conflict_ignore)

    def precedence(self, field: str) -> list[str]:
        p = self.main.get("precedence") or {}
        return p.get(field) or p.get("default") or []

    # ---------- словари ----------
    def _build_aliases(self) -> None:
        d = self.dictionary
        self.teams = d.get("teams") or {}
        self.alias: dict[str, dict[str, str]] = {f: {} for f in DICT_FIELDS}
        for team, spec in self.teams.items():
            for a in [team, *as_list((spec or {}).get("aliases"))]:
                self.alias["owner_team"][norm_token(a)] = team
        for env, aliases in (d.get("environments") or {}).items():
            for a in [env, *as_list(aliases)]:
                self.alias["environment"][norm_token(a)] = env
        for crit, aliases in (d.get("criticality") or {}).items():
            for a in [crit, *as_list(aliases)]:
                self.alias["criticality"][norm_token(a)] = crit
        for svc, spec in self.catalog.items():
            self._alias_service(svc, spec)

    def _alias_service(self, svc: str, spec: dict) -> None:
        for a in [svc, *as_list((spec or {}).get("aliases"))]:
            self.alias["service"][norm_token(a)] = svc

    def add_service(self, name: str, spec: dict, origin: str) -> None:
        """Сервис, найденный в Git (catalog-info.yaml): дополняет каталог, не перетирая ручной."""
        if name in self.catalog:
            merged = {**spec, **self.catalog[name]}
            merged["k8s_namespaces"] = sorted(set(as_list(spec.get("k8s_namespaces")))
                                              | set(as_list(self.catalog[name].get("k8s_namespaces"))))
            self.catalog[name] = merged
            self.catalog_origin[name] += f", {origin}"
        else:
            self.catalog[name] = spec
            self.catalog_origin[name] = origin
        self._alias_service(name, self.catalog[name])

    def normalize(self, field: str, value) -> tuple[str | None, bool]:
        """Вернуть (каноническое значение, известно ли оно словарю)."""
        if value in (None, ""):
            return None, False
        v = norm_token(value)
        table = self.alias.get(field)
        if table is None:
            return v, True
        if v in table:
            return table[v], True
        if field == "owner_team":
            stripped = re.sub(r"^(team-|group-)|(-team|-group|-devs?)$", "", v)
            if stripped in table:
                return table[stripped], True
        return v, False

    def support_model(self, criticality: str | None) -> str | None:
        return (self.dictionary.get("support_model") or {}).get(criticality) if criticality else None

    def env_criticality(self, environment: str | None) -> str | None:
        return (self.dictionary.get("env_criticality") or {}).get(environment) if environment else None

    def team_info(self, team: str | None) -> dict:
        return (self.teams.get(team) or {}) if team else {}

"""Git: каталог сервисов из репозиториев.

data/raw/git/<repo>/catalog-info.yaml  — дескриптор Backstage (kind: Component)
data/raw/git/<repo>/CODEOWNERS         — владельцы кода (fallback, если нет catalog-info)

Достаточно положить туда только эти файлы (sparse checkout / выгрузка через API GitLab).
"""
from __future__ import annotations

import re

import yaml

from .base import observation

CRITICALITY_ANNOTATIONS = ("rsm/criticality", "example.com/criticality", "criticality")


def _owner(value: str | None) -> str | None:
    if not value:
        return None
    return re.sub(r"^(group|user):", "", value).split("/")[-1]   # group:default/payments → payments


def _codeowners(path) -> list[str]:
    owners = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            parts = line.split()
            if parts[0] in ("*", "/"):
                owners += [o.lstrip("@").split("/")[-1] for o in parts[1:]]
    return owners


def collect(cfg) -> list[dict]:
    out = []
    base = cfg.raw("git")
    for repo in sorted(p for p in base.iterdir() if p.is_dir()) if base.exists() else []:
        codeowners = []
        for cand in (repo / "CODEOWNERS", repo / ".github" / "CODEOWNERS", repo / ".gitlab" / "CODEOWNERS"):
            if cand.exists():
                codeowners = _codeowners(cand)
                break
        catalog = repo / "catalog-info.yaml"
        docs = [d for d in yaml.safe_load_all(catalog.read_text(encoding="utf-8")) if d] if catalog.exists() else []
        components = [d for d in docs if d.get("kind") == "Component"]
        if not components and codeowners:
            components = [{"metadata": {"name": repo.name}, "spec": {"owner": codeowners[0]}}]
        for c in components:
            md, spec = c.get("metadata", {}), c.get("spec", {})
            ann = md.get("annotations") or {}
            ns = ann.get("backstage.io/kubernetes-namespace")
            out.append(observation(
                "git", "service",
                attrs={"name": md["name"], "owner_team": _owner(spec.get("owner")) or (codeowners or [None])[0],
                       "criticality": next((ann[k] for k in CRITICALITY_ANNOTATIONS if k in ann), None),
                       "lifecycle": spec.get("lifecycle"), "system": spec.get("system"),
                       "description": md.get("description"),
                       "repo": ann.get("gitlab.com/project-slug") or ann.get("github.com/project-slug") or repo.name,
                       "k8s_namespaces": [x.strip() for x in ns.split(",")] if ns else [],
                       "codeowners": codeowners},
                ref=f"git/{repo.name}"))
    return out

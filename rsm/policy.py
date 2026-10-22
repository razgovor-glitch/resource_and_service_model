"""Policy-as-code: новые ресурсы не должны появляться без меток владения.

  rsm policy check k8s/ terraform/ charts-rendered.yaml
  helm template my-chart | rsm policy check -

Проверяется:
  * Kubernetes-манифесты (Namespace, Deployment, StatefulSet, DaemonSet, CronJob, Job):
    metadata.labels содержит policy.k8s_required_labels, команда есть в словаре;
  * Terraform (*.tf): ресурсы из policy.terraform_resource_types содержат ключи
    policy.terraform_required_tags в tags/labels (или они заданы в default_tags провайдера).
Это лёгкая проверка для CI; в кластере то же самое обеспечивает Kyverno
(deploy/k8s/kyverno-require-ownership-labels.yaml).
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

import yaml

K8S_KINDS = {"Namespace", "Deployment", "StatefulSet", "DaemonSet", "CronJob", "Job"}


def _policy(cfg) -> dict:
    p = cfg.main.get("policy") or {}
    return {"k8s_required_labels": p.get("k8s_required_labels", ["team", "service", "env"]),
            "terraform_required_tags": p.get("terraform_required_tags", ["owner_team", "service", "environment"]),
            "terraform_resource_types": p.get("terraform_resource_types", [])}


def _iter_files(paths):
    for p in paths:
        if p == "-":
            yield "<stdin>", sys.stdin.read()
            continue
        path = Path(p)
        files = [path] if path.is_file() else sorted(x for x in path.rglob("*")
                                                       if x.suffix in (".yaml", ".yml", ".tf") and x.is_file())
        for f in files:
            yield str(f), f.read_text(encoding="utf-8")


def check_k8s(cfg, name, text, pol) -> list[str]:
    out = []
    try:
        docs = list(yaml.safe_load_all(text))
    except yaml.YAMLError as err:
        return [f"{name}: не YAML ({err.__class__.__name__}) — пропущен"] if name.endswith((".yaml", ".yml")) else []
    for d in docs:
        if not isinstance(d, dict) or d.get("kind") not in K8S_KINDS:
            continue
        md = d.get("metadata") or {}
        labels = md.get("labels") or {}
        obj = f"{d['kind']}/{md.get('name', '?')}"
        missing = [k for k in pol["k8s_required_labels"] if not labels.get(k)]
        if missing:
            out.append(f"{name}: {obj}: нет обязательных labels {missing}")
        team = labels.get("team")
        if team and not cfg.normalize("owner_team", team)[1]:
            out.append(f"{name}: {obj}: team='{team}' нет в dictionary.yaml")
    return out


def _blocks(text, header_re):
    for m in re.finditer(header_re, text):
        depth, i = 0, m.end() - 1
        while i < len(text):
            depth += {"{": 1, "}": -1}.get(text[i], 0)
            if depth == 0:
                yield m, text[m.end():i]
                break
            i += 1


def check_terraform(name, text, pol, default_tag_keys) -> list[str]:
    out = []
    types = set(pol["terraform_resource_types"])
    for m, body in _blocks(text, r'resource\s+"([\w-]+)"\s+"([\w-]+)"\s*\{'):
        rtype, rname = m.group(1), m.group(2)
        if types and rtype not in types:
            continue
        inherited = default_tag_keys if rtype.startswith("aws_") else set()
        missing = [k for k in pol["terraform_required_tags"]
                   if k not in inherited and not re.search(rf'["\']?\b{re.escape(k)}\b["\']?\s*[=:]', body)]
        if missing:
            out.append(f"{name}: {rtype}.{rname}: в tags/labels нет {missing}")
    return out


def check_paths(cfg, paths) -> list[str]:
    pol = _policy(cfg)
    files = list(_iter_files(paths))
    default_tag_keys = set()
    for name, text in files:
        if name.endswith(".tf"):
            for _, body in _blocks(text, r"default_tags\s*\{"):
                default_tag_keys |= set(re.findall(r'["\']?(\w+)["\']?\s*=', body))
    violations = []
    for name, text in files:
        if name.endswith(".tf"):
            violations += check_terraform(name, text, pol, default_tag_keys)
        else:
            violations += check_k8s(cfg, name, text, pol)
    return violations

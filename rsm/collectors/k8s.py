"""Kubernetes: выгрузки kubectl (-o json) по каждому кластеру.

  data/raw/k8s/<cluster>/nodes.json       kubectl get nodes -o json
  data/raw/k8s/<cluster>/namespaces.json  kubectl get namespaces -o json
  data/raw/k8s/<cluster>/workloads.json   kubectl get deploy,sts,ds -A -o json
  data/raw/k8s/<cluster>/pods.json        kubectl get pods -A -o json

Ноды — это хосты (склеиваются с vCenter/Ansible по systemUUID/имени/IP).
Namespaces и workloads — сервисный слой. По подам считается, чьи нагрузки
работают на каждой ноде (для атрибуции shared-нод и наследования критичности).
"""
from __future__ import annotations

import json
import re
from collections import defaultdict

from ..util import iso, parse_cpu_m, parse_mem_mb, parse_time, short_hostname
from .base import observation

NODE_POOL_LABELS = ("node-pool", "nodepool", "agentpool", "cloud.google.com/gke-nodepool",
                    "eks.amazonaws.com/nodegroup", "node.kubernetes.io/pool")
SKIP_LABEL_PREFIXES = ("beta.kubernetes.io/", "kubernetes.io/", "node.kubernetes.io/instance-type",
                       "topology.kubernetes.io/", "feature.node.kubernetes.io/")


def _items(path) -> list[dict]:
    if not path.exists():
        return []
    return json.loads(path.read_text(encoding="utf-8")).get("items", [])


def _workload_of(pod: dict) -> str:
    refs = pod["metadata"].get("ownerReferences") or []
    if not refs:
        return f"Pod/{pod['metadata']['name']}"
    kind, name = refs[0]["kind"], refs[0]["name"]
    if kind == "ReplicaSet":            # deploy-name-<pod-template-hash>
        return "Deployment/" + re.sub(r"-[a-z0-9]{6,10}$", "", name)
    if kind == "Job":                   # cronjob-name-<timestamp>
        return "CronJob/" + re.sub(r"-\d{6,}$", "", name)
    return f"{kind}/{name}"


def collect(cfg) -> list[dict]:
    out = []
    base = cfg.raw("k8s")
    for cdir in sorted(p for p in base.iterdir() if p.is_dir()) if base.exists() else []:
        cluster = cdir.name
        for n in _items(cdir / "nodes.json"):
            md, st = n["metadata"], n.get("status", {})
            info = st.get("nodeInfo", {})
            labels = md.get("labels") or {}
            internal = [a["address"] for a in st.get("addresses", []) if a["type"] == "InternalIP"]
            hostnames = [a["address"] for a in st.get("addresses", []) if a["type"] == "Hostname"]
            roles = {k.split("/", 1)[1] for k in labels if k.startswith("node-role.kubernetes.io/")}
            ready = next((c for c in st.get("conditions", []) if c.get("type") == "Ready"), {})
            pool = next((labels[k] for k in NODE_POOL_LABELS if k in labels), None)
            out.append(observation(
                "k8s", "host",
                keys={"uuid": [info.get("systemUUID")], "host": [md["name"], *hostnames], "ip": internal},
                attrs={"hostname": short_hostname(md["name"]),
                       "fqdn": md["name"] if "." in md["name"] else None, "ips": internal,
                       "os": info.get("osImage"), "kernel": info.get("kernelVersion"),
                       "cpu": parse_cpu_m((st.get("capacity") or {}).get("cpu")) // 1000 or None,
                       "memory_mb": parse_mem_mb((st.get("capacity") or {}).get("memory")) or None,
                       "uuid": info.get("systemUUID"), "k8s_cluster": cluster,
                       "k8s_role": "control-plane" if roles & {"control-plane", "master"} else "worker",
                       "k8s_version": info.get("kubeletVersion"), "k8s_node_uid": md.get("uid"),
                       "node_pool": pool,
                       "labels": {k: v for k, v in labels.items() if not k.startswith(SKIP_LABEL_PREFIXES)
                                  and not k.startswith("node-role.kubernetes.io/")},
                       "alive": ready.get("status") == "True",
                       "observed_at": iso(parse_time(ready.get("lastHeartbeatTime")))},
                ref=f"{cluster}/node/{md['name']}"))

        for ns in _items(cdir / "namespaces.json"):
            md = ns["metadata"]
            out.append(observation(
                "k8s", "k8s_namespace",
                attrs={"cluster": cluster, "name": md["name"], "uid": md.get("uid"),
                       "labels": {k: v for k, v in (md.get("labels") or {}).items()
                                  if k != "kubernetes.io/metadata.name"},
                       "annotations": {k: v for k, v in (md.get("annotations") or {}).items()
                                       if not k.startswith("kubectl.kubernetes.io/")},
                       "phase": (ns.get("status") or {}).get("phase")},
                ref=f"{cluster}/ns/{md['name']}"))

        for w in _items(cdir / "workloads.json"):
            md, spec = w["metadata"], w.get("spec", {})
            tpl = (spec.get("template") or {})
            labels = {**((tpl.get("metadata") or {}).get("labels") or {}), **(md.get("labels") or {})}
            ann = md.get("annotations") or {}
            containers = (tpl.get("spec") or {}).get("containers") or []
            out.append(observation(
                "k8s", "k8s_workload",
                attrs={"cluster": cluster, "namespace": md["namespace"], "kind": w["kind"], "name": md["name"],
                       "labels": labels, "replicas": spec.get("replicas"),
                       "images": [c.get("image") for c in containers],
                       "managed_by": labels.get("app.kubernetes.io/managed-by"),
                       "helm_release": ann.get("meta.helm.sh/release-name"),
                       "argocd_app": labels.get("argocd.argoproj.io/instance")
                       or (ann.get("argocd.argoproj.io/tracking-id") or "").split(":")[0] or None},
                ref=f"{cluster}/{md['namespace']}/{w['kind']}/{md['name']}"))

        agg = defaultdict(lambda: {"pods": 0, "cpu_m": 0, "mem_mb": 0})
        for pod in _items(cdir / "pods.json"):
            node = (pod.get("spec") or {}).get("nodeName")
            if not node or (pod.get("status") or {}).get("phase") in ("Succeeded", "Failed"):
                continue
            a = agg[(node, pod["metadata"]["namespace"], _workload_of(pod))]
            a["pods"] += 1
            for c in pod["spec"].get("containers", []):
                req = (c.get("resources") or {}).get("requests") or {}
                a["cpu_m"] += parse_cpu_m(req.get("cpu"))
                a["mem_mb"] += parse_mem_mb(req.get("memory"))
        for (node, ns, wl), a in sorted(agg.items()):
            out.append(observation(
                "k8s", "k8s_placement",
                attrs={"cluster": cluster, "node": node, "namespace": ns, "workload": wl, **a},
                ref=f"{cluster}/{node}/{ns}/{wl}"))
    return out

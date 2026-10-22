"""Сбор сырых данных из живых систем в data/raw/ (тонкие обёртки над штатными CLI/API).

Каждый fetch только сохраняет выгрузку; разбор делает `rsm collect`. Так сырые данные
можно приложить к тикету, сравнить между днями и перепрогнать правила без доступа к системам.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _run(cmd: list[str], out: Path | None = None) -> str:
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        raise RuntimeError(f"{' '.join(cmd)}\n{res.stderr.strip()}")
    if out:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(res.stdout, encoding="utf-8")
    return res.stdout


def _need(tool: str):
    if not shutil.which(tool):
        raise RuntimeError(f"не найден '{tool}' в PATH")


# ---------------------------------------------------------------- Kubernetes
K8S_QUERIES = {
    "nodes.json": ["get", "nodes"],
    "namespaces.json": ["get", "namespaces"],
    "workloads.json": ["get", "deployments,statefulsets,daemonsets", "-A"],
    "pods.json": ["get", "pods", "-A"],
}


def k8s_cluster_name(context: str) -> str:
    # admin@k8s-prod-eu → k8s-prod-eu; arn:aws:eks:...:cluster/prod → prod
    name = context.split("@")[-1].split("/")[-1]
    return re.sub(r"[^A-Za-z0-9._-]+", "-", name)


def fetch_k8s(cfg, contexts: list[str], kubeconfig: str | None = None, name: str | None = None) -> list[str]:
    _need("kubectl")
    if not contexts:
        contexts = _run(["kubectl", "config", "get-contexts", "-o", "name"]
                        + (["--kubeconfig", kubeconfig] if kubeconfig else [])).split()
    done = []
    for ctx in contexts:
        cluster = name if (name and len(contexts) == 1) else k8s_cluster_name(ctx)
        base = ["kubectl", "--context", ctx, "--request-timeout=60s"] + (["--kubeconfig", kubeconfig] if kubeconfig else [])
        for fname, args in K8S_QUERIES.items():
            _run(base + args + ["-o", "json"], cfg.raw("k8s", cluster, fname))
        done.append(cluster)
    return done


# ---------------------------------------------------------------- Zabbix
def fetch_zabbix(cfg) -> int:
    zc = cfg.main.get("zabbix") or {}
    url = os.environ.get(zc.get("url_env", "ZABBIX_URL"))
    token = os.environ.get(zc.get("token_env", "ZABBIX_TOKEN"))
    if not url or not token:
        raise RuntimeError("задайте ZABBIX_URL (https://zabbix.example.com) и ZABBIX_TOKEN (API token)")
    params = {"output": ["hostid", "host", "name", "status"],
              "selectInterfaces": ["ip", "dns", "type", "available"],
              "selectHostGroups": ["name"], "selectTags": "extend",
              "selectInventory": ["os", "serialno_a", "macaddress_a", "hardware"]}
    if zc.get("legacy_groups"):              # Zabbix < 6.2: selectGroups вместо selectHostGroups
        params["selectGroups"] = params.pop("selectHostGroups")
    body = {"jsonrpc": "2.0", "method": "host.get", "params": params, "id": 1}
    headers = {"Content-Type": "application/json-rpc"}
    if zc.get("auth_in_body"):               # Zabbix < 6.4: токен в поле auth
        body["auth"] = token
    else:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url.rstrip("/") + "/api_jsonrpc.php", data=json.dumps(body).encode(), headers=headers)
    with urllib.request.urlopen(req, timeout=120) as r:
        data = json.loads(r.read())
    if "error" in data:
        raise RuntimeError(f"Zabbix API: {data['error']}")
    out = cfg.raw("zabbix", "hosts.json")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(data["result"], ensure_ascii=False, indent=1), encoding="utf-8")
    return len(data["result"])


# ---------------------------------------------------------------- nmap
def fetch_nmap(cfg, targets: list[str], ports: str | None = None, name: str = "scan") -> str:
    _need("nmap")
    ports = ports or (cfg.main.get("nmap") or {}).get("ports", "22,80,443,3389,5432,1521,1433,3306,6443,10250")
    out = cfg.raw("nmap", f"{name}.xml")
    out.parent.mkdir(parents=True, exist_ok=True)
    # -sT не требует root; -R — rDNS для всех; --open — только открытые порты в выводе
    _run(["nmap", "-sT", "-R", "-T4", "--open", "-p", ports, "-oX", str(out), *targets])
    return str(out)


# ---------------------------------------------------------------- Ansible
def fetch_ansible(cfg, inventory: str, limit: str | None = None) -> str:
    _need("ansible-playbook")
    base = cfg.raw("ansible")
    (base / "facts").mkdir(parents=True, exist_ok=True)
    _run(["ansible-inventory", "-i", inventory, "--list"], base / "inventory.json")
    cmd = ["ansible-playbook", "-i", inventory, str(ROOT / "deploy" / "ansible" / "collect_facts.yml"),
           "-e", f"rsm_facts_dir={(base / 'facts').resolve()}"]
    if limit:
        cmd += ["--limit", limit]
    # Недоступные хосты не валят прогон: они попадут в модель как «объявлены, но не отвечают».
    subprocess.run(cmd)
    return str(base)

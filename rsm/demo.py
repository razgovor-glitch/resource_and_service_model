"""Демо-генератор: вымышленная компания на ~300 серверов и три «дня» discovery.

Данные нарочно «грязные», как в жизни:
  * теги в vCenter есть не везде, значения разнобойные («Payments», «pay», «платежи», «DWH»);
  * legacy без Ansible (RHEL 6, Windows), владелец только в Notes ВМ («Ответственный: i.petrov»);
  * UUID в Linux с переставленными байтами относительно vCenter;
  * гостевое имя «localhost», имя ВМ «paygw03 (old, do not delete)»;
  * зомби в Zabbix и DNS, переиспользованный IP, хосты, видимые только nmap (shadow IT);
  * ошибочный тег владельца (конфликт), namespaces без labels, неизвестная команда.
День 1 → 2 → 3: часть dev-ВМ удаляют, old-jira выключают, появляются новые хосты.
Для оценки качества пишется data/raw/_ground_truth.json (коллекторы его игнорируют).
"""
from __future__ import annotations

import json
import random
import shutil
import uuid as uuidlib
import xml.etree.ElementTree as ET
from collections import Counter
from pathlib import Path

import yaml

from .util import parse_time, swap_uuid

DOMAIN = "corp.example.com"
DAYS = {1: "2026-09-15T06:00:00Z", 2: "2026-10-08T06:00:00Z", 3: "2026-10-22T06:00:00Z"}
MARKER = ".rsm-demo"
PORT_NAMES = {21: "ftp", 22: "ssh", 25: "smtp", 53: "domain", 80: "http", 88: "kerberos-sec", 389: "ldap",
              443: "https", 445: "microsoft-ds", 514: "shell", 873: "rsync", 1433: "ms-sql-s", 1521: "oracle",
              1540: "1c-agent", 1541: "1c-manager", 1560: "1c-worker", 2379: "etcd-client", 3000: "ppp",
              3389: "ms-wbt-server", 3690: "svn", 5432: "postgresql", 6443: "sun-sr-https", 8020: "intu-ec-svcdisc",
              8080: "http-proxy", 8200: "trivnet1", 8443: "https-alt", 8530: "wsus", 9090: "zeus-admin",
              9092: "XmlIpcRegSvc", 9100: "jetdirect", 9200: "wap-wsp", 9870: "unknown", 10051: "zabbix-trapper",
              10250: "unknown", 16509: "libvirt"}


def _fmt_uuid(h: str) -> str:
    return f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:]}"


class Fleet:
    def __init__(self, seed: int = 7, dev_vms: int = 90):
        self.r = random.Random(seed)
        self.hosts: list[dict] = []
        self.pools: dict[str, int] = {}
        self._build(dev_vms)

    # ------------------------------------------------------------ модель «правды»
    def ip(self, net: str) -> str:
        n = self.pools.get(net, 11)
        self.pools[net] = n + 1
        return f"{net}.{n}"

    def add(self, name, net, team, service, env, os_name, ports, **kw) -> dict:
        r = self.r
        virtual = kw.pop("virtual", True)
        h = {"name": name, "ip": kw.pop("ip", None) or self.ip(net), "team": team, "service": service, "env": env,
             "os": os_name, "ports": ports, "virtual": virtual, "windows": kw.pop("windows", False),
             "k8s": kw.pop("k8s", None), "uuid": uuidlib.UUID(int=r.getrandbits(128)).hex,
             "mac": ("00:50:56" if virtual else r.choice(["f8:bc:12", "3c:ec:ef", "b4:96:91"]))
             + "".join(f":{r.randrange(256):02x}" for _ in range(3)),
             "vc_tags": kw.pop("vc_tags", {}), "annotation": kw.pop("annotation", None),
             "ansible": kw.pop("ansible", True), "groups": kw.pop("groups", []), "hostvars": kw.pop("hostvars", {}),
             "local_facts": kw.pop("local_facts", None),
             "zabbix": kw.pop("zabbix", True), "zbx_groups": kw.pop("zbx_groups", ["Linux servers"]),
             "zbx_tags": kw.pop("zbx_tags", {}), "dns": kw.pop("dns", True),
             "vm_name": kw.pop("vm_name", None), "guest_hostname": kw.pop("guest_hostname", None),
             "ansible_hostname": kw.pop("ansible_hostname", None),
             "cpu": kw.pop("cpu", r.choice([2, 4, 4, 8])), "mem": kw.pop("mem", r.choice([4096, 8192, 16384])),
             "vendor": kw.pop("vendor", None), "model": kw.pop("model", None),
             "vc_cluster": kw.pop("vc_cluster", "DC1-Prod"),
             "added_day": kw.pop("added_day", 1), "removed_day": kw.pop("removed_day", None),
             "off_day": kw.pop("off_day", None), "ghost": kw.pop("ghost", False), "shadow": kw.pop("shadow", False),
             "ptr": kw.pop("ptr", None)}
        assert not kw, f"unknown args {kw}"
        h["swapped"] = virtual and r.random() < 0.15
        h["serial"] = ("VMware-" + " ".join(h["uuid"][i:i + 2] for i in range(0, 16, 2)) + "-"
                       + " ".join(h["uuid"][i:i + 2] for i in range(16, 32, 2))) if virtual else \
            "".join(r.choice("BCDFGHJKLMNPQRSTVWXYZ0123456789") for _ in range(7))
        self.hosts.append(h)
        return h

    def _build(self, dev_vms: int) -> None:
        r = self.r
        # --- Kubernetes: ноды принадлежат платформе ---
        for cluster, net, cps, workers, physical, env in (("k8s-prod-eu", "10.10.10", 3, 48, False, "prod"),
                                                          ("k8s-stage", "10.10.20", 3, 12, False, "stage"),
                                                          ("k8s-dev", "10.10.30", 1, 8, True, "dev")):
            prefix = cluster.removesuffix("-eu")
            for i in range(cps + workers):
                cp = i < cps
                self.add(f"{prefix}-cp-{i + 1:02d}" if cp else f"{prefix}-w-{i - cps + 1:02d}", net,
                         "platform", "kubernetes-platform", env, "Ubuntu 22.04", [22, 10250] + ([6443, 2379] if cp else []),
                         virtual=not physical, k8s=(cluster, "control-plane" if cp else "worker"),
                         vc_tags={"owner": "platform", "env": env} if r.random() < 0.7 else {},
                         ansible=r.random() < 0.95, groups=[f"k8s_{env}_{'masters' if cp else 'workers'}"],
                         zabbix=r.random() < 0.9, zbx_groups=["Kubernetes", "Linux servers"],
                         cpu=8 if cp else 16, mem=16384 if cp else 65536, vc_cluster="DC1-K8s",
                         vendor="Dell Inc." if physical else None, model="PowerEdge R630" if physical else None)
        # --- Платежи: legacy-шлюз ---
        owners = ["Payments", "pay", "платежи", None, None, "payments"]
        for i in range(1, 7):
            self.add(f"paygw{i:02d}", "10.20.30", "payments", "payment-gateway-legacy", "prod", "CentOS 7.9", [22, 8443],
                     vc_tags={"owner": owners[i - 1]} if owners[i - 1] else {},
                     vm_name=f"paygw{i:02d} (old, do not delete)" if i == 3 else None,
                     ansible=i != 4, groups=["paygw_prod"], zbx_groups=["Teams/Payments", "Linux servers"])
        for i in (1, 2):
            self.add(f"pay-db-{i:02d}", "10.20.30", "payments", "payment-gateway-legacy", "prod", "CentOS 7.9",
                     [22, 5432], groups=["paydb_prod"], zbx_groups=["Teams/Payments", "PostgreSQL"])
        # --- Биллинг: современная конвенция имён ---
        for i in range(1, 7):
            tags = {"owner": "billing", "service": "billing-core", "env": "prod"} if r.random() < 0.5 else {}
            if i == 5:
                tags = {"owner": "crm"}                  # ошибка разметки → конфликт
            self.add(f"prod-billing-app-{i:02d}", "10.20.40", "billing", "billing-core", "prod", "Ubuntu 20.04",
                     [22, 8080], vc_tags=tags, groups=["billing_core_prod"], hostvars={"owner_team": "billing"},
                     zbx_groups=["Teams/Billing"])
        for i in range(1, 4):
            self.add(f"prod-billing-db-{i:02d}", "10.20.40", "billing", "billing-core", "prod", "Ubuntu 20.04",
                     [22, 5432], groups=["billing_core_prod"], zbx_groups=["Teams/Billing", "PostgreSQL"])
        for i in (1, 2):
            self.add(f"stg-billing-app-{i:02d}", "10.20.40", "billing", "billing-core", "stage", "Ubuntu 20.04",
                     [22, 8080], groups=["billing_core_stage"], zabbix=False, vc_cluster="DC1-Dev")
        # --- 1С: Windows, без Ansible, владелец только в Notes ---
        for i in range(1, 5):
            self.add(f"srv-1c-app-{i:02d}", "10.30.0", "erp", "1c-erp", "prod", "Microsoft Windows Server 2019",
                     [445, 1540, 1541, 1560, 3389], windows=True, ansible=False,
                     annotation="Ответственный: i.petrov" if i in (1, 3) else None, zbx_groups=["Windows servers", "1C"])
        for i in (1, 2):
            self.add(f"srv-1c-sql-{i:02d}", "10.30.0", "erp", "1c-erp", "prod", "Microsoft Windows Server 2019",
                     [445, 1433, 3389], windows=True, ansible=False,
                     annotation="Ответственный: i.petrov" if i == 1 else None, zbx_groups=["Windows servers", "MSSQL"])
        # --- CRM legacy: RHEL 6 (Ansible не работает) + физические Oracle ---
        for i in range(1, 5):
            self.add(f"crm-app-{i:02d}", "10.20.50", "crm", "crm-legacy", "prod", "Red Hat Enterprise Linux 6.10",
                     [22, 8080], ansible=False, annotation="owner: s.kuznetsov" if i <= 2 else None,
                     zbx_groups=["Teams/CRM"], zbx_tags={"team": "crm"} if i == 4 else {})
        for i in (1, 2):
            self.add(f"oradb-crm-{i:02d}", "10.20.50", "crm", "crm-legacy", "prod", "Oracle Linux 7.9", [22, 1521],
                     virtual=False, vendor="HPE", model="ProLiant DL380 Gen10", groups=["crm_prod"],
                     zbx_groups=["Teams/CRM", "Oracle"], cpu=32, mem=262144)
        # --- Данные ---
        for i in range(1, 17):
            self.add(f"dwh-node-{i:02d}", "10.40.0", "data", "data-warehouse", "prod", "Ubuntu 22.04",
                     [22, 8020, 9870], virtual=False, vendor="Dell Inc.", model="PowerEdge R740xd",
                     ansible=r.random() < 0.9, groups=["dwh_prod"], zbx_groups=["Teams/Data"], cpu=48, mem=393216)
        for i in range(1, 6):
            self.add(f"kafka-{i:02d}", "10.40.0", "data", "data-streaming", "prod", "Ubuntu 22.04", [22, 9092],
                     vc_tags={"owner": "DWH", "service": "kafka"} if r.random() < 0.7 else {},
                     groups=["kafka_prod"], zbx_groups=["Teams/Data"])
        for i in (1, 2):
            self.add(f"airflow-{i:02d}", "10.40.0", "data", "data-warehouse", "prod", "Ubuntu 22.04", [22, 8080],
                     vc_tags={"owner": "data"}, groups=["airflow_prod"], zbx_groups=["Teams/Data"])
        # --- Веб ---
        for i in range(1, 9):
            self.add(f"prod-web-portal-{i:02d}", "10.50.0", "web", "web-portal", "prod", "Ubuntu 22.04", [22, 80, 443],
                     vc_tags={"owner": "web"} if r.random() < 0.6 else {}, groups=["web_portal_prod"],
                     zbx_groups=["Teams/Web"])
        for i in (1, 2):
            self.add(f"stg-web-portal-{i:02d}", "10.50.0", "web", "web-portal", "stage", "Ubuntu 22.04", [22, 80, 443],
                     groups=["web_portal_stage"], zabbix=False, vc_cluster="DC1-Dev")
        # --- Офисная инфраструктура ---
        for name, ports in (("dc01", [53, 88, 389, 445, 3389]), ("dc02", [53, 88, 389, 445, 3389]),
                            ("fs01", [445, 3389]), ("print01", [445, 3389]), ("wsus01", [3389, 8530])):
            self.add(name, "10.60.0", "it-ops", "office-infra", "prod", "Microsoft Windows Server 2016", ports,
                     windows=True, ansible=False, zbx_groups=["Office", "Windows servers"])
        # --- Мониторинг и CI (платформа) ---
        for name, ports in ([("mon-zbx-01", [22, 80, 10051]), ("prom-01", [22, 9090]), ("prom-02", [22, 9090]),
                             ("grafana-01", [22, 3000])] + [(f"elk-{i:02d}", [22, 9200]) for i in range(1, 7)]):
            self.add(name, "10.70.0", "platform", "monitoring", "prod", "Ubuntu 22.04", ports,
                     vc_tags={"owner": "platform"} if r.random() < 0.5 else {}, groups=["monitoring_prod"],
                     zbx_groups=["Teams/Platform"])
        for i in range(1, 11):
            self.add(f"gitlab-runner-{i:02d}", "10.70.1", "platform", "ci-runners", "prod", "Ubuntu 22.04", [22],
                     vc_tags={"owner": "platform", "service": "ci-runners"} if r.random() < 0.3 else {},
                     groups=["ci_runners_prod"], zabbix=r.random() < 0.5, zbx_groups=["Teams/Platform"],
                     local_facts={"team": "platform", "service": "ci-runners"} if i <= 5 else None)
        # --- Безопасность: доступа Ansible нет ---
        for name, ports in [(f"siem-{i:02d}", [22, 443, 514]) for i in (1, 2, 3)] + \
                           [(f"vault-{i:02d}", [22, 8200]) for i in (1, 2, 3)]:
            self.add(name, "10.80.0", "security", "security-tools", "prod", "Rocky Linux 9.4", ports, ansible=False,
                     zbx_groups=["Teams/Security"])
        # --- Dev-ВМ команд ---
        svc_team = [("payment-api", "payments"), ("billing-core", "billing"), ("web-portal", "web"),
                    ("crm-legacy", "crm"), ("data-warehouse", "data"), ("notification-worker", "web")]
        for i in range(1, dev_vms + 1):
            svc, team = r.choice(svc_team)
            tagged = r.random() < 0.4
            self.add(f"dev-{svc}-{i:02d}", f"10.120.{i // 200}", team, svc, "dev",
                     r.choice(["Ubuntu 22.04", "Ubuntu 20.04", "Debian 12"]), [22] + ([8080] if r.random() < 0.5 else []),
                     vc_tags={"owner": team, "env": "dev"} if tagged else ({"env": "dev"} if r.random() < 0.5 else {}),
                     ansible=r.random() < 0.6, groups=["dev"], zabbix=r.random() < 0.3, zbx_groups=["Dev"],
                     dns=r.random() < 0.7, vc_cluster="DC1-Dev",
                     removed_day=2 if i in (3, 11, 19, 27, 35) else (3 if i in (44, 52, 60) else None))
        for i in (dev_vms + 1, dev_vms + 2):
            self.add(f"dev-web-portal-{i:02d}", "10.120.0", "web", "web-portal", "dev", "Ubuntu 24.04", [22, 8080],
                     vc_tags={"owner": "web", "env": "dev"}, groups=["dev"], zabbix=False, vc_cluster="DC1-Dev",
                     added_day=3)
        # --- Legacy-зоопарк: владельцы неизвестны или только в головах ---
        zoo = [("test-ivanov", None, [22], {"removed_day": 3}),
               ("tmp-srv-03", None, [22], {"removed_day": 2}),
               ("old-jira", "web", [22, 8080], {"annotation": "Ответственный: k.volkov", "off_day": 2}),
               ("build-old", "platform", [22, 8080], {}),
               ("ws2012-fs01", None, [445, 3389], {"windows": True, "ansible": False}),
               ("ftp-legacy", None, [21, 22], {}),
               ("mail-relay-old", "it-ops", [22, 25], {"zbx_groups": ["Office"]}),
               ("svn01", "platform", [22, 3690], {}),
               ("redmine", "web", [22, 80], {}),
               ("backup-old-01", "it-ops", [22, 873], {}),
               ("lab-01", None, [22], {}),
               ("lab-02", None, [22], {"guest_hostname": "localhost.localdomain", "ansible_hostname": "localhost",
                                       "dns": False}),
               ("kvm-host-03", None, [22, 16509], {"virtual": False, "vendor": "Supermicro", "model": "SYS-1029P"}),
               ("oracle-test", "crm", [22, 1521], {"annotation": "owner: s.kuznetsov"}),
               ("report-srv", "data", [22, 80], {"annotation": "owner: a.ivanov"}),
               ("legacy-api-02", None, [22, 8080], {})]
        for name, team, ports, extra in zoo:
            extra.setdefault("ansible", r.random() < 0.5)
            extra.setdefault("dns", r.random() < 0.5)
            self.add(name, "10.90.0", team, None, None, extra.pop("os", "CentOS 7.9" if "windows" not in extra
                                                                   else "Microsoft Windows Server 2012 R2"),
                     ports, groups=["legacy"], zabbix=r.random() < 0.5, vc_cluster="DC1-Legacy", **extra)
        # --- Зомби: давно выключены, но живут в Zabbix и DNS ---
        web08 = next(h for h in self.hosts if h["name"] == "prod-web-portal-08")
        self.add("web-old-07", "10.50.0", "web", None, None, "CentOS 6", [], ip=web08["ip"], ghost=True,
                 ansible=False, zbx_groups=["Teams/Web"])
        self.add("nagios-old", "10.90.0", None, None, None, "CentOS 6", [], ghost=True, ansible=False)
        # --- Shadow IT: видны только nmap ---
        for i, ports in enumerate([[22], [80, 443], [3389], [9100], [22, 8080], [22, 5432]]):
            self.add(f"shadow-{i}", "10.90.0", None, None, None, None, ports, ip=f"10.90.0.{200 + i}", shadow=True)
        for i, ports in enumerate([[22], [80], [22, 3306]]):
            self.add(f"shadow-new-{i}", "10.90.0", None, None, None, None, ports, ip=f"10.90.0.{208 + i}",
                     shadow=True, added_day=3, ptr=f"host-10-90-0-{208 + i}.{DOMAIN}" if i == 0 else None)

    # ------------------------------------------------------------ состояния по дням
    @staticmethod
    def exists(h, day):
        return h["added_day"] <= day and (h["removed_day"] is None or day < h["removed_day"])

    def powered(self, h, day):
        return self.exists(h, day) and not h["ghost"] and (h["off_day"] is None or day < h["off_day"])

    # ------------------------------------------------------------ выгрузки
    def write_raw(self, raw: Path, day: int) -> None:
        if raw.exists():
            shutil.rmtree(raw)
        raw.mkdir(parents=True)
        ts = DAYS[day]
        self._nmap(raw, day, ts)
        self._dns(raw)
        self._vcenter(raw, day, ts)
        self._ansible(raw, day, ts)
        self._zabbix(raw, day)
        self._k8s(raw, day, ts)
        self._git(raw)
        truth = {h["name"]: {"team": h["team"], "service": h["service"], "env": h["env"]}
                 for h in self.hosts if not h["shadow"]}
        (raw / "_ground_truth.json").write_text(json.dumps(truth, ensure_ascii=False, indent=1), encoding="utf-8")

    def _nmap(self, raw, day, ts):
        root = ET.Element("nmaprun", scanner="nmap", version="7.95", start=str(int(parse_time(ts).timestamp())),
                          args="nmap -sT -R -T4 --open -p 21,22,25,53,80,... 10.0.0.0/8")
        for h in self.hosts:
            if not self.powered(h, day):
                continue
            he = ET.SubElement(root, "host")
            ET.SubElement(he, "status", state="up", reason="conn-refused")
            ET.SubElement(he, "address", addr=h["ip"], addrtype="ipv4")
            if h["ip"].startswith("10.90.0.") and not h["shadow"]:      # сканер в том же L2 — видит MAC
                ET.SubElement(he, "address", addr=h["mac"].upper(), addrtype="mac",
                              vendor="VMware" if h["virtual"] else "Unknown")
            hn = ET.SubElement(he, "hostnames")
            if h["dns"] and not h["shadow"]:
                ET.SubElement(hn, "hostname", name=f"{h['name']}.{DOMAIN}", type="PTR")
            elif h["ptr"]:
                ET.SubElement(hn, "hostname", name=h["ptr"], type="PTR")
            ports = ET.SubElement(he, "ports")
            for p in h["ports"]:
                pe = ET.SubElement(ports, "port", protocol="tcp", portid=str(p))
                ET.SubElement(pe, "state", state="open", reason="syn-ack")
                ET.SubElement(pe, "service", name=PORT_NAMES.get(p, "unknown"), method="table", conf="3")
        (raw / "nmap").mkdir()
        ET.ElementTree(root).write(raw / "nmap" / "scan.xml", encoding="utf-8", xml_declaration=True)

    def _dns(self, raw):
        (raw / "dns").mkdir()
        with (raw / "dns" / f"{DOMAIN}.csv").open("w", encoding="utf-8") as f:
            f.write("name,type,value\n")
            for h in self.hosts:
                if h["dns"] and not h["shadow"]:         # записи живут дольше серверов
                    f.write(f"{h['name']}.{DOMAIN},A,{h['ip']}\n")

    def _vcenter(self, raw, day, ts):
        vms = []
        for h in self.hosts:
            if not h["virtual"] or h["ghost"] or h["shadow"] or not self.exists(h, day) or \
                    (h["k8s"] and h["k8s"][0] == "k8s-dev"):
                continue
            on = self.powered(h, day)
            vms.append({"name": h["vm_name"] or h["name"], "uuid": _fmt_uuid(h["uuid"]),
                        "instance_uuid": str(uuidlib.UUID(int=int(h["uuid"], 16) ^ 0xFFFF)),
                        "guest_hostname": (h["guest_hostname"] or f"{h['name']}.{DOMAIN}") if on else None,
                        "ip_addresses": [h["ip"]] if on else [], "mac_addresses": [h["mac"]],
                        "guest_os": h["os"], "num_cpu": h["cpu"], "memory_mb": h["mem"],
                        "power_state": "PoweredOn" if on else "PoweredOff", "cluster": h["vc_cluster"],
                        "datacenter": "DC1", "folder": f"/vm/{(h['team'] or 'Discovered virtual machine')}",
                        "esxi_host": f"esxi-{self.r.randint(1, 24):02d}.{DOMAIN}",
                        "tags": {k: v for k, v in h["vc_tags"].items() if v}, "annotation": h["annotation"] or "",
                        "custom_attributes": {}})
        (raw / "vcenter").mkdir()
        (raw / "vcenter" / "vc01.json").write_text(json.dumps({"exported_at": ts, "vcenter": f"vc01.{DOMAIN}",
                                                               "vms": vms}, ensure_ascii=False, indent=1),
                                                   encoding="utf-8")

    def _linux_uuid(self, h):
        u = swap_uuid(h["uuid"]) if h["swapped"] else h["uuid"]
        return _fmt_uuid(u).upper() if h["swapped"] else _fmt_uuid(u)

    def _ansible(self, raw, day, ts):
        facts_dir = raw / "ansible" / "facts"
        facts_dir.mkdir(parents=True)
        inv = {"_meta": {"hostvars": {}}, "all": {"children": ["ungrouped"]}}
        for h in self.hosts:
            if not h["ansible"] or h["windows"] or h["ghost"] or h["shadow"] or not self.exists(h, day):
                continue
            for g in h["groups"]:
                inv.setdefault(g, {"hosts": []})["hosts"].append(h["name"])
                if g not in inv["all"]["children"]:
                    inv["all"]["children"].append(g)
            inv["_meta"]["hostvars"][h["name"]] = {"ansible_host": h["ip"], **h["hostvars"]}
            if not self.powered(h, day):
                continue
            dist, _, ver = h["os"].rpartition(" ")
            ips = [h["ip"]] + (["172.17.0.1"] if self.r.random() < 0.3 else []) + \
                (["10.244.0.1"] if h["k8s"] else [])
            facts = {"ansible_hostname": h["ansible_hostname"] or h["name"],
                     "ansible_fqdn": f"{h['name']}.{DOMAIN}" if not h["ansible_hostname"] else "localhost.localdomain",
                     "ansible_default_ipv4": {"address": h["ip"], "macaddress": h["mac"], "interface": "ens192"},
                     "ansible_all_ipv4_addresses": ips,
                     "ansible_product_uuid": self._linux_uuid(h),
                     "ansible_product_serial": h["serial"],
                     "ansible_system_vendor": "VMware, Inc." if h["virtual"] else h["vendor"],
                     "ansible_product_name": "VMware Virtual Platform" if h["virtual"] else h["model"],
                     "ansible_virtualization_role": "guest" if h["virtual"] else ("host" if "kvm" in h["name"] else "NA"),
                     "ansible_virtualization_type": "VMware" if h["virtual"] else ("kvm" if "kvm" in h["name"] else "NA"),
                     "ansible_distribution": dist, "ansible_distribution_version": ver,
                     "ansible_kernel": "5.15.0-119-generic", "ansible_processor_vcpus": h["cpu"],
                     "ansible_memtotal_mb": h["mem"], "ansible_date_time": {"iso8601": ts}}
            if h["local_facts"]:
                facts["ansible_local"] = {"rsm": h["local_facts"]}
            (facts_dir / h["name"]).write_text(json.dumps({"ansible_facts": facts, "changed": False}), encoding="utf-8")
        (raw / "ansible" / "inventory.json").write_text(json.dumps(inv, indent=1), encoding="utf-8")

    def _zabbix(self, raw, day):
        out = []
        for i, h in enumerate(self.hosts):
            if not h["zabbix"] or h["shadow"] or day < h["added_day"]:
                continue
            on = self.powered(h, day)
            if not on and not h["ghost"] and h["removed_day"] and self.r.random() < 0.5:
                continue                                  # половину удалённых из Zabbix всё же убрали
            out.append({"hostid": str(10500 + i), "host": h["name"], "name": h["name"].upper() if h["windows"] else h["name"],
                        "status": "0",
                        "interfaces": [{"ip": h["ip"], "dns": f"{h['name']}.{DOMAIN}", "type": "1",
                                        "available": "1" if on else "2"}],
                        "hostgroups": [{"name": g} for g in h["zbx_groups"]],
                        "tags": [{"tag": k, "value": v} for k, v in h["zbx_tags"].items()],
                        "inventory": {"os": h["os"], "serialno_a": "" if h["virtual"] else h["serial"],
                                      "macaddress_a": ""}})
        (raw / "zabbix").mkdir()
        (raw / "zabbix" / "hosts.json").write_text(json.dumps(out, ensure_ascii=False, indent=1), encoding="utf-8")

    # ------------------------------------------------------------ Kubernetes
    NAMESPACES = {
        "k8s-prod-eu": [
            ("kube-system", {}, {}, [("Deployment", "coredns", 2, "100m"), ("DaemonSet", "kube-proxy", 0, "50m")]),
            ("monitoring", {"team": "platform", "service": "monitoring", "env": "prod"}, {},
             [("StatefulSet", "prometheus", 2, "1000m"), ("DaemonSet", "node-exporter", 0, "50m"),
              ("Deployment", "grafana", 1, "200m")]),
            ("ingress-nginx", {}, {}, [("Deployment", "ingress-nginx-controller", 3, "500m")]),
            ("argocd", {"team": "platform"}, {}, [("Deployment", "argocd-server", 2, "250m"),
                                                  ("StatefulSet", "argocd-application-controller", 1, "500m")]),
            ("cert-manager", {}, {}, [("Deployment", "cert-manager", 1, "50m")]),
            ("payments", {"team": "payments", "service": "payment-api", "env": "prod"}, {},
             [("Deployment", "payment-api", 6, "500m"), ("Deployment", "payment-worker", 4, "250m")]),
            ("billing", {"team": "billing"}, {}, [("Deployment", "billing-core-api", 6, "1000m"),
                                                  ("Deployment", "billing-scheduler", 1, "200m")]),
            ("web-portal", {}, {}, [("Deployment", "portal-frontend", 8, "200m"), ("Deployment", "portal-bff", 4, "500m")]),
            ("notifications", {}, {}, [("Deployment", "notification-worker", 3, "250m")]),
            ("data-pipelines", {"team": "dwh"}, {}, [("Deployment", "etl-runner", 4, "1000m"),
                                                     ("Deployment", "spark-operator", 1, "200m")]),
            ("recommendations", {"team": "ml-team", "service": "recsys"}, {}, [("Deployment", "recsys-api", 3, "1000m")]),
            ("sandbox-ivanov", {}, {}, [("Deployment", "test-app", 1, "100m")]),
            ("legacy-migration", {}, {"owner": "s.kuznetsov"},
             [("Deployment", "crm-sync", 2, "500m", {"app.kubernetes.io/part-of": "crm-legacy"})]),
        ],
        "k8s-stage": [
            ("kube-system", {}, {}, [("Deployment", "coredns", 2, "100m"), ("DaemonSet", "kube-proxy", 0, "50m")]),
            ("monitoring", {"team": "platform", "service": "monitoring", "env": "stage"}, {},
             [("StatefulSet", "prometheus", 1, "500m")]),
            ("payments", {"team": "payments", "service": "payment-api", "env": "stage"}, {},
             [("Deployment", "payment-api", 2, "250m")]),
            ("billing", {"team": "billing"}, {}, [("Deployment", "billing-core-api", 2, "500m")]),
            ("web-portal", {}, {}, [("Deployment", "portal-frontend", 2, "100m")]),
            ("notifications", {}, {}, [("Deployment", "notification-worker", 1, "100m")]),
            ("qa-autotests", {}, {}, [("Deployment", "selenium-grid", 4, "500m")]),
        ],
        "k8s-dev": [
            ("kube-system", {}, {}, [("Deployment", "coredns", 1, "100m"), ("DaemonSet", "kube-proxy", 0, "50m")]),
            ("payments", {"team": "payments", "service": "payment-api", "env": "dev"}, {},
             [("Deployment", "payment-api", 1, "250m")]),
            ("ml-experiments", {}, {}, [("Deployment", "jupyterhub", 1, "2000m")]),
        ],
    }

    def _k8s(self, raw, day, ts):
        for cluster, namespaces in self.NAMESPACES.items():
            cdir = raw / "k8s" / cluster
            cdir.mkdir(parents=True)
            nodes = [h for h in self.hosts if h["k8s"] and h["k8s"][0] == cluster and self.powered(h, day)]
            workers = [h for h in nodes if h["k8s"][1] == "worker"]
            fqdn_names = cluster == "k8s-stage"
            node_name = (lambda h: f"{h['name']}.{DOMAIN}") if fqdn_names else (lambda h: h["name"])
            node_items = []
            for h in nodes:
                labels = {"kubernetes.io/hostname": node_name(h), "kubernetes.io/os": "linux",
                          "node-pool": "system" if h["k8s"][1] != "worker" else "general"}
                if h["k8s"][1] == "control-plane":
                    labels["node-role.kubernetes.io/control-plane"] = ""
                node_items.append({
                    "apiVersion": "v1", "kind": "Node",
                    "metadata": {"name": node_name(h), "uid": str(uuidlib.UUID(int=int(h["uuid"], 16) ^ 0xABCDEF)),
                                 "labels": labels},
                    "status": {"addresses": [{"type": "InternalIP", "address": h["ip"]},
                                             {"type": "Hostname", "address": node_name(h)}],
                               "capacity": {"cpu": str(h["cpu"]), "memory": f"{h['mem'] * 1024}Ki"},
                               "conditions": [{"type": "Ready", "status": "True", "lastHeartbeatTime": ts}],
                               "nodeInfo": {"systemUUID": self._linux_uuid(h).upper(), "osImage": "Ubuntu 22.04.4 LTS",
                                            "kubeletVersion": "v1.30.4", "kernelVersion": "5.15.0-119-generic"}}})
            ns_items, wl_items, pods = [], [], []
            for ns, labels, ann, wls in namespaces:
                ns_items.append({"apiVersion": "v1", "kind": "Namespace",
                                 "metadata": {"name": ns, "uid": str(uuidlib.UUID(int=self.r.getrandbits(128))),
                                              "labels": {"kubernetes.io/metadata.name": ns, **labels},
                                              "annotations": ann},
                                 "status": {"phase": "Active"}})
                for wl in wls:
                    kind, name, replicas, cpu = wl[:4]
                    extra = wl[4] if len(wl) > 4 else {}
                    wlabels = {"app.kubernetes.io/name": name, **extra}
                    spec = {"template": {"metadata": {"labels": wlabels}, "spec": {"containers": [
                        {"name": name, "image": f"registry.{DOMAIN}/{ns}/{name}:1.{self.r.randint(0, 9)}.{self.r.randint(0, 30)}",
                         "resources": {"requests": {"cpu": cpu, "memory": "512Mi"}}}]}}}
                    if kind != "DaemonSet":
                        spec["replicas"] = replicas
                    wl_items.append({"apiVersion": "apps/v1", "kind": kind,
                                     "metadata": {"name": name, "namespace": ns, "labels": wlabels,
                                                  "annotations": {"meta.helm.sh/release-name": name}},
                                     "spec": spec})
                    targets = nodes if kind == "DaemonSet" else [self.r.choice(workers) for _ in range(replicas)]
                    for j, node in enumerate(targets):
                        if kind == "Deployment":
                            owner = {"kind": "ReplicaSet", "name": f"{name}-7d9f8c6b5"}
                            pod_name = f"{name}-7d9f8c6b5-{self.r.randrange(36 ** 5):05x}"
                        else:
                            owner = {"kind": kind, "name": name}
                            pod_name = f"{name}-{j}"
                        pods.append({"apiVersion": "v1", "kind": "Pod",
                                     "metadata": {"name": pod_name, "namespace": ns, "ownerReferences": [owner]},
                                     "spec": {"nodeName": node_name(node), "containers": [
                                         {"name": name, "resources": {"requests": {"cpu": cpu, "memory": "512Mi"}}}]},
                                     "status": {"phase": "Running"}})
            for fname, items in (("nodes.json", node_items), ("namespaces.json", ns_items),
                                 ("workloads.json", wl_items), ("pods.json", pods)):
                (cdir / fname).write_text(json.dumps({"apiVersion": "v1", "kind": "List", "items": items}),
                                          encoding="utf-8")

    @staticmethod
    def _git(raw):
        repos = {
            "payment-api": ("group:default/payments", "payments", "tier-1", "@payments-team"),
            "billing-core": ("group:default/billing", "billing", "tier-1", "@billing-team"),
            "web-portal": ("group:default/web", "web-portal", "tier-2", "@web-team"),
            "notification-worker": ("group:default/web", "notifications", "tier-3", "@web-team"),
        }
        for repo, (owner, ns, crit, co) in repos.items():
            d = raw / "git" / repo
            d.mkdir(parents=True)
            doc = {"apiVersion": "backstage.io/v1alpha1", "kind": "Component",
                   "metadata": {"name": repo, "description": f"{repo} service",
                                "annotations": {"backstage.io/kubernetes-namespace": ns,
                                                "gitlab.com/project-slug": f"{owner.split('/')[-1]}/{repo}",
                                                "rsm/criticality": crit}},
                   "spec": {"type": "service", "lifecycle": "production", "owner": owner}}
            (d / "catalog-info.yaml").write_text(yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")
            (d / "CODEOWNERS").write_text(f"* {co}\n", encoding="utf-8")


# ---------------------------------------------------------------- оценка качества
def evaluate(snapshot: dict, truth_path: Path) -> dict:
    truth = json.loads(truth_path.read_text(encoding="utf-8"))
    by_host = {ci["hostname"]: ci for ci in snapshot["resources"]}
    stats, wrong = Counter(), []
    for host, t in truth.items():
        ci = by_host.get(host)
        if not ci:
            continue
        st, team = ci["owner_status"], ci.get("owner_team")
        if t["team"] is None:
            stats["нет владельца в «правде»: " + ("остался ничейным" if st == "unowned" else f"атрибутирован ({st})")] += 1
            continue
        if st in ("auto", "confirmed"):
            key = "верно (авто/подтверждено)" if team == t["team"] else "ОШИБКА (авто)"
        elif st in ("needs-confirmation", "conflict"):
            key = "на подтверждении, кандидат верный" if (team or ci.get("owner_suggestion")) == t["team"] \
                else "на подтверждении, кандидат неверный"
        else:
            key = "не определён"
        stats[key] += 1
        if key.startswith("ОШИБКА") or key.endswith("неверный"):
            wrong.append(f"{host}: правда={t['team']}, модель={team or ci.get('owner_suggestion')} ({st})")
    return {"stats": dict(stats), "wrong": wrong}


def prepare_dir(data_dir: Path) -> None:
    if data_dir.exists() and any(data_dir.iterdir()) and not (data_dir / MARKER).exists():
        raise RuntimeError(f"{data_dir} не пуст и не похож на демо-каталог — не трогаю. Укажите другой --data-dir.")
    if data_dir.exists():
        shutil.rmtree(data_dir)
    data_dir.mkdir(parents=True)
    (data_dir / MARKER).write_text("demo data, safe to delete\n", encoding="utf-8")

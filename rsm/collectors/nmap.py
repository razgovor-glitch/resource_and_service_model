"""nmap XML (-oX): живые хосты, rDNS, MAC (если сканер в том же L2), открытые порты, ОС."""
from __future__ import annotations

import xml.etree.ElementTree as ET

from ..util import iso, parse_time, short_hostname
from .base import observation


def collect(cfg) -> list[dict]:
    out = []
    for path in sorted(cfg.raw("nmap").glob("*.xml")):
        root = ET.parse(path).getroot()
        scanned_at = iso(parse_time(root.get("start")))
        for h in root.findall("host"):
            status = h.find("status")
            if status is not None and status.get("state") != "up":
                continue
            ips, macs, mac_vendor = [], [], None
            for a in h.findall("address"):
                if a.get("addrtype") in ("ipv4", "ipv6"):
                    ips.append(a.get("addr"))
                elif a.get("addrtype") == "mac":
                    macs.append(a.get("addr"))
                    mac_vendor = a.get("vendor")
            names = [n.get("name") for n in h.findall("hostnames/hostname") if n.get("name")]
            ports, services = [], []
            for p in h.findall("ports/port"):
                state = p.find("state")
                if state is None or state.get("state") != "open":
                    continue
                ports.append(int(p.get("portid")))
                svc = p.find("service")
                if svc is not None:
                    services.append(f"{p.get('portid')}/{svc.get('name')}"
                                    + (f" {svc.get('product')}" if svc.get("product") else ""))
            osmatch = h.find("os/osmatch")
            fqdn = names[0] if names else None
            out.append(observation(
                "nmap", "host",
                keys={"ip": ips, "mac": macs, "host": [short_hostname(n) for n in names]},
                attrs={"hostname": short_hostname(fqdn), "fqdn": fqdn, "ips": ips, "macs": macs,
                       "mac_vendor": mac_vendor, "open_ports": sorted(ports), "nmap_services": services,
                       "os": osmatch.get("name") if osmatch is not None else None,
                       "alive": True, "observed_at": scanned_at},
                ref=f"{path.name}:{ips[0] if ips else '?'}"))
    return out

"""Юнит-тесты ключевой логики. Запуск: python -m unittest discover -s tests -v"""
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from rsm import merge, pipeline, policy  # noqa: E402
from rsm.attribution import Engine  # noqa: E402
from rsm.collectors.base import observation  # noqa: E402
from rsm.config import Config  # noqa: E402
from rsm.util import parse_time, swap_uuid, uuid_key  # noqa: E402

NOW = parse_time("2026-10-22T06:00:00Z")


def cfg(data_dir=None):
    return Config(ROOT / "config", data_dir or tempfile.mkdtemp())


class IdentityTest(unittest.TestCase):
    def test_uuid_key_ignores_byte_order(self):
        u = "4216a1b2-c3d4-e5f6-0718-293a4b5c6d7e"
        swapped = swap_uuid(u.replace("-", ""))
        self.assertEqual(uuid_key(u), uuid_key(swapped.upper()))

    def test_merge_by_uuid_mac_and_ip_only(self):
        c = cfg()
        obs = [
            observation("vcenter", "host", {"uuid": ["4216a1b2-c3d4-e5f6-0718-293a4b5c6d7e"], "host": ["app-01"],
                                            "ip": ["10.1.1.5"]}, {"hostname": "app-01", "ips": ["10.1.1.5"]}, "vm-1"),
            observation("ansible", "host", {"uuid": [swap_uuid("4216a1b2c3d4e5f60718293a4b5c6d7e")],
                                            "host": ["localhost"], "mac": ["00:50:56:aa:bb:cc"]},
                        {"hostname": "localhost", "os": "Ubuntu 22.04"}, "app-01"),
            observation("nmap", "host", {"ip": ["10.1.1.5"]}, {"ips": ["10.1.1.5"], "open_ports": [22]}, "scan"),
            observation("nmap", "host", {"ip": ["10.1.1.99"]}, {"ips": ["10.1.1.99"]}, "scan"),
        ]
        cis, conflicts = merge.resolve(obs, c, NOW)
        self.assertEqual(len(cis), 2)
        app = next(ci for ci in cis if ci["hostname"] == "app-01")
        self.assertEqual(app["sources"], ["ansible", "nmap", "vcenter"])
        self.assertEqual(app["os"], "Ubuntu 22.04")
        self.assertEqual(app["open_ports"], [22])
        self.assertFalse(conflicts)

    def test_ip_conflict_detected(self):
        c = cfg()
        obs = [observation("dns", "host", {"host": ["a"], "ip": ["10.1.1.5"]}, {"hostname": "a", "ips": ["10.1.1.5"]}),
               observation("dns", "host", {"host": ["b"], "ip": ["10.1.1.5"]}, {"hostname": "b", "ips": ["10.1.1.5"]})]
        cis, _ = merge.resolve(obs, c, NOW)
        self.assertTrue(all(any(x["type"] == "ip-conflict" for x in ci["conflicts"]) for ci in cis))


class AttributionTest(unittest.TestCase):
    def setUp(self):
        self.engine = Engine(cfg())

    def test_alias_and_catalog_derivation(self):
        view = {"hostname": "paygw07", "ips": ["10.20.30.40"], "tags": {"vcenter:owner": "Платежи"},
                "sources": ["vcenter"], "groups": []}
        r = self.engine.evaluate(view)
        self.assertEqual(r["owner_team"]["value"], "payments")
        self.assertEqual(r["owner_team"]["status"], "auto")
        self.assertEqual(r["service"]["value"], "payment-gateway-legacy")
        self.assertEqual(r["support_model"]["value"], "24x7")

    def test_conflict_between_strong_signals(self):
        view = {"hostname": "x1", "tags": {"vcenter:owner": "crm", "zabbix:team": "billing",
                                           "ansible:owner_team": "billing"}, "sources": ["vcenter"]}
        r = self.engine.evaluate(view)
        self.assertEqual(r["owner_team"]["status"], "conflict")

    def test_person_annotation_needs_confirmation(self):
        view = {"hostname": "old-box", "annotation": "Ответственный: i.petrov", "sources": ["vcenter"]}
        r = self.engine.evaluate(view)
        self.assertEqual((r["owner_team"]["value"], r["owner_team"]["status"]), ("erp", "needs-confirmation"))

    def test_confirmed_wins(self):
        view = {"hostname": "prod-billing-app-01", "sources": ["vcenter"]}
        r = self.engine.evaluate(view, confirmed={"owner_team": {"value": "crm", "by": "x", "at": "y"}})
        self.assertEqual((r["owner_team"]["value"], r["owner_team"]["status"]), ("crm", "confirmed"))

    def test_dev_environment_lowers_criticality(self):
        view = {"hostname": "dev-billing-core-12", "tags": {"vcenter:owner": "billing"}, "sources": ["vcenter"]}
        r = self.engine.evaluate(view)
        self.assertEqual(r["environment"]["value"], "development")
        self.assertEqual(r["criticality"]["value"], "tier-4")


class CollectorTest(unittest.TestCase):
    def test_ansible_playbook_format_without_prefix(self):
        """deploy/ansible/collect_facts.yml пишет ansible_facts без префикса ansible_."""
        import json
        from rsm.collectors import ansible
        tmp = Path(tempfile.mkdtemp())
        try:
            c = cfg(tmp)
            d = c.raw("ansible", "facts")
            d.mkdir(parents=True)
            (d / "app-01").write_text(json.dumps({"ansible_facts": {
                "hostname": "app-01", "fqdn": "app-01.corp", "default_ipv4": {"address": "10.1.1.5",
                                                                               "macaddress": "00:50:56:01:02:03"},
                "all_ipv4_addresses": ["10.1.1.5", "172.17.0.1"], "product_uuid": "4216A1B2-C3D4-E5F6-0718-293A4B5C6D7E",
                "distribution": "Ubuntu", "distribution_version": "22.04", "virtualization_role": "guest",
                "local": {"rsm": {"team": "billing"}},
                "services": {"postgresql.service": {"state": "running"}, "cron.service": {"state": "stopped"}}}}))
            (o,) = ansible.collect(c)
            self.assertEqual(o["attrs"]["ips"], ["10.1.1.5"])          # docker bridge отфильтрован
            self.assertEqual(o["attrs"]["tags"], {"fact_team": "billing"})
            self.assertEqual(o["attrs"]["services_running"], ["postgresql"])
            self.assertTrue(o["attrs"]["virtual"])
        finally:
            shutil.rmtree(tmp)


class NetBoxDiffTest(unittest.TestCase):
    def test_diff_tolerates_netbox_formats(self):
        from rsm.netbox import _diff
        obj = {"name": "a", "status": {"value": "active"}, "tenant": {"id": 3}, "vcpus": 4.0,
               "tags": [{"slug": "rsm-managed"}],
               "custom_fields": {"rsm_last_seen": "2026-10-22T06:00:00Z", "rsm_owner_confidence": 1.0}}
        payload = {"name": "a", "status": "active", "tenant": 3, "vcpus": 4, "tags": [{"slug": "rsm-managed"}],
                   "custom_fields": {"rsm_last_seen": "2026-10-22T06:00:00+00:00", "rsm_owner_confidence": 1}}
        self.assertEqual(_diff(obj, payload), {})
        payload["custom_fields"]["rsm_last_seen"] = "2026-10-23T06:00:00+00:00"
        self.assertEqual(list(_diff(obj, payload)), ["custom_fields"])


class PolicyTest(unittest.TestCase):
    def test_examples_have_violations(self):
        v = policy.check_paths(cfg(), [str(ROOT / "examples" / "policy")])
        text = "\n".join(v)
        self.assertIn("Deployment/payment-api", text)
        self.assertIn("ml-team", text)
        self.assertIn("tmp_test", text)
        self.assertNotIn("billing_app", text)
        self.assertNotIn("Namespace/payments", text)


class DemoPipelineTest(unittest.TestCase):
    def test_demo_day1_quality(self):
        from rsm import demo
        tmp = Path(tempfile.mkdtemp())
        try:
            c = cfg(tmp)
            fleet = demo.Fleet(seed=1, dev_vms=20)
            fleet.write_raw(c.raw(), 1)
            pipeline.collect(c)
            snap = pipeline.build(c, parse_time(demo.DAYS[1]))
            pipeline.reconcile(c, snap, parse_time(demo.DAYS[1]))
            ev = demo.evaluate(snap, c.raw("_ground_truth.json"))["stats"]
            self.assertEqual(ev.get("ОШИБКА (авто)", 0), 0)
            self.assertGreater(ev.get("верно (авто/подтверждено)", 0), 100)
            hosts = [ci["hostname"] for ci in snap["resources"]]
            self.assertEqual(len(hosts), len(set(hosts)), "дубли CI после склейки")
        finally:
            shutil.rmtree(tmp)


if __name__ == "__main__":
    unittest.main()

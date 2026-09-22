import argparse
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile

spec = importlib.util.spec_from_file_location("collector", Path(__file__).with_name("update-configs.py"))
c = importlib.util.module_from_spec(spec)
spec.loader.exec_module(c)


def site(name="example.org", group="tools"):
    return c.validate_site({"domains": [name], "ip4": ["1.1.1.1"], "ip6": [], "cidr4": ["1.1.1.0/24"], "cidr6": []}, name, group)


class CollectionTests(unittest.TestCase):
    def test_missing_json_site_does_not_clear_previous(self):
        old = site()
        previous = {"sites": {old["name"]: old}, "last_success_at": "2026-09-20T00:00:00Z"}
        with patch.object(c, "discover", return_value={old["name"]: "tools"}), patch.object(c, "fetch_json", return_value={}), patch.object(c, "fetch", return_value=b"<html>bad gateway</html>"):
            result = c.collect_public("beta", previous)
        self.assertEqual(result["sites"], previous["sites"])
        self.assertEqual(result["last_success_at"], previous["last_success_at"])
        self.assertTrue(result["warnings"])

    def test_empty_small_field_and_wrong_family_are_rejected(self):
        old = site()
        with self.assertRaises(ValueError):
            c.check_drop(old, {**old, "ip4": []})
        for field, value in (("ip4", ["::1"]), ("domains", ["<html>"]), ("ip4", [1]), ("ip6", None)):
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                c.normalize(field, value)

    def test_recovered_fields_do_not_mark_old_metadata_fresh(self):
        old = site()
        previous = {"sites": {old["name"]: old}, "last_success_at": "2026-09-20T00:00:00Z"}
        incomplete = {k: v for k, v in old.items() if k != "external"}
        with patch.object(c, "discover", return_value={old["name"]: "tools"}), patch.object(c, "fetch_json", return_value={old["name"]: incomplete}), patch.object(c, "fetch_field", side_effect=lambda base, name, field: old[field]):
            result = c.collect_public("beta", previous)
        self.assertEqual(result["sites"], previous["sites"])
        self.assertEqual(result["last_success_at"], previous["last_success_at"])
        self.assertIn("previous metadata retained", result["warnings"][0])

    def test_catalog_exception_uses_fallback(self):
        with patch.object(c, "fetch_json", side_effect=[RuntimeError("503"), {"example.org": ["example.org"]}]) as fetch:
            self.assertEqual(c.discover("https://example.org"), {"example.org": None})
            self.assertEqual(fetch.call_count, 2)

    def test_missing_site_is_retained_and_group_move_keeps_identity(self):
        one, two = site(), site("second.org")
        previous = {"sites": {one["name"]: one, two["name"]: two}, "last_success_at": c.now()}
        with patch.object(c, "discover", return_value={one["name"]: "new-group"}), patch.object(c, "fetch_json", return_value={one["name"]: one}):
            result = c.collect_public("beta", previous)
        self.assertEqual(result["sites"][one["name"]]["group"], "new-group")
        self.assertEqual(result["sites"][two["name"]], two)
        self.assertTrue(result["warnings"])

    def test_master_empty_archive_rejected(self):
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w") as z:
            z.writestr("iplist-master/config/", "")
        with patch.object(c, "fetch", return_value=stream.getvalue()), self.assertRaises(ValueError):
            c.collect_master({})

    def test_text_error_is_not_an_empty_result(self):
        with patch.object(c, "fetch", return_value=b"# Error: unavailable"), self.assertRaises(ValueError):
            c.text_values("https://example.org", "ip4")

    def test_dns_priority_preserved(self):
        value = {**site(), "dns": ["127.0.0.11:53", "1.1.1.1:53"]}
        self.assertEqual(c.validate_site(value, value["name"], value["group"])["dns"], value["dns"])

    def test_external_failure_preserves_resource(self):
        value = site()
        url = "https://example.org/list"
        value["external"]["ip4"] = [url]
        cache = {"ip4:" + url: {"values": ["8.8.8.8"], "last_success_at": c.EPOCH}}
        warnings = []
        with patch.object(c, "fetch", return_value=b"<html>error</html>"):
            enriched = c.enrich(value, cache, warnings)
        self.assertIn("8.8.8.8", enriched["ip4"])
        self.assertTrue(warnings)
        self.assertEqual(cache["ip4:" + url]["last_success_at"], c.EPOCH)

    def test_legitimate_empty_asn_and_unexpected_loss(self):
        value = site()
        value["as"] = ["AS32163"]
        response = {"status": "ok", "data": {"resource": "32163", "prefixes": []}}
        with patch.object(c, "fetch_json", return_value=response):
            warnings = []
            self.assertEqual(c.enrich(value, {}, warnings)["cidr4"], value["cidr4"])
            self.assertEqual(warnings, [])
            cache = {"asn:AS32163": {"values": ["8.8.8.0/24"], "last_success_at": c.EPOCH}}
            result = c.enrich(value, cache, warnings)
            self.assertIn("8.8.8.0/24", result["cidr4"])
            self.assertTrue(warnings)

    def test_invalid_domains_are_quarantined_without_accepting_html(self):
        value = site()
        value["domains"] = [f"host{i}.example.org" for i in range(20)] + ["user@example.org"]
        result = c.validate_site(value, value["name"], value["group"])
        self.assertEqual(result["rejected_domains"], ["user@example.org"])
        self.assertEqual(len(result["domains"]), 20)
        with self.assertRaises(ValueError):
            c.validate_site({**value, "domains": ["<html>error</html>"]}, value["name"], value["group"])

    def test_objects_are_deterministic_and_checksums_verified(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            value = {"sites": [site()]}
            one = c.write_object(root, value)
            self.assertEqual(one, c.write_object(root, value))
            body = (root / one["path"]).read_bytes()
            with patch.object(c, "fetch", return_value=body):
                self.assertEqual(c.read_object(c.DEFAULT_URL, one), value)
            with patch.object(c, "fetch", return_value=body + b"bad"), self.assertRaises(ValueError):
                c.read_object(c.DEFAULT_URL, one)

    def test_independent_sources_and_manifest_freshness(self):
        old = {"sites": {"example.org": site()}, "last_success_at": c.EPOCH, "warnings": []}
        state = {"schema_version": 1, "sources": {k: old for k in ("master", "beta", "russia")}, "resources": {}}
        with tempfile.TemporaryDirectory() as tmp:
            args = argparse.Namespace(previous_url=c.DEFAULT_URL, seed_dir="unused", custom_dir=tmp, output=tmp, allow_removals=False, workers=2)
            with patch.object(c, "fetch_json", side_effect=RuntimeError("missing")), patch.object(c, "seed", return_value=state), patch.object(c, "collect_master", return_value={**old, "last_success_at": c.now()}), patch.object(c, "collect_public", side_effect=[RuntimeError("beta unavailable"), {**old, "last_success_at": c.now()}]):
                manifest = c.build(args)
            self.assertEqual(manifest["sets"]["beta"]["status"], "degraded")
            self.assertEqual(manifest["sets"]["beta"]["last_success_at"], c.EPOCH)
            self.assertEqual(manifest["sets"]["main"]["status"], "ok")
            self.assertEqual(manifest["sets"]["russia"]["status"], "ok")


if __name__ == "__main__":
    unittest.main()

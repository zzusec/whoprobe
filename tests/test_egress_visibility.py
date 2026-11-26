import concurrent.futures
import json
import unittest
import urllib.error
import urllib.parse
from datetime import datetime, timezone
from unittest.mock import patch

import egress_intel as intel


VISITOR = "9.9.9.42"  # Only used with the offline fixtures below.
PREFIX = "9.9.9.0/24"


class OfflineTests(unittest.TestCase):
    def mock(self, obj, name, **kwargs):
        p = patch.object(obj, name, **kwargs)
        mocked = p.start()
        self.addCleanup(p.stop)
        return mocked

    def setUp(self):
        for obj, name in ((intel.urllib.request, "urlopen"), (intel.socket, "create_connection"), (intel.socket, "socket")):
            forbidden = self.mock(obj, name, side_effect=AssertionError("Unexpected network call"))
            self.addCleanup(forbidden.assert_not_called)


class _ImmediateExecutor:
    def submit(self, fn, *args):
        result = concurrent.futures.Future()
        try:
            result.set_result(fn(*args))
        except Exception as err:
            result.set_exception(err)
        return result


class PurityTests(OfflineTests):
    def setUp(self):
        super().setUp()
        self.mock(intel, "_INTEL_POOL", new=_ImmediateExecutor())
        self.mock(intel, "INTEL_CACHE", new=intel.SimpleTTLCache())
        self.mock(intel, "fetch_route_history", side_effect=AssertionError("History must be queried separately"))
        self.addCleanup(intel.fetch_route_history.assert_not_called)
        self.flags = {
            "ipapiis": ("vpn", "proxy", "tor", "hosting", "abuser"),
            "ipquery": ("vpn", "proxy", "tor", "hosting"),
            "iplocate": ("vpn", "proxy", "tor", "hosting", "abuser"),
            "blackbox": ("vpn", "proxy", "tor", "hosting"),
            "ipapi": ("proxy", "hosting"),
            "ipinfo": (), "ipleak": (), "freeipapi": ("proxy",),
        }
        self.sources = {key: self.mock(intel, f"_src_{key}", return_value=None) for key in self.flags}
        self.rdap = self.mock(intel, "_fetch_rdap_ip", return_value=None)
        self.shodan = self.mock(intel, "_fetch_shodan", return_value=None)
        self.sfs = self.mock(intel, "_fetch_sfs", return_value=None)
        self.otx = self.mock(intel, "_fetch_otx", return_value=None)
        self.tor = self.mock(intel, "_fetch_onionoo", return_value=None)
        self.dnsbl = self.mock(intel, "_check_single_dnsbl", side_effect=TimeoutError)
        self.cidr = self.mock(intel, "load_cidr_list", return_value=None)
        self.asn = self.mock(intel, "fetch_asn_profile", return_value={})

    def inspect(self, ip=VISITOR):
        result = intel.inspect_ip_intelligence(ip, enable_active_443=False, enable_port_scan=False)
        purity = result["purity"]
        return result, purity, {e["id"]: e for e in purity["evidence"]}

    def test_all_missing_keeps_legacy_base_but_is_not_clean(self):
        result, purity, evidence = self.inspect()
        self.assertEqual((purity["base"], purity["score"], purity["grade"]), (92, 92, "A"))
        self.assertEqual(purity["bonuses"], [])
        self.assertTrue(purity["uncertain"])
        self.assertIsNone(result["consensus"]["riskScore"])
        self.assertEqual(result["votes"]["proxy"]["of"], 0)
        self.assertEqual(purity["coverage"]["known"], 0)
        self.assertEqual(purity["coverage"]["ratio"], 0)
        self.assertEqual(purity["coverage"]["applicable"], purity["coverage"]["unknown"])
        self.assertEqual(evidence["neighbours"]["status"], "unknown")
        self.assertEqual(evidence["ports"]["status"], "not_applicable")
        self.assertEqual(evidence["tls443"]["status"], "not_applicable")

    def test_mixed_sources_keep_explicit_denials_hits_and_unknown_separate(self):
        self.sources["ipapiis"].return_value = {"id": "ipapiis", "name": "Mock API", "flags": {"proxy": False, "vpn": True}}
        self.shodan.return_value = {"unseen": True, "ports": [], "vulns": [], "tags": []}
        self.sfs.return_value = {"appears": 0}
        self.dnsbl.side_effect = lambda entry, *_: {
            **entry,
            "status": "ok" if entry["id"] in {"spamcop", "dronebl"} else "error",
            "listed": entry["id"] == "dronebl",
        }
        self.cidr.side_effect = lambda entry, *_: intel._parse_cidr_ranges("203.0.113.9") if entry["id"] == "firehol1" else None
        result, purity, evidence = self.inspect()
        self.assertEqual(evidence["ipapiis"]["checks"]["proxy"], "clear")
        self.assertEqual(evidence["ipapiis"]["checks"]["vpn"], "hit")
        self.assertEqual(evidence["ipapiis"]["checks"]["tor"], "unknown")
        self.assertEqual(evidence["shodan"]["status"], "unknown")
        self.assertEqual(evidence["sfs"]["status"], "clear")
        self.assertEqual(evidence["cidr:firehol1"]["status"], "clear")
        self.assertEqual(evidence["dnsbl:spamcop"]["status"], "clear")
        self.assertEqual(evidence["dnsbl:dronebl"]["status"], "hit")
        self.assertEqual(evidence["dnsbl:psbl"]["status"], "unknown")
        self.assertEqual(result["dnsbl"]["total"], 2)
        self.assertTrue(purity["uncertain"])
        self.assertLess(purity["score"], 92)
        self.assertEqual(purity["bonuses"], [])
        coverage = purity["coverage"]
        self.assertEqual(coverage["known"] + coverage["unknown"], coverage["applicable"])
        self.assertEqual(coverage["applicable"] + coverage["notApplicable"], len(evidence))

    def test_ipv6_only_excludes_inapplicable_checks_from_denominator(self):
        result, purity, evidence = self.inspect("2620:fe::42")
        for entry in evidence.values():
            if entry["group"] in {"dnsbl", "cidr"} or entry["id"] in {"neighbours", "asn-density"}:
                self.assertEqual(entry["status"], "not_applicable")
        self.assertEqual(purity["coverage"]["notApplicable"], len(intel.DNSBLS) + len(intel.CIDR_LISTS) + 4)
        self.assertEqual(result["dnsbl"]["total"], 0)
        self.assertEqual(purity["bonuses"], [])
        self.cidr.assert_not_called()

    def test_full_coverage_and_only_evidence_backed_bonuses(self):
        for key, flags in self.flags.items():
            self.sources[key].return_value = {"id": key, "name": key, "country": "US", "asn": 7922, "flags": dict.fromkeys(flags, False)}
        self.sources["ipapiis"].return_value["risk"] = 0
        self.sources["ipquery"].return_value["risk"] = 0
        self.rdap.return_value = {"regCountry": "US", "cidr": PREFIX}
        self.asn.return_value = {"rpki": "valid", "v4Ips": 8192, "_mergedRoutes": intel._merge_route_cidrs(["9.9.0.0/19"])[0]}
        self.shodan.return_value = {"unseen": False, "ports": [80], "tags": [], "vulns": []}
        self.sfs.return_value = {"appears": 0}
        self.otx.return_value = {"pulses": 0}
        self.tor.return_value = {"torExit": False, "neighbourRelays": 0}
        self.dnsbl.side_effect = lambda entry, *_: {**entry, "status": "ok", "listed": False}
        ranges = intel._parse_cidr_ranges("203.0.113.9")
        self.cidr.return_value = ranges
        _, purity, evidence = self.inspect()
        self.assertFalse(purity["uncertain"])
        self.assertEqual(purity["coverage"]["ratio"], 1)
        self.assertGreater(purity["bonusTotal"], 0)
        self.assertEqual(evidence["neighbours"]["status"], "clear")
        self.assertEqual(evidence["asn-density"]["status"], "observed")

        self.sources["ipquery"].return_value.pop("risk")
        self.dnsbl.side_effect = lambda entry, *_: {**entry, "status": "error" if entry["id"] == "psbl" else "ok", "listed": False}
        self.cidr.side_effect = lambda entry, *_: None if entry["id"] == "greensnow" else ranges
        with patch.object(intel, "INTEL_CACHE", intel.SimpleTTLCache()):
            _, partial, evidence = self.inspect()
        self.assertTrue(partial["uncertain"])
        self.assertEqual(evidence["risk"]["status"], "unknown")
        self.assertEqual(evidence["neighbours"]["status"], "unknown")
        self.assertEqual(evidence["asn-density"]["status"], "unknown")
        # Only separate affirmative evidence (matching geolocation and a valid ROA) remains.
        self.assertEqual([b["pts"] for b in partial["bonuses"]], [0.5, 0.5])

    def test_sparse_coverage_bypasses_intel_cache_while_usable_coverage_caches(self):
        first_sparse, _, _ = self.inspect()
        second_sparse, _, _ = self.inspect()
        self.assertFalse(first_sparse["cacheHit"])
        self.assertFalse(second_sparse["cacheHit"])

        for key, flags in self.flags.items():
            self.sources[key].return_value = {"id": key, "name": key, "country": "US", "asn": 7922, "flags": dict.fromkeys(flags, False)}
        self.dnsbl.side_effect = lambda entry, *_: {**entry, "status": "ok", "listed": False}
        self.cidr.return_value = intel._parse_cidr_ranges("203.0.113.9")
        first_ok, _, _ = self.inspect()
        second_ok, _, _ = self.inspect()
        self.assertFalse(first_ok["cacheHit"])
        self.assertTrue(second_ok["cacheHit"])


class SourceSchemaTests(OfflineTests):
    def test_missing_threat_fields_and_empty_cidr_body_are_not_denials(self):
        get = self.mock(intel, "_http_json", return_value={})
        self.assertIsNone(intel._fetch_sfs(VISITOR))
        self.assertIsNone(intel._fetch_otx(VISITOR, 4))
        self.assertIsNone(intel._fetch_onionoo(VISITOR, 4))
        entry = intel.CIDR_LISTS[0]
        self.mock(intel, "CIDR_CACHE", new=intel.SimpleTTLCache())
        self.mock(intel, "_http_text", return_value="<html>maintenance</html>")
        self.assertIsNone(intel.load_cidr_list(entry))
        get.return_value = {"success": 1, "ip": {"appears": 0}}
        self.assertEqual(intel._fetch_sfs(VISITOR)["appears"], 0)
        get.return_value = {"pulse_info": {"count": 0, "pulses": []}}
        self.assertEqual(intel._fetch_otx(VISITOR, 4)["pulses"], 0)
        get.return_value = {"relays": []}
        self.assertIs(intel._fetch_onionoo(VISITOR, 4)["torExit"], False)

    def test_dnsbl_negative_vs_service_error(self):
        get = self.mock(intel, "_http_json", return_value={"Status": 0, "Answer": [{"type": 1, "data": "127.255.255.254"}]})
        dnsbl = intel.DNSBLS[0]
        self.assertEqual(intel._check_single_dnsbl(dnsbl, VISITOR, 4)["status"], "error")
        get.return_value = {"Status": 0, "Answer": {"invalid": "shape"}}
        self.assertEqual(intel._check_single_dnsbl(dnsbl, VISITOR, 4)["status"], "error")
        get.return_value = {"Status": 3}
        check = intel._check_single_dnsbl(dnsbl, VISITOR, 4)
        self.assertEqual(check["status"], "ok")
        self.assertIs(check["listed"], False)


class _FixedDateTime(datetime):
    @classmethod
    def now(cls, tz=None):
        fixed = datetime(2026, 3, 31, 12, tzinfo=timezone.utc)
        return fixed.astimezone(tz) if tz else fixed.replace(tzinfo=None)


def _origin(asn, *intervals, prefix=PREFIX):
    return {"origin": str(asn), "prefixes": [{"prefix": prefix, "timelines": [
        {"starttime": start, "endtime": end, "full_peers_seeing": 5} for start, end in intervals
    ]}]}


T0 = "2026-03-01T08:00:00"
T1 = "2026-03-10T00:00:00"
T2 = "2026-03-20T00:00:00"
T3 = "2026-03-31T08:00:00"


class RouteHistoryTests(OfflineTests):
    def setUp(self):
        super().setUp()
        self.mock(intel, "datetime", new=_FixedDateTime)
        self.mock(intel, "ROUTE_HISTORY_CACHE", new=intel.SimpleTTLCache(maxsize=2, ttl_sec=900))
        self.opener = self.mock(intel.urllib.request, "build_opener")
        self.open = self.opener.return_value.open
        self.read = self.open.return_value.__enter__.return_value.read

    def reply(self, *groups):
        self.read.return_value = json.dumps({"status": "ok", "status_code": 200, "data": {
            "by_origin": groups, "query_starttime": T0, "query_endtime": T3, "latest_max_ff_peers": 300,
        }}).encode()

    def test_rejects_unsafe_or_single_address_inputs_without_request(self):
        invalid = (
            None, "", VISITOR, "2620:fe::42", "9.9.9.42/32", "2620:fe::42/128", "9.9.9.42/24",
            "9.9.9.0/255.255.255.0", "0.0.0.0/0", "::/0", "10.0.0.0/24", "127.0.0.0/8", "100.64.0.0/10",
            "203.0.113.0/24", "224.0.0.0/4", "128.0.0.0/2", "fc00::/7", "2606:4700::%x/32", "3fff::/20",
            "::ffff:9.9.9.0/120", "9.9.9.0/24&resource=AS1", " 9.9.9.0/24", "9.9.9.0/24\n",
        )
        for prefix in invalid:
            with self.subTest(prefix=prefix):
                result = intel.fetch_route_history(prefix)
                self.assertFalse(result["ok"])
                self.assertEqual(result["status"], "invalid")
                self.assertIsNone(result["prefix"])
        self.opener.assert_not_called()

    def test_adjacent_changes_are_not_simultaneous_and_only_prefix_is_sent(self):
        self.reply(_origin(101, (T0, T1)), _origin(102, (T1, T3)), _origin(999, (T0, T3), prefix="9.9.8.0/23"))
        result = intel.fetch_route_history(PREFIX)
        self.assertTrue(result["ok"])
        self.assertEqual(result["status"], "observed")
        self.assertEqual(result["origins"], [101, 102])
        self.assertIs(result["multiOrigin"], False)
        self.assertIs(result["originChanged"], True)
        self.assertEqual(result["source"], "RIPEstat (RIS)")
        self.assertEqual(result["window"], {"start": "2026-03-01T12:00:00Z", "end": T3 + "Z"})
        self.assertEqual([r["origins"] for r in result["timeline"]], [[101], [102]])
        self.assertEqual(result["timeline"][0]["end"], result["timeline"][1]["start"])
        request = self.open.call_args.args[0]
        url = urllib.parse.urlparse(request.full_url)
        self.assertEqual((url.scheme, url.netloc, url.path), ("https", "stat.ripe.net", "/data/routing-history/data.json"))
        self.assertEqual(urllib.parse.parse_qs(url.query), {
            "resource": [PREFIX], "starttime": ["2026-03-01T12:00:00Z"], "min_peers": ["1"],
            "include_first_hop": ["false"], "max_rows": ["1000"],
        })
        self.assertGreater(self.open.call_args.kwargs["timeout"], 0)
        self.assertIsNone(self.opener.call_args.args[0].redirect_request(None, None, 302, "", {}, "https://9.9.9.42/"))

    def test_simultaneous_origin_that_does_not_replace_another(self):
        self.reply(_origin("AS101", (T0, T3), (T1, T2)), _origin(102, (T1, T2)))
        result = intel.fetch_route_history(PREFIX)
        self.assertIs(result["multiOrigin"], True)
        self.assertIs(result["originChanged"], False)
        self.assertEqual([r["origins"] for r in result["timeline"]], [[101], [101, 102], [101]])

    def test_handoff_with_overlap_can_be_both(self):
        self.reply(_origin(101, (T0, T2)), _origin(102, (T1, T3)))
        result = intel.fetch_route_history(PREFIX)
        self.assertIs(result["multiOrigin"], True)
        self.assertIs(result["originChanged"], True)
        self.assertEqual([r["origins"] for r in result["timeline"]], [[101], [101, 102], [102]])

    def test_two_point_observations_at_the_same_time_are_simultaneous(self):
        self.reply(_origin(101, (T1, T1)), _origin(102, (T1 + "+00:00", T1 + "+00:00")))
        result = intel.fetch_route_history(PREFIX)
        self.assertIs(result["multiOrigin"], True)
        self.assertIs(result["originChanged"], False)
        self.assertEqual(result["timeline"], [{"start": T1 + "Z", "end": T1 + "Z", "origins": [101, 102]}])

    def test_another_prefix_or_no_rows_is_not_observed_not_stable(self):
        self.reply(_origin(101, (T0, T3), prefix="9.9.9.0/25"))
        result = intel.fetch_route_history(PREFIX)
        self.assertTrue(result["ok"])
        self.assertEqual(result["status"], "not_observed")
        self.assertEqual(result["origins"], [])
        self.assertIsNone(result["multiOrigin"])
        self.assertIsNone(result["originChanged"])
        self.reply()
        self.assertEqual(intel.fetch_route_history("2620:fe::/48")["status"], "not_observed")

    def test_failed_or_invalid_results_are_unknown(self):
        self.open.side_effect = urllib.error.URLError(TimeoutError())
        timed_out = intel.fetch_route_history(PREFIX)
        self.assertEqual((timed_out["status"], timed_out["error"]), ("unknown", "timeout"))
        self.assertIsNone(timed_out["multiOrigin"])
        self.assertFalse(timed_out["ok"])
        self.open.side_effect = ConnectionResetError()
        failed = intel.fetch_route_history("9.9.8.0/24")
        self.assertEqual((failed["status"], failed["error"]), ("unknown", "upstream-error"))
        self.open.side_effect = None
        for bad in (b"{", b'{"status":"maintenance","data":{}}', b'{"status":"ok","data":{"by_origin":[]}}'):
            with self.subTest(bad=bad), patch.object(intel, "ROUTE_HISTORY_CACHE", intel.SimpleTTLCache()):
                self.read.return_value = bad
                result = intel.fetch_route_history(PREFIX)
                self.assertEqual((result["status"], result["error"]), ("unknown", "invalid-upstream-response"))

    def test_canonical_cache_is_bounded_and_expired(self):
        self.reply()
        clock = self.mock(intel.time, "monotonic", return_value=100)
        first = intel.fetch_route_history("2620:FE:0:0:0:0:0:0/48")
        first["window"]["end"] = "caller mutation"
        cached = intel.fetch_route_history("2620:fe::/48")
        self.assertTrue(cached["cacheHit"])
        self.assertEqual(cached["prefix"], "2620:fe::/48")
        self.assertEqual(cached["window"]["end"], T3 + "Z")
        self.open.assert_called_once()
        intel.fetch_route_history(PREFIX)
        intel.fetch_route_history("9.9.8.0/24")
        self.assertFalse(intel.fetch_route_history("2620:fe::/48")["cacheHit"])
        clock.return_value += 901
        self.assertFalse(intel.fetch_route_history("2620:fe::/48")["cacheHit"])


if __name__ == "__main__":
    unittest.main()

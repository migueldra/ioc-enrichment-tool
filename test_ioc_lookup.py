"""Tests sin red: detección de tipo, refang, veredicto y flujo con APIs simuladas."""

import unittest
from unittest import mock

import ioc_lookup as m


class TestDetection(unittest.TestCase):
    def test_types(self):
        cases = {
            "8.8.8.8": "ip",
            "2001:4860:4860::8888": "ip",
            "44d88612fea8a8f36de82e1278abb02f": "hash",
            "3395856ce81f2b7382dee72602f798b642f14140": "hash",
            "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f": "hash",
            "https://example.com/login": "url",
            "example.com": "url",
        }
        for ioc, expected in cases.items():
            self.assertEqual(m.detect_type(ioc), expected, ioc)

    def test_invalid(self):
        with self.assertRaises(ValueError):
            m.detect_type("no-es-un-ioc")

    def test_refang(self):
        self.assertEqual(m.refang("hxxps://evil[.]com/x"), "https://evil.com/x")
        self.assertEqual(m.refang(" 1.2.3[.]4 "), "1.2.3.4")


class TestVerdict(unittest.TestCase):
    def report(self, mal=None, susp=0, abuse=None):
        r = m.Report(ioc="x", type="ip")
        if mal is not None:
            r.detections = {"malicious": mal, "suspicious": susp}
        if abuse is not None:
            r.reputation["abuseipdb_score"] = abuse
        return r

    def test_verdicts(self):
        self.assertEqual(m.compute_verdict(self.report()), "unknown")
        self.assertEqual(m.compute_verdict(self.report(mal=0, abuse=0)), "clean")
        self.assertEqual(m.compute_verdict(self.report(mal=1)), "suspicious")
        self.assertEqual(m.compute_verdict(self.report(mal=0, abuse=40)), "suspicious")
        self.assertEqual(m.compute_verdict(self.report(mal=10)), "malicious")
        self.assertEqual(m.compute_verdict(self.report(mal=0, abuse=100)), "malicious")


class TestAnalyzeMocked(unittest.TestCase):
    VT_IP = {"data": {"attributes": {
        "last_analysis_stats": {"malicious": 12, "suspicious": 1, "harmless": 50, "undetected": 20},
        "reputation": -45, "country": "RU", "as_owner": "Evil Hosting",
    }}}
    ABUSE = {"data": {
        "abuseConfidenceScore": 100, "countryCode": "RU", "isp": "Evil Hosting",
        "usageType": "Data Center/Web Hosting/Transit", "totalReports": 321,
        "reports": [{"categories": [18, 22]}, {"categories": [14]}],
    }}

    def fake_get(self, url, headers, params=None):
        return self.ABUSE if "abuseipdb" in url else self.VT_IP

    def test_ip_full(self):
        with mock.patch.object(m, "http_get", side_effect=self.fake_get):
            r = m.analyze("185.220.101.1", "vt", "abuse")
        self.assertEqual(r.verdict, "malicious")
        self.assertEqual(r.country, "RU")
        self.assertEqual(r.detections["ratio"], "12/83")
        self.assertEqual(r.reputation, {"virustotal": -45, "abuseipdb_score": 100})
        self.assertEqual(r.categories, ["Port Scan", "Brute-Force", "SSH"])
        self.assertFalse(r.errors)

    def test_vt_url_id_is_unpadded_base64(self):
        self.assertTrue(m.vt_endpoint("http://a.com", "url").endswith("aHR0cDovL2EuY29t"))


if __name__ == "__main__":
    unittest.main()

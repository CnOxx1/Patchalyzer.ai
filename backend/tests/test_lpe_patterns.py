from collections import Counter
import unittest

from backend.services.lpe_patterns import (
    classify_audit,
    findings_from_disasm,
    findings_from_score,
    observations_from_audit,
    verdict_of,
)
from backend.services.surface import score_handler


class ScoreHandlerTests(unittest.TestCase):
    def test_copy_without_probe_is_high(self):
        ev = Counter({"memcpy": 1, "ExAllocatePool": 1})
        row = score_handler("AfdBind", 400, ev, "neither")
        self.assertEqual(row["risk"], "high")
        self.assertTrue(any("copy without probe" in w for w in row["why"]))

    def test_neither_without_probe_is_high(self):
        ev = Counter({"ExAllocatePool": 1})
        row = score_handler("AfdSetInfo", 200, ev, "neither")
        self.assertEqual(row["risk"], "high")
        self.assertTrue(any("METHOD_NEITHER" in w for w in row["why"]))

    def test_buffered_stays_buffered(self):
        ev = Counter({"memcpy": 1})
        row = score_handler("AfdGetInfo", 300, ev, "buffered")
        self.assertEqual(row["risk"], "buffered")

    def test_free_without_lock_promotes_medium(self):
        ev = Counter({"ExFreePoolWithTag": 1, "ProbeForRead": 1})
        row = score_handler("AfdClose", 400, ev, None)
        self.assertEqual(row["risk"], "medium")
        self.assertTrue(any("free/deref without lock" in w for w in row["why"]))

    def test_tiny_stub_is_wrapper(self):
        row = score_handler("AfdStub", 40, Counter(), None)
        self.assertEqual(row["risk"], "wrapper")


class PatternTests(unittest.TestCase):
    def test_score_maps_to_missing_probe(self):
        hits = findings_from_score(
            {
                "name": "AfdBind",
                "risk": "high",
                "method": "neither",
                "why": ["copy without probe/MDL"],
                "rva": "0x1000",
            }
        )
        self.assertTrue(hits)
        self.assertEqual(hits[0]["pattern"], "missing_probe")
        self.assertEqual(hits[0]["status"], "suspect")

    def test_disasm_lifetime_uaf(self):
        lines = [
            "0001  call ExFreePoolWithTag",
            "0002  nop",
            "0003  call memcpy",
        ]
        hits = findings_from_disasm("AfdRestart", lines)
        classes = {h["pattern"] for h in hits}
        self.assertIn("lifetime_uaf", classes)

    def test_disasm_copy_without_probe(self):
        lines = ["0001  call memcpy", "0002  ret"]
        hits = findings_from_disasm("AfdCopy", lines)
        self.assertTrue(any(h["pattern"] == "missing_probe" and h["status"] == "suspect" for h in hits))

    def test_verdict_likely_from_high_suspect(self):
        findings = [
            {"function": "A", "pattern": "missing_probe", "severity": "high", "status": "suspect"},
        ]
        self.assertEqual(verdict_of(findings), "likely")

    def test_classify_and_observations(self):
        scores = [
            {
                "name": "AfdBind",
                "risk": "high",
                "method": "neither",
                "why": ["METHOD_NEITHER without probe/MDL"],
                "rva": "0x10",
            }
        ]
        pack = classify_audit(scores, [])
        self.assertEqual(pack["verdict"], "likely")
        obs = observations_from_audit(pack["findings"], scores)
        self.assertTrue(obs)
        self.assertEqual(obs[0]["function"], "AfdBind")
        self.assertTrue(str(obs[0]["bp"]).startswith("bp "))


if __name__ == "__main__":
    unittest.main()

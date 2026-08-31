import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from backend.database import KIND_AUDIT, normalize_kind
from backend.services.agent_tools import PATH_HARDENED_BUDGET, PATH_BUDGET, LoopResult
from backend.services.kernel_audit import (
    _finalize_budget,
    _is_quota_error,
    collect_hunt_apis,
    run_kernel_audit,
)


class KindTests(unittest.TestCase):
    def test_normalize(self):
        self.assertEqual(normalize_kind("audit"), KIND_AUDIT)
        self.assertEqual(normalize_kind("solo"), KIND_AUDIT)
        self.assertEqual(normalize_kind(None), "patch_diff")
        self.assertEqual(normalize_kind("patch_diff"), "patch_diff")


class KernelAuditFlowTests(unittest.TestCase):
    def test_offline_audit_writes_pack(self):
        scores = [
            {
                "name": "AfdBind",
                "risk": "high",
                "method": "neither",
                "size": 400,
                "why": ["copy without probe/MDL"],
                "rva": "0x1000",
            }
        ]
        surface = {
            "status": "ok",
            "dispatch": {"handler": "AfdDispatchDeviceControl", "limit": 20, "ioctl": [{"handler": "AfdBind", "method": "neither"}]},
            "immediate": {"symbol": None, "entries": [], "filled": 0},
            "fastio": {"handler": None, "callees": []},
            "major_functions": {"create": {"handler": "AfdDispatchCreate", "size": 80}},
            "handler_count": 1,
            "scores": scores,
        }
        pe = {
            "original_filename": "afd.sys",
            "file_version": "10.0.26100.1",
            "machine": "AMD64",
            "size": 123,
            "sha256": "abc",
        }
        blocks = [
            {
                "name": "AfdBind",
                "new": {
                    "rva": "0x1000",
                    "size": 400,
                    "calls": ["memcpy"],
                    "disasm": ["0001  call memcpy", "0002  ret"],
                },
                "old": {},
            }
        ]
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            sample = work / "sample.sys"
            sample.write_bytes(b"MZ")
            with patch("backend.services.kernel_audit.extract_pe", return_value=pe), patch(
                "backend.services.kernel_audit.fetch_pdb", side_effect=RuntimeError("no net")
            ), patch(
                "backend.services.kernel_audit.build_surface_map", return_value=surface
            ), patch(
                "backend.services.kernel_audit.disassemble_functions", return_value=blocks
            ), patch(
                "backend.services.kernel_audit.llm_configured", return_value=False
            ):
                art = run_kernel_audit(sample, work, "afd audit", run_llm=True)

            pack = art["kernel_audit"]
            self.assertEqual(pack["kind"], "kernel_audit")
            self.assertEqual(pack["verdict"], "likely")
            self.assertTrue(any(f["pattern"] == "missing_probe" for f in pack["findings"]))
            self.assertIn("## 1. 结论", pack["report"])
            self.assertIn("禁止 exploit", pack["report"])
            self.assertTrue((work / "kernel_audit.json").is_file())
            saved = json.loads((work / "kernel_audit.json").read_text(encoding="utf-8"))
            self.assertEqual(saved["verdict"], "likely")
            self.assertEqual(art["llm_report"], pack["report"])
            self.assertEqual([a["handler"] for a in pack["hunt_apis"]], ["AfdBind"])
            self.assertEqual(pack.get("agents") or [], [])

    def test_callee_follow_skips_kernel_apis(self):
        from backend.services.kernel_audit import _callee_follow_names

        scores = [
            {
                "name": "AfdDispatchImmediateIrp",
                "risk": "high",
                "top_calls": [
                    "Feature_1943735611__private_IsEnabledDeviceUsageNoInline",
                    "_guard_dispatch_icall",
                    "IofCompleteRequest",
                    "AfdImmediateCallDispatch",
                    "ExAllocatePool2",
                ],
            }
        ]
        blocks = [
            {
                "name": "AfdDispatchImmediateIrp",
                "new": {"calls": ["AfdImmediateCallDispatch", "memcpy", "WPP_SF_"]},
            }
        ]
        names = _callee_follow_names(scores, blocks, ["AfdDispatchImmediateIrp"])
        self.assertIn("AfdImmediateCallDispatch", names)
        self.assertNotIn("IofCompleteRequest", names)
        self.assertNotIn("ExAllocatePool2", names)
        self.assertNotIn("memcpy", names)
        self.assertTrue(all(not n.startswith("Feature_") for n in names))


class HuntApiTests(unittest.TestCase):
    def test_collect_neither_groups_and_skips_buffered(self):
        surface = {
            "dispatch": {
                "handler": "AfdDispatchDeviceControl",
                "ioctl": [
                    {"code": "0x12003", "method": "neither", "handler": "AfdBind"},
                    {"code": "0x12007", "method": "neither", "handler": "AfdBind"},
                    {"code": "0x1200c", "method": "buffered", "handler": "AfdAccept"},
                    {"code": "0x12023", "method": "neither", "handler": "AfdDispatchImmediateIrp"},
                    {"code": "0x12027", "method": "neither", "handler": "AfdDispatchImmediateIrp"},
                ],
            },
            "immediate": {
                "symbol": "AfdImmediateCallDispatch",
                "entries": [
                    {"index": 0, "handler": "AfdFastIo"},
                    {"index": 1, "handler": "AfdTLSendMessage"},
                    {"index": 2, "handler": "Feature_1"},
                ],
            },
            "fastio": {"callees": [{"to": "AfdRioFastIo"}, {"to": "IofCompleteRequest"}]},
            "major_functions": {
                "create": {"handler": "AfdDispatchCreate"},
                "close": {"handler": "AfdDispatchClose"},
            },
        }
        scores = [
            {"name": "AfdBind", "risk": "high", "why": ["METHOD_NEITHER"]},
            {"name": "AfdAccept", "risk": "buffered", "why": ["METHOD_BUFFERED"]},
            {"name": "AfdDispatchImmediateIrp", "risk": "high", "why": ["trampoline"]},
            {"name": "AfdFastIo", "risk": "medium", "why": ["copy"]},
            {"name": "AfdTLSendMessage", "risk": "high", "why": ["copy without probe/MDL"]},
            {"name": "AfdRioFastIo", "risk": "medium", "why": ["fastio"]},
            {"name": "AfdDispatchCreate", "risk": "low", "why": ["no copy"]},
        ]
        apis = collect_hunt_apis(surface, scores)
        handlers = [a["handler"] for a in apis]
        kinds = {a["handler"]: a["kind"] for a in apis}
        self.assertIn("AfdBind", handlers)
        self.assertEqual(kinds["AfdBind"], "ioctl")
        bind = next(a for a in apis if a["handler"] == "AfdBind")
        self.assertEqual(bind["codes"], ["0x12003", "0x12007"])
        self.assertEqual(bind["budget"], "full")
        self.assertNotIn("AfdAccept", handlers)
        self.assertNotIn("AfdDispatchImmediateIrp", handlers)
        self.assertNotIn("AfdImmediateCallDispatch", handlers)
        self.assertNotIn("Feature_1", handlers)
        self.assertNotIn("IofCompleteRequest", handlers)
        self.assertNotIn("AfdDispatchClose", handlers)
        self.assertNotIn("AfdDispatchCreate", handlers)
        self.assertEqual(kinds["AfdFastIo"], "immediate")
        self.assertEqual(kinds["AfdTLSendMessage"], "immediate")
        self.assertEqual(kinds["AfdRioFastIo"], "fastio")

    def test_hardened_neither_uses_short_budget(self):
        surface = {
            "dispatch": {
                "handler": "AfdDispatchDeviceControl",
                "ioctl": [{"code": "0x1201f", "method": "neither", "handler": "AfdSend"}],
            },
            "immediate": {"entries": []},
            "fastio": {"callees": []},
            "major_functions": {},
        }
        scores = [{"name": "AfdSend", "risk": "hardened", "why": ["has probe or MDL"]}]
        apis = collect_hunt_apis(surface, scores)
        self.assertEqual(len(apis), 1)
        self.assertEqual(apis[0]["budget"], "short")

    def test_one_agent_per_hunt_api(self):
        scores = [
            {
                "name": "AfdBind",
                "risk": "high",
                "method": "neither",
                "size": 400,
                "why": ["copy without probe/MDL"],
                "rva": "0x1000",
            },
            {
                "name": "AfdConnect",
                "risk": "high",
                "method": "neither",
                "size": 300,
                "why": ["METHOD_NEITHER"],
                "rva": "0x2000",
            },
        ]
        surface = {
            "status": "ok",
            "dispatch": {
                "handler": "AfdDispatchDeviceControl",
                "limit": 20,
                "ioctl": [
                    {"code": "0x12003", "method": "neither", "handler": "AfdBind"},
                    {"code": "0x12007", "method": "neither", "handler": "AfdConnect"},
                ],
            },
            "immediate": {"symbol": None, "entries": [], "filled": 0},
            "fastio": {"handler": None, "callees": []},
            "major_functions": {},
            "handler_count": 2,
            "scores": scores,
        }
        pe = {
            "original_filename": "afd.sys",
            "file_version": "10.0.26100.1",
            "machine": "AMD64",
            "size": 123,
            "sha256": "abc",
        }
        done = LoopResult(
            text='{"done":true,"verdict":"none","unresolved":[],"findings":[]}',
            parsed={"done": True, "verdict": "none", "unresolved": [], "findings": [], "followed": ["AfdBind"]},
            tool_log=[],
            calls=3,
            rounds=2,
        )
        writer = type("R", (), {"content": "## 1. 结论\n按入口跟完。\n## 2. 用户入口（IOCTL / FastIo / MajorFunction）\n-\n## 3. 处理函数打分\n-\n## 4. 缺陷类证据\n-\n## 5. 隔离 VM 观察清单\n-"})()
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            sample = work / "sample.sys"
            sample.write_bytes(b"MZ")
            with patch("backend.services.kernel_audit.extract_pe", return_value=pe), patch(
                "backend.services.kernel_audit.fetch_pdb", side_effect=RuntimeError("no net")
            ), patch(
                "backend.services.kernel_audit.build_surface_map", return_value=surface
            ), patch(
                "backend.services.kernel_audit.disassemble_functions", return_value=[]
            ), patch(
                "backend.services.kernel_audit.llm_configured", return_value=True
            ), patch(
                "backend.services.kernel_audit.run_tool_loop", return_value=done
            ) as loop, patch(
                "backend.services.kernel_audit.make_chat"
            ) as chat, patch(
                "backend.services.kernel_audit.bind_tools", return_value=[]
            ), patch(
                "backend.services.kernel_audit.AnalysisToolbox"
            ):
                chat.return_value.invoke.return_value = writer
                art = run_kernel_audit(sample, work, "afd audit", run_llm=True)

        self.assertEqual(loop.call_count, 2)
        users = [c.kwargs.get("user") or "" for c in loop.call_args_list]
        self.assertTrue(any("AfdBind" in u and "不要审其它" in u for u in users))
        self.assertTrue(any("AfdConnect" in u for u in users))
        pack = art["kernel_audit"]
        self.assertEqual(pack["llm_review"]["mode"], "per_api_agents")
        self.assertEqual(pack["llm_review"]["agent_count"], 2)
        self.assertEqual(len(pack["agents"]), 2)

    def test_finalize_budget_moves_unresolved_to_blocked(self):
        rec = {
            "verdict": "unknown",
            "summary": "still going",
            "unresolved": ["netio!WskSend"],
            "blocked": [],
            "rounds": 14,
            "tool_call_count": 20,
        }
        _finalize_budget(rec, max_rounds=14, max_calls=32)
        self.assertEqual(rec["unresolved"], [])
        self.assertEqual(rec["blocked"][0]["reason"], "budget_exhausted")
        self.assertIn("预算用尽", rec["summary"])

    def test_quota_error_detects_402(self):
        self.assertTrue(_is_quota_error("Error code: 402 - Insufficient Balance"))
        self.assertFalse(_is_quota_error("pdb missing"))

    def test_quota_stops_remaining_agents(self):
        from backend.services.llm_service import LLMError

        scores = [
            {"name": "AfdBind", "risk": "high", "method": "neither", "size": 100, "why": ["x"], "rva": "0x1"},
            {"name": "AfdConnect", "risk": "high", "method": "neither", "size": 100, "why": ["x"], "rva": "0x2"},
            {"name": "AfdSend", "risk": "high", "method": "neither", "size": 100, "why": ["x"], "rva": "0x3"},
        ]
        surface = {
            "status": "ok",
            "dispatch": {
                "handler": "AfdDispatchDeviceControl",
                "ioctl": [
                    {"code": "0x1", "method": "neither", "handler": "AfdBind"},
                    {"code": "0x2", "method": "neither", "handler": "AfdConnect"},
                    {"code": "0x3", "method": "neither", "handler": "AfdSend"},
                ],
            },
            "immediate": {"symbol": None, "entries": []},
            "fastio": {"callees": []},
            "major_functions": {},
            "handler_count": 3,
            "scores": scores,
        }
        pe = {"original_filename": "afd.sys", "file_version": "1", "machine": "AMD64", "size": 1, "sha256": "a"}
        done = LoopResult(
            text="{}",
            parsed={"done": True, "verdict": "none", "unresolved": [], "findings": []},
            tool_log=[],
            calls=2,
            rounds=2,
        )
        n = {"i": 0}

        def loop_side_effect(*_a, **_k):
            n["i"] += 1
            if n["i"] >= 2:
                raise LLMError("Error code: 402 - Insufficient Balance")
            return done

        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            sample = work / "sample.sys"
            sample.write_bytes(b"MZ")
            with patch("backend.services.kernel_audit.extract_pe", return_value=pe), patch(
                "backend.services.kernel_audit.fetch_pdb", side_effect=RuntimeError("no net")
            ), patch(
                "backend.services.kernel_audit.build_surface_map", return_value=surface
            ), patch(
                "backend.services.kernel_audit.disassemble_functions", return_value=[]
            ), patch(
                "backend.services.kernel_audit.llm_configured", return_value=True
            ), patch(
                "backend.services.kernel_audit.run_tool_loop", side_effect=loop_side_effect
            ) as loop, patch(
                "backend.services.kernel_audit.make_chat"
            ), patch(
                "backend.services.kernel_audit.bind_tools", return_value=[]
            ), patch(
                "backend.services.kernel_audit.AnalysisToolbox"
            ):
                art = run_kernel_audit(sample, work, "afd audit", run_llm=True)
                self.assertTrue((work / "path_agents.json").is_file())

        self.assertEqual(loop.call_count, 2)
        agents = art["kernel_audit"]["agents"]
        self.assertEqual(len(agents), 2)
        self.assertTrue(agents[-1].get("error"))
        self.assertIn("402", art["kernel_audit"]["error"] or "")
        self.assertIn("额度不足", art["kernel_audit"]["report"])

    def test_resume_skips_complete_agents(self):
        scores = [
            {"name": "AfdBind", "risk": "high", "method": "neither", "size": 100, "why": ["x"], "rva": "0x1"},
            {"name": "AfdConnect", "risk": "high", "method": "neither", "size": 100, "why": ["x"], "rva": "0x2"},
        ]
        surface = {
            "status": "ok",
            "dispatch": {
                "handler": "AfdDispatchDeviceControl",
                "ioctl": [
                    {"code": "0x1", "method": "neither", "handler": "AfdBind"},
                    {"code": "0x2", "method": "neither", "handler": "AfdConnect"},
                ],
            },
            "immediate": {"symbol": None, "entries": []},
            "fastio": {"callees": []},
            "major_functions": {},
            "handler_count": 2,
            "scores": scores,
        }
        pe = {"original_filename": "afd.sys", "file_version": "1", "machine": "AMD64", "size": 1, "sha256": "a"}
        done = LoopResult(
            text="{}",
            parsed={"done": True, "verdict": "none", "unresolved": [], "findings": [], "followed": ["AfdConnect"]},
            tool_log=[],
            calls=2,
            rounds=2,
        )
        writer = type("R", (), {"content": "## 1. 结论\nx\n## 2. 用户入口（IOCTL / FastIo / MajorFunction）\n-\n## 3. 处理函数打分\n-\n## 4. 缺陷类证据\n-\n## 5. 隔离 VM 观察清单\n-"})()
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            sample = work / "sample.sys"
            sample.write_bytes(b"MZ")
            (work / "path_agents.json").write_text(
                json.dumps(
                    {
                        "agents": [
                            {
                                "id": "ioctl:AfdBind",
                                "handler": "AfdBind",
                                "verdict": "none",
                                "rounds": 4,
                                "unresolved": [],
                                "summary": "cached",
                            }
                        ]
                    },
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )
            with patch("backend.services.kernel_audit.extract_pe", return_value=pe), patch(
                "backend.services.kernel_audit.fetch_pdb", side_effect=RuntimeError("no net")
            ), patch(
                "backend.services.kernel_audit.build_surface_map", return_value=surface
            ), patch(
                "backend.services.kernel_audit.disassemble_functions", return_value=[]
            ), patch(
                "backend.services.kernel_audit.llm_configured", return_value=True
            ), patch(
                "backend.services.kernel_audit.run_tool_loop", return_value=done
            ) as loop, patch(
                "backend.services.kernel_audit.make_chat"
            ) as chat, patch(
                "backend.services.kernel_audit.bind_tools", return_value=[]
            ), patch(
                "backend.services.kernel_audit.AnalysisToolbox"
            ):
                chat.return_value.invoke.return_value = writer
                art = run_kernel_audit(sample, work, "afd audit", run_llm=True, resume=True)

        self.assertEqual(loop.call_count, 1)
        users = [c.kwargs.get("user") or "" for c in loop.call_args_list]
        self.assertTrue(any("AfdConnect" in u for u in users))
        handlers = [a["handler"] for a in art["kernel_audit"]["agents"]]
        self.assertEqual(handlers, ["AfdBind", "AfdConnect"])

    def test_hardened_agent_gets_short_tool_budget(self):
        scores = [
            {"name": "AfdSend", "risk": "hardened", "method": "neither", "size": 200, "why": ["probe"], "rva": "0x1"},
        ]
        surface = {
            "status": "ok",
            "dispatch": {
                "handler": "AfdDispatchDeviceControl",
                "ioctl": [{"code": "0x1201f", "method": "neither", "handler": "AfdSend"}],
            },
            "immediate": {"symbol": None, "entries": []},
            "fastio": {"callees": []},
            "major_functions": {},
            "handler_count": 1,
            "scores": scores,
        }
        pe = {"original_filename": "afd.sys", "file_version": "1", "machine": "AMD64", "size": 1, "sha256": "a"}
        done = LoopResult(
            text="{}",
            parsed={"done": True, "verdict": "none", "unresolved": [], "findings": []},
            tool_log=[],
            calls=2,
            rounds=2,
        )
        writer = type("R", (), {"content": "## 1. 结论\nx\n## 2. 用户入口（IOCTL / FastIo / MajorFunction）\n-\n## 3. 处理函数打分\n-\n## 4. 缺陷类证据\n-\n## 5. 隔离 VM 观察清单\n-"})()
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            sample = work / "sample.sys"
            sample.write_bytes(b"MZ")
            with patch("backend.services.kernel_audit.extract_pe", return_value=pe), patch(
                "backend.services.kernel_audit.fetch_pdb", side_effect=RuntimeError("no net")
            ), patch(
                "backend.services.kernel_audit.build_surface_map", return_value=surface
            ), patch(
                "backend.services.kernel_audit.disassemble_functions", return_value=[]
            ), patch(
                "backend.services.kernel_audit.llm_configured", return_value=True
            ), patch(
                "backend.services.kernel_audit.run_tool_loop", return_value=done
            ) as loop, patch(
                "backend.services.kernel_audit.make_chat"
            ) as chat, patch(
                "backend.services.kernel_audit.bind_tools", return_value=[]
            ), patch(
                "backend.services.kernel_audit.AnalysisToolbox"
            ):
                chat.return_value.invoke.return_value = writer
                run_kernel_audit(sample, work, "afd audit", run_llm=True)

        budget = loop.call_args.kwargs.get("budget")
        self.assertEqual(budget.max_rounds, PATH_HARDENED_BUDGET.max_rounds)
        self.assertLess(budget.max_rounds, PATH_BUDGET.max_rounds)


if __name__ == "__main__":
    unittest.main()

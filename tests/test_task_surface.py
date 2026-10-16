import unittest
import threading
import time
from unittest.mock import Mock, call, patch

from artex_agent.artex_api import MAX_RESPONSE_BYTES, TASK_DETAIL_SURFACES, ArtexAPIError, ArtexClient


class TaskSurfaceTests(unittest.TestCase):
    def setUp(self):
        self.client = ArtexClient()
        self.client._request = Mock(return_value={"ok": True})

    def test_read_surfaces_use_fixed_get_routes(self):
        cases = {
            "sessions": "/api/exploration/main-sessions?task=3",
            "intents": "/api/exploration/intents?task=3&limit=30&page=1&before=8",
            "exploration": "/api/exploration/graph?task=3",
            "broadcast": "/api/exploration/nodes?task=3&page=2&size=30",
            "activity": "/api/exploration/activity?task=3&since=8&limit=30",
            "findings": "/api/exploration/findings?task=3",
            "assets": "/api/assets?task_id=3&limit=30&offset=30",
            "coverage": "/api/tasks/3/coverage",
            "coverage_graph": "/api/tasks/3/coverage-graph",
            "intercept_approvals": "/api/intercept/task/3?page=2&size=30",
            "intercept_rules": "/api/tasks/3/intercept-rules",
        }
        for surface, expected in cases.items():
            with self.subTest(surface=surface):
                self.client._request.reset_mock()
                self.client.get_task_surface(3, surface, page=1 if surface == "intents" else 2, size=30, before=8)
                self.client._request.assert_called_once_with("GET", expected)

    def test_report_surface_reads_native_and_cowork_reports_separately(self):
        self.client._request = Mock(return_value={"markdown": "native report"})
        self.client.read_task_workspace_file = Mock(return_value={"content": "Cowork report"})
        result = self.client.get_task_surface(3, "report")
        self.client._request.assert_called_once_with("GET", "/api/report?task=3")
        self.client.read_task_workspace_file.assert_called_once_with(
            3, "tasks/3/reports/cowork-report.md"
        )
        self.assertEqual(result["native"], {"markdown": "native report"})
        self.assertEqual(result["cowork"], {"content": "Cowork report"})
        self.assertIsNone(result["native_read_error"])
        self.assertIsNone(result["cowork_read_error"])

    def test_report_surface_treats_missing_cowork_report_as_empty(self):
        self.client._request = Mock(return_value={"markdown": "native report"})
        self.client.read_task_workspace_file = Mock(
            side_effect=ArtexAPIError("ARTEx API returned HTTP 404: file not found")
        )
        result = self.client.get_task_surface(3, "report")
        self.assertEqual(result["cowork"], {"content": "", "missing": True})
        self.assertIsNone(result["cowork_read_error"])

    def test_report_surface_preserves_cowork_report_when_native_report_fails(self):
        self.client._request = Mock(side_effect=ArtexAPIError("native report unavailable"))
        self.client.read_task_workspace_file = Mock(return_value={"content": "Cowork report"})
        result = self.client.get_task_surface(3, "report")
        self.assertIsNone(result["native"])
        self.assertEqual(result["native_read_error"], "native report unavailable")
        self.assertEqual(result["cowork"], {"content": "Cowork report"})

    def test_task_cowork_traffic_reads_are_task_bound_and_bounded(self):
        self.client.list_cowork_traffic(3, page=2, size=25)
        self.client._request.assert_called_once_with("GET", "/api/tasks/3/cowork/traffic?page=2&size=25")
        self.client._request.reset_mock()
        capture_id = "cowork-t3-0123456789abcdef0123456789abcdef-1"
        self.client.get_cowork_traffic(3, capture_id)
        self.client._request.assert_called_once_with("GET", f"/api/tasks/3/cowork/traffic/{capture_id}")
        self.client._request.reset_mock()
        blob_hash = "a" * 64
        self.client.read_cowork_traffic_blob(3, capture_id, blob_hash, offset=8192, length=4096)
        self.client._request.assert_called_once_with(
            "GET", f"/api/tasks/3/cowork/traffic/{capture_id}/blob?hash={blob_hash}&offset=8192&length=4096"
        )
        self.client._request.reset_mock()
        with self.assertRaises(ValueError):
            self.client.get_cowork_traffic(3, "cowork-t4-0123456789abcdef0123456789abcdef-1")
        with self.assertRaises(ValueError):
            self.client.list_cowork_traffic(3, page=-1)
        with self.assertRaises(ValueError):
            self.client.list_cowork_traffic(3, page=1_000_001)
        with self.assertRaises(ValueError):
            self.client.read_cowork_traffic_blob(3, capture_id, blob_hash, length=8193)
        self.client._request.assert_not_called()

    def test_cowork_capture_binding_uses_task_finding_route_and_exact_confirmation(self):
        capture_id = "cowork-t3-0123456789abcdef0123456789abcdef-1"
        refs = [{"traffic_id": capture_id, "role": "proof", "note": "observed response"}]
        self.client.bind_cowork_traffic_to_finding(
            3, 42, "http://127.0.0.1:18081", refs,
            "CONFIRM bind_cowork_traffic task=3 finding=42",
        )
        self.client._request.assert_called_once_with(
            "POST", "/api/tasks/3/cowork/findings/42/traffic", {
                "target": "http://127.0.0.1:18081",
                "traffic_refs": refs,
                "confirmation": "CONFIRM bind_cowork_traffic task=3 finding=42",
            },
        )
        self.client._request.reset_mock()
        self.client.get_finding_traffic(3, 42)
        self.client._request.assert_called_once_with(
            "GET", "/api/exploration/findings/42/traffic?context_task=3",
        )
        self.client._request.reset_mock()
        with self.assertRaises(ValueError):
            self.client.bind_cowork_traffic_to_finding(
                3, 42, "http://127.0.0.1:18081", refs, "CONFIRM bind_cowork_traffic task=3",
            )
        with self.assertRaises(ValueError):
            self.client.bind_cowork_traffic_to_finding(
                3, 42, "http://127.0.0.1:18081",
                [{"traffic_id": "cowork-t4-0123456789abcdef0123456789abcdef-1"}],
                "CONFIRM bind_cowork_traffic task=3 finding=42",
            )
        with self.assertRaises(ValueError):
            self.client.bind_cowork_traffic_to_finding(
                3, 42, "http://127.0.0.1:18081", refs * 2,
                "CONFIRM bind_cowork_traffic task=3 finding=42",
            )
        self.client._request.assert_not_called()

    def test_existing_finding_traffic_reads_are_task_bound_and_body_bounded(self):
        self.client.get_finding_traffic(3, 42)
        self.client._request.assert_called_once_with(
            "GET", "/api/exploration/findings/42/traffic?context_task=3",
        )
        self.client._request.reset_mock()
        self.client.get_finding_traffic(3, 42, 7)
        self.client._request.assert_called_once_with(
            "GET", "/api/exploration/findings/42/traffic/7?context_task=3",
        )
        self.client._request.reset_mock()
        self.client.read_finding_traffic_body(3, 42, 7, "request", offset=8192, length=2048)
        self.client._request.assert_called_once_with(
            "GET", "/api/exploration/findings/42/traffic/7/body?context_task=3&side=request&offset=8192&length=2048",
        )
        self.client._request.reset_mock()
        with self.assertRaises(ValueError):
            self.client.read_finding_traffic_body(3, 42, 7, "response", length=8193)
        self.client._request.assert_not_called()

    def test_dashboard_snapshot_uses_read_only_pinned_or_active_routes(self):
        result = self.client.get_dashboard_snapshot(3)
        self.assertTrue(result["read_only"])
        self.assertEqual(result["task_selection"], "explicit")
        calls = {call.args[1] for call in self.client._request.call_args_list}
        self.assertEqual(calls, {
            "/api/tasks",
            "/api/exploration/findings?task=3",
            "/api/stats?task=3",
            "/api/intercept/pending",
            "/api/exploration/activity?task=3&limit=30",
            "/api/exploration/tokens?task=3",
            "/api/tokens/conversations",
            "/api/tokens/usage?days=365",
            "/api/assets/counts?task_id=3",
        })
        self.assertIn("LLM/API credential configuration", result["excluded"])

    def test_dashboard_snapshot_rejects_negative_task_id_before_calls(self):
        with self.assertRaises(ValueError):
            self.client.get_dashboard_snapshot(-1)
        self.client._request.assert_not_called()

    def test_cowork_asset_registration_uses_task_scoped_server_gate(self):
        assets = [{"type": "endpoint", "url": "http://127.0.0.1:18081/api/items", "method": "GET"}]
        self.client.register_cowork_assets(3, "http://127.0.0.1:18081", assets, "CONFIRM insert_assets task=3")
        self.client._request.assert_called_once_with("POST", "/api/tasks/3/cowork/assets", {
            "target": "http://127.0.0.1:18081",
            "assets": assets,
            "confirmation": "CONFIRM insert_assets task=3",
        })

    def test_records_matches_native_tab_with_graph_facts_and_workspace_files(self):
        def request(_method, path, _payload=None):
            if path.startswith("/api/exploration/graph"):
                return {"nodes": [
                    {"id": "1", "type": "fact", "state": "confirmed"},
                    {"id": "2", "type": "goal", "state": "open"},
                    {"id": "3", "type": "fact", "state": "origin"},
                ]}
            if path.startswith("/api/tasks/3/cowork/traffic"):
                return {"enabled": True, "total": 1, "exchanges": [{"id": "cowork-t3-capture"}]}
            return {"entries": [
                {"name": "folder", "dir": True, "mtime": 50},
                {"name": "old.md", "dir": False, "mtime": 10},
                {"name": "new.md", "dir": False, "mtime": 20},
            ]}
        self.client._request = Mock(side_effect=request)
        records = self.client.get_task_surface(3, "records")
        self.assertEqual([node["id"] for node in records["facts"]], ["1"])
        self.assertEqual([entry["name"] for entry in records["files"]], ["new.md", "old.md"])
        self.assertEqual(records["traffic"]["total"], 1)
        self.assertIsNone(records["facts_error"])
        self.assertIsNone(records["files_error"])
        self.assertIsNone(records["traffic_error"])

    def test_records_surface_uses_bounded_page_arguments_for_cowork_traffic(self):
        self.client._request = Mock(side_effect=lambda _method, path, _payload=None: (
            {"nodes": []} if path.startswith("/api/exploration/graph") else
            {"entries": []} if path.startswith("/api/workspace/list") else
            {"enabled": True, "total": 30, "page": 2, "size": 25, "exchanges": []}
        ))
        result = self.client.get_task_surface(3, "records", page=3, size=25)
        self.assertEqual(result["traffic"]["page"], 2)
        self.assertIn(
            call("GET", "/api/tasks/3/cowork/traffic?page=2&size=25"),
            self.client._request.call_args_list,
        )

    def test_records_preserves_evidence_files_if_graph_read_fails(self):
        def request(_method, path, _payload=None):
            if path.startswith("/api/exploration/graph"):
                raise ArtexAPIError("graph unavailable")
            return {"entries": [{"name": "evidence.md", "dir": False, "mtime": 1}]}
        self.client._request = Mock(side_effect=request)
        records = self.client.get_task_surface(3, "records")
        self.assertEqual(records["facts"], [])
        self.assertEqual(records["facts_error"]["read_error"], "graph unavailable")
        self.assertEqual([item["name"] for item in records["files"]], ["evidence.md"])
        self.assertIsNone(records["files_error"])

    def test_records_treats_missing_new_task_evidence_directory_as_empty(self):
        def request(_method, path, _payload=None):
            if path.startswith("/api/exploration/graph"):
                return {"nodes": []}
            raise ArtexAPIError("ARTEx API GET /api/workspace/list?path=tasks%2F3%2Fevidence: HTTP 404: path not found")
        self.client._request = Mock(side_effect=request)
        records = self.client.get_task_surface(3, "records")
        self.assertEqual(records["facts"], [])
        self.assertEqual(records["files"], [])
        self.assertIsNone(records["facts_error"])
        self.assertIsNone(records["files_error"])

    def test_records_does_not_hide_non_404_workspace_failures(self):
        def request(_method, path, _payload=None):
            if path.startswith("/api/exploration/graph"):
                return {"nodes": []}
            raise ArtexAPIError("ARTEx API GET /api/workspace/list: HTTP 500: database unavailable")
        self.client._request = Mock(side_effect=request)
        records = self.client.get_task_surface(3, "records")
        self.assertEqual(records["files"], [])
        self.assertEqual(records["files_error"]["read_error"], "ARTEx API GET /api/workspace/list: HTTP 500: database unavailable")

    def test_overview_reads_task_goals_scope_and_constraints(self):
        result = self.client.get_task_surface(3, "overview")
        self.assertEqual(set(result), {"task", "goals", "scope", "constraints"})
        self.assertEqual(self.client._request.call_count, 4)
        self.assertEqual(
            {call.args[1] for call in self.client._request.call_args_list},
            {
                "/api/tasks/3",
                "/api/tasks/3/goals",
                "/api/tasks/3/scope",
                "/api/tasks/3/constraints",
            },
        )

    def test_overview_keeps_partial_data_when_one_native_section_fails(self):
        original = self.client._request
        def request(method, path, payload=None):
            if path.endswith("/constraints"):
                raise ArtexAPIError("constraints endpoint unavailable")
            return original(method, path, payload)
        self.client._request = Mock(side_effect=request)
        result = self.client.get_task_surface(3, "overview")
        self.assertEqual(result["task"], {"ok": True})
        self.assertEqual(result["constraints"], {
            "read_error": "constraints endpoint unavailable", "available": False,
        })

    def test_preflight_context_fails_closed_on_incomplete_task_state(self):
        def request(_method, path, _payload=None):
            if path.endswith("/scope"):
                raise ArtexAPIError("scope endpoint unavailable")
            return {"ok": True}
        self.client._request = Mock(side_effect=request)
        with self.assertRaisesRegex(ArtexAPIError, "complete Task context"):
            self.client.get_task_context(3)

    def test_session_and_retests_are_task_scoped(self):
        self.client.get_task_surface(3, "session_history", session="intent:42", before=9, size=25)
        self.client._request.assert_called_once_with(
            "GET", "/api/exploration/activity/history?task=3&session=intent%3A42&limit=25&before=9"
        )
        self.client._request.reset_mock()
        self.client.get_task_surface(3, "session_history", session="cowork", size=25)
        self.client._request.assert_called_once_with(
            "GET", "/api/exploration/activity/history?task=3&session=cowork&limit=25"
        )
        self.client._request.reset_mock()
        self.client.get_finding = Mock(return_value={"id": 4})
        self.client.get_task_surface(3, "retests", finding_id=4)
        self.client.get_finding.assert_called_once_with(4, 3)
        self.client._request.assert_called_once_with("GET", "/api/exploration/findings/4/retests")

    def test_activity_detail_requires_positive_task_and_sequence_and_is_task_scoped(self):
        self.client.get_activity_detail(3, 148)
        self.client._request.assert_called_once_with(
            "GET", "/api/exploration/activity/148?task=3"
        )
        self.client._request.reset_mock()
        for task_id, seq in ((0, 1), (1, 0), (-1, 1), (1, -1)):
            with self.subTest(task_id=task_id, seq=seq), self.assertRaises(ValueError):
                self.client.get_activity_detail(task_id, seq)
        self.client._request.assert_not_called()

    def test_rejects_unsafe_or_unscoped_requests(self):
        for surface in ("http://127.0.0.1/", "delete", ""):
            with self.subTest(surface=surface), self.assertRaises(ValueError):
                self.client.get_task_surface(3, surface)
        with self.assertRaises(ValueError):
            self.client.get_task_surface(0, "overview")
        with self.assertRaises(ValueError):
            self.client.get_task_surface(3, "retests")
        self.client.get_finding = Mock(return_value=None)
        with self.assertRaises(ArtexAPIError):
            self.client.get_task_surface(3, "retests", finding_id=999)
        self.client._request.assert_not_called()

    def test_session_history_rejects_non_native_session_key_before_request(self):
        for session in ("worker#1", "intent:0", "main:-1", "https://example.com", "x" * 10000):
            with self.subTest(session=session[:40]), self.assertRaises(ValueError):
                self.client.get_task_surface(3, "session_history", session=session)
        self.client._request.assert_not_called()

    def test_page_size_is_bounded(self):
        self.client.get_task_surface(3, "assets", page=0, size=10000)
        self.client._request.assert_called_once_with(
            "GET", "/api/assets?task_id=3&limit=200&offset=0"
        )
        self.client._request.reset_mock()
        self.client.get_task_surface(3, "session_history", session="cowork", size=10000)
        self.client._request.assert_called_once_with(
            "GET", "/api/exploration/activity/history?task=3&session=cowork&limit=500"
        )

    def test_oversized_response_fails_instead_of_returning_truncated_json(self):
        class Response:
            def __enter__(self):
                return self
            def __exit__(self, *_args):
                return False
            def read(self, size):
                return b"{" + b" " * size
        class Opener:
            def open(self, *_args, **_kwargs):
                return Response()
        with patch("artex_agent.artex_api.build_opener", return_value=Opener()):
            with self.assertRaisesRegex(ArtexAPIError, "response exceeded"):
                ArtexClient()._request("GET", "/api/tasks/3")

    def test_intent_index_requires_cursor_pagination(self):
        with self.assertRaisesRegex(ValueError, "before cursor"):
            self.client.get_task_surface(3, "intents", page=2)
        self.client._request.assert_not_called()

    def test_surface_bundle_reads_all_task_tabs_and_skips_retests_without_finding(self):
        self.client.get_task_surface = Mock(side_effect=lambda task_id, surface, **kwargs: {"surface": surface})
        result = self.client.get_task_surface_bundle(3, session="intent:9")
        self.assertTrue(result["read_only"])
        self.assertEqual(result["task_id"], 3)
        self.assertIn("overview", result["surfaces"])
        self.assertEqual(result["surfaces"]["session_history"], {"surface": "session_history"})
        self.assertEqual(result["surfaces"]["cowork_activity"], {"surface": "session_history"})
        self.assertEqual(result["surfaces"]["retests"], {"skipped": "finding_id not supplied"})
        self.assertEqual(self.client.get_task_surface.call_count, 16)

    def test_surface_bundle_preserves_partial_results(self):
        def read(_task_id, surface, **_kwargs):
            if surface == "coverage":
                raise ArtexAPIError("endpoint unavailable")
            return {"surface": surface}
        self.client.get_task_surface = Mock(side_effect=read)
        result = self.client.get_task_surface_bundle(3)
        self.assertEqual(result["surfaces"]["overview"], {"surface": "overview"})
        self.assertEqual(result["surfaces"]["coverage"], {"read_error": "endpoint unavailable", "available": False})

    def test_surface_bundle_reads_in_parallel_with_a_bounded_worker_pool(self):
        lock = threading.Lock()
        active = 0
        peak = 0
        def read(_task_id, surface, **_kwargs):
            nonlocal active, peak
            with lock:
                active += 1
                peak = max(peak, active)
            try:
                time.sleep(0.02)
                return {"surface": surface}
            finally:
                with lock:
                    active -= 1
        self.client.get_task_surface = Mock(side_effect=read)
        result = self.client.get_task_surface_bundle(3)
        self.assertTrue(result["read_only"])
        self.assertGreater(peak, 1)
        self.assertLessEqual(peak, 6)
        self.assertEqual(self.client.get_task_surface.call_count, 16)

    def test_bundle_surface_registry_covers_every_native_task_tab(self):
        self.assertEqual(set(TASK_DETAIL_SURFACES), {
            "overview", "sessions", "intents", "exploration", "records", "activity",
            "session_history", "broadcast", "findings", "assets", "coverage",
            "coverage_graph", "intercept_approvals", "intercept_rules", "report",
        })

    def test_finding_report_update_is_task_scoped_put(self):
        self.client.update_finding_report(3, 42, "# Verified", "CONFIRM update_finding_report task=3", 7)
        self.client._request.assert_called_once_with(
            "PUT", "/api/tasks/3/cowork/findings/42/report",
            {"report": "# Verified", "confirmation": "CONFIRM update_finding_report task=3", "evidence_version": 7},
        )

    def test_cowork_finding_report_read_uses_task_and_graph_node_id(self):
        self.client.get_cowork_finding_report(3, 42)
        self.client._request.assert_called_once_with(
            "GET", "/api/tasks/3/cowork/findings/42/report",
        )

    def test_cowork_fact_and_finding_forward_authorized_target_to_server(self):
        self.client.record_task_fact(
            3, "Observed", "Detail", "Evidence", "observed", "http://127.0.0.1:18081",
            "CONFIRM record_fact task=3",
        )
        self.client._request.assert_called_once_with(
            "POST", "/api/tasks/3/cowork/facts", {
                "summary": "Observed", "detail": "Detail", "evidence": "Evidence",
                "confidence": "observed", "target": "http://127.0.0.1:18081",
                "confirmation": "CONFIRM record_fact task=3",
            },
        )
        self.client._request.reset_mock()
        self.client.report_confirmed_finding(
            3, "xss", "Finding", "high", "Confirmed", "Evidence", "http://127.0.0.1:18081",
            "CONFIRM report_finding task=3",
        )
        self.client._request.assert_called_once_with(
            "POST", "/api/tasks/3/cowork/findings", {
                "vulnclass": "xss", "name": "Finding", "severity": "high",
                "summary": "Confirmed", "evidence": "Evidence",
                "target": "http://127.0.0.1:18081", "confirmation": "CONFIRM report_finding task=3",
            },
        )

    def test_cowork_goal_proof_uses_task_owned_route_and_evidence_id(self):
        confirmation = "CONFIRM prove_goal task=3 goal=17 evidence=81"
        self.client.prove_task_goal(3, 17, 81, "http://127.0.0.1:18081", "Existing fact directly proves this goal", confirmation)
        self.client._request.assert_called_once_with(
            "POST", "/api/tasks/3/cowork/goals/17/prove", {
                "evidence_id": 81, "target": "http://127.0.0.1:18081",
                "reason": "Existing fact directly proves this goal", "confirmation": confirmation,
            },
        )

    def test_pause_task_uses_native_control_route_without_resume_action(self):
        confirmation = "CONFIRM pause_task task=3"
        self.client.pause_task(3, confirmation)
        self.client._request.assert_called_once_with("POST", "/api/tasks/3/cowork/pause", {"confirmation": confirmation})

    def test_cowork_retest_records_native_task_route(self):
        self.client.record_cowork_finding_retest(3, 42, "http://127.0.0.1:18081", "reproduced", "still present", "observed response", "CONFIRM record_cowork_retest task=3 finding=42")
        self.client._request.assert_called_once_with(
            "POST", "/api/tasks/3/cowork/retests", {
                "finding_id": 42, "target": "http://127.0.0.1:18081", "verdict": "reproduced",
                "summary": "still present", "evidence": "observed response",
                "confirmation": "CONFIRM record_cowork_retest task=3 finding=42",
            },
        )

    def test_cowork_intercept_decision_uses_task_owned_route(self):
        self.client.decide_cowork_intercept(3, 15, "denied", "CONFIRM decide_intercept task=3 pending=15 decision=denied")
        self.client._request.assert_called_once_with(
            "POST", "/api/tasks/3/cowork/intercepts/15/decide",
            {"decision": "denied", "confirmation": "CONFIRM decide_intercept task=3 pending=15 decision=denied"},
        )

    def test_cowork_intent_batch_uses_task_graph_route(self):
        intents = [{"summary": "Inspect authorized response", "priority": 7, "parent_ids": []}]
        self.client.add_cowork_intents(3, intents, "CONFIRM add_cowork_intents task=3")
        self.client._request.assert_called_once_with(
            "POST", "/api/tasks/3/cowork/intents",
            {"intents": intents, "confirmation": "CONFIRM add_cowork_intents task=3"},
        )

    def test_cowork_intent_completion_uses_task_owned_route(self):
        confirmation = "CONFIRM complete_cowork_intent task=3 intent=9 state=done"
        self.client.complete_cowork_intent(3, 9, "done", "Reviewed", "Evidence", confirmation)
        self.client._request.assert_called_once_with(
            "POST", "/api/tasks/3/cowork/intents/9/complete",
            {"state": "done", "summary": "Reviewed", "evidence": "Evidence", "confirmation": confirmation},
        )


if __name__ == "__main__":
    unittest.main()

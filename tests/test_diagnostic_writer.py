import unittest
import json
from unittest.mock import patch

from artex_agent.desktop_diagnostic_writer import (
    CONFIRMATION,
    _clean_field,
    _validate_task_assets,
    _verify_context,
    artex_register_task_assets,
    artex_record_task_fact,
    artex_prove_goal,
    artex_pause_task,
    artex_record_finding_retest_result,
    artex_decide_intercept,
    artex_add_task_intents,
    artex_complete_cowork_intent,
    artex_report_confirmed_finding,
    artex_record_diagnostic_evidence,
    artex_save_task_report,
    artex_update_finding_status,
    artex_update_finding_report,
    artex_bind_cowork_traffic_to_finding,
    _verify_cowork_activity,
)


class FakeArtexClient:
    def __init__(self, scope=None, constraints=None, task=None, goals=None):
        self.scope = scope if scope is not None else [{"kind": "ip", "net": "127.0.0.1/32"}]
        self.constraints = constraints if constraints is not None else [
            {"kind": "allow", "source": "human", "text": "127.0.0.1:18081만 허용"}
        ]
        self.task = task if task is not None else {"id": 17, "description": "local test"}
        self.goals = goals if goals is not None else [{"text": "허가된 로컬 Juice Shop 취약점 진단"}]
        self.scope_task_ids = []
        self.constraint_task_ids = []

    def clear_token(self):
        pass

    def get_task(self, task_id):
        return self.task

    def list_goals(self, task_id):
        return self.goals

    def list_constraints(self, task_id):
        self.constraint_task_ids.append(task_id)
        return self.constraints

    def list_task_scope(self, task_id):
        self.scope_task_ids.append(task_id)
        return self.scope

    def list_tasks(self):
        fact = getattr(self, "fact", {})
        return {"tasks": [{
            "id": str(self.task.get("id", 17)),
            "latest_record_summary": fact.get("summary", ""),
            "latest_record_unix": 1 if fact else 0,
        }]}


class DiagnosticWriterTests(unittest.TestCase):
    def test_activity_readback_pages_when_new_event_is_beyond_first_history_window(self):
        class Client:
            def __init__(self):
                self.before_values = []

            def get_task_surface(self, task_id, surface, **kwargs):
                self.before_values.append(kwargs.get("before", 0))
                if len(self.before_values) == 1:
                    return {"items": [], "has_more": True, "earliest_cursor": 500}
                return {
                    "items": [{
                        "worker": "cowork", "tool": "record_fact",
                        "tool_use_id": "cowork-fact-77",
                    }],
                    "has_more": True,
                    "earliest_cursor": 1,
                }

        client = Client()
        self.assertTrue(_verify_cowork_activity(client, 17, "record_fact", "cowork-fact-77"))
        self.assertEqual(client.before_values, [0, 500])

    def test_task_report_writer_saves_task_owned_report_and_links_graph_activity(self):
        class Client(FakeArtexClient):
            def __init__(self):
                super().__init__()
                self.file = ""
                self.write_count = 0
                self.fact_count = 0

            def write_workspace_file(self, path, content):
                self.write_count += 1
                self.path, self.file = path, content
                return {"ok": True}

            def read_task_workspace_file(self, task_id, path):
                if not path.startswith(f"tasks/{task_id}/"):
                    raise AssertionError("report path escaped task")
                return {"content": self.file}

            def record_task_fact(self, task_id, summary, detail, evidence, confidence, target, confirmation):
                self.fact_count += 1
                self.fact = {"summary": summary, "detail": detail, "evidence": evidence, "confidence": confidence}
                return {"ok": True, "node_id": "91", "activity_updated": True}

            def get_task_surface(self, task_id, surface, **kwargs):
                if surface == "records":
                    fact = getattr(self, "fact", None)
                    return {"facts": ([{"id": "91", "type": "fact", "payload": fact.copy()}] if fact else [])}
                return {"items": [{"worker": "cowork", "tool": "record_fact", "tool_use_id": "cowork-fact-91"}]}

            def clear_token(self):
                pass

        client = Client()
        with patch("artex_agent.desktop_diagnostic_writer._authenticated_client", return_value=client):
            result = json.loads(artex_save_task_report(
                17, "# Assessment\n\nObserved behavior.", "http://127.0.0.1:18081",
                "CONFIRM save_task_report task=17",
            ))
            first_write_count = client.write_count
            repeated = json.loads(artex_save_task_report(
                17, "# Assessment\n\nObserved behavior.", "http://127.0.0.1:18081",
                "CONFIRM save_task_report task=17",
            ))
        self.assertTrue(result["verified"])
        self.assertEqual(result["report_path"], "tasks/17/reports/cowork-report.md")
        self.assertEqual(result["node_id"], 91)
        self.assertTrue(repeated["verified"])
        self.assertTrue(repeated["idempotent_reuse"])
        self.assertEqual(repeated["node_id"], 91)
        self.assertEqual(client.fact_count, 1)
        self.assertEqual(client.write_count, first_write_count)

    def test_evidence_writer_creates_and_verifies_file_graph_fact_and_activity(self):
        class Client(FakeArtexClient):
            def __init__(self):
                super().__init__()
                self.file = ""

            def write_workspace_file(self, path, content):
                self.path, self.file = path, content
                return {"ok": True}

            def read_workspace_file(self, path):
                return {"content": self.file}

            def read_task_workspace_file(self, task_id, path):
                return self.read_workspace_file(path)

            def record_task_fact(self, task_id, summary, detail, evidence, confidence, target, confirmation):
                self.fact = {
                    "summary": summary, "detail": detail, "evidence": evidence,
                    "confidence": confidence, "node_id": 81,
                }
                return {"ok": True, "node_id": "81", "activity_updated": True}

            def get_task_surface(self, task_id, surface, **kwargs):
                if surface == "records":
                    fact = getattr(self, "fact", None)
                    return {"facts": ([{"id": "81", "type": "fact", "payload": {
                        key: fact[key] for key in ("summary", "detail", "evidence", "confidence")
                    }}] if fact else [])}
                return {"items": [{"worker": "cowork", "tool": "record_fact", "tool_use_id": "cowork-fact-81"}]}

            def clear_token(self):
                pass

        client = Client()
        with patch("artex_agent.desktop_diagnostic_writer._authenticated_client", return_value=client):
            result = json.loads(artex_record_diagnostic_evidence(
                17, "observation", "Root response", "Root returned the application shell",
                "GET / returned 200", "http://127.0.0.1:18081", CONFIRMATION,
            ))
        self.assertTrue(result["verified"])
        self.assertTrue(result["workspace_file_verified"])
        self.assertTrue(result["graph_fact_verified"])
        self.assertTrue(result["activity_verified"])
        self.assertTrue(result["dashboard_record_verified"])
        self.assertEqual(result["node_id"], 81)
        self.assertIn("cowork-diagnostic-", result["path"])

    def test_evidence_writer_reports_partial_persistence_when_graph_activity_is_missing(self):
        class Client(FakeArtexClient):
            def write_workspace_file(self, path, content):
                self.file = content
                return {"ok": True}

            def read_workspace_file(self, path):
                return {"content": self.file}

            def read_task_workspace_file(self, task_id, path):
                return self.read_workspace_file(path)

            def record_task_fact(self, *args):
                self.fact = {
                    "summary": args[1], "detail": args[2], "evidence": args[3],
                    "confidence": args[4],
                }
                return {"ok": True, "node_id": "81", "activity_updated": False}

            def get_task_surface(self, task_id, surface, **kwargs):
                if surface == "records":
                    return {"facts": [{"id": "81", "type": "fact", "payload": {
                        key: self.fact[key] for key in ("summary", "detail", "evidence", "confidence")
                    }}]}
                return {"items": []}

            def clear_token(self):
                pass

        with patch("artex_agent.desktop_diagnostic_writer._authenticated_client", return_value=Client()):
            result = json.loads(artex_record_diagnostic_evidence(
                17, "observation", "Root response", "Root returned shell", "GET / 200",
                "http://127.0.0.1:18081", CONFIRMATION,
            ))
        self.assertFalse(result["ok"])
        self.assertTrue(result["partial_write"])
        self.assertTrue(result["workspace_file_verified"])
        self.assertFalse(result["graph_fact_verified"])

    def test_evidence_checkpoint_retry_reuses_file_fact_and_activity(self):
        class Client(FakeArtexClient):
            def __init__(self):
                super().__init__()
                self.files = {}
                self.fact = None
                self.fact_writes = 0

            def get_task_surface(self, task_id, surface, **kwargs):
                if surface == "records":
                    facts = [] if self.fact is None else [{"id": "81", "type": "fact", "payload": self.fact}]
                    return {"files": [{"path": path} for path in self.files], "facts": facts}
                return {"items": [{"worker": "cowork", "tool": "record_fact", "tool_use_id": "cowork-fact-81"}]}

            def write_workspace_file(self, path, content):
                self.files[path] = content
                return {"ok": True}

            def read_task_workspace_file(self, task_id, path):
                return {"content": self.files[path]}

            def record_task_fact(self, task_id, summary, detail, evidence, confidence, target, confirmation):
                self.fact_writes += 1
                self.fact = {"summary": summary, "detail": detail, "evidence": evidence, "confidence": confidence}
                return {"ok": True, "node_id": "81", "activity_updated": True}

            def clear_token(self):
                pass

        client = Client()
        args = (
            17, "observation", "Checkpoint A", "Batch A completed", "GET / returned 200",
            "http://127.0.0.1:18081", CONFIRMATION,
        )
        with patch("artex_agent.desktop_diagnostic_writer._authenticated_client", return_value=client):
            first = json.loads(artex_record_diagnostic_evidence(*args, checkpoint_id="task17-batch-a"))
            second = json.loads(artex_record_diagnostic_evidence(*args, checkpoint_id="task17-batch-a"))
            changed_args = (*args[:3], "Changed batch content", *args[4:])
            changed = json.loads(artex_record_diagnostic_evidence(*changed_args, checkpoint_id="task17-batch-a"))
        self.assertTrue(first["verified"])
        self.assertFalse(first["idempotent_reuse"])
        self.assertTrue(second["verified"])
        self.assertTrue(second["idempotent_reuse"])
        self.assertEqual(first["path"], second["path"])
        self.assertEqual(client.fact_writes, 1)
        self.assertTrue(changed["partial_write"])
        self.assertEqual(client.fact_writes, 1)

    def test_evidence_checkpoint_rejects_invalid_identifier_before_connecting(self):
        with patch("artex_agent.desktop_diagnostic_writer._authenticated_client") as client_factory:
            with self.assertRaisesRegex(ValueError, "checkpoint_id"):
                artex_record_diagnostic_evidence(
                    17, "observation", "A", "B", "C", "http://127.0.0.1:18081", CONFIRMATION,
                    checkpoint_id="../outside",
                )
        client_factory.assert_not_called()

    def test_pause_task_requires_exact_confirmation_and_verifies_paused_state(self):
        client = FakeArtexClient(task={"id": 17, "paused": False})
        client.clear_token = lambda: None
        calls = []
        def pause(task_id, confirmation):
            calls.append((task_id, confirmation))
            client.task["paused"] = True
            return {"ok": True, "activity_updated": True}
        client.pause_task = pause
        client.get_task_surface = lambda task_id, surface, **kwargs: {
            "items": [{"worker": "cowork", "tool": "pause_task", "tool_use_id": "cowork-pause-17"}]
        }
        with self.assertRaisesRegex(ValueError, "CONFIRM pause_task task=17"):
            artex_pause_task(17, "wrong")
        with patch("artex_agent.desktop_diagnostic_writer._authenticated_client", return_value=client):
            result = json.loads(artex_pause_task(17, "CONFIRM pause_task task=17"))
        self.assertTrue(result["verified"])
        self.assertFalse(result["already_paused"])
        self.assertFalse(result["cowork_session_paused"])
        self.assertTrue(result["activity_verified"])
        self.assertEqual(calls, [(17, "CONFIRM pause_task task=17")])

    def test_prove_goal_requires_exact_confirmation_and_verifies_native_goal_state(self):
        client = FakeArtexClient(goals=[{"id": 91, "text": "확정된 취약점 확인", "state": "met"}])
        client.clear_token = lambda: None
        calls = []
        client.prove_task_goal = lambda *args: calls.append(args) or {"ok": True, "goal_id": 91, "evidence_id": 81, "task_completed": True, "activity_updated": True}
        client.get_task_surface = lambda task_id, surface, **kwargs: (
            {"items": [{"worker": "cowork", "tool": "prove_goal", "tool_use_id": "cowork-prove-goal-91-81"}]}
            if surface == "session_history"
            else {}
        )
        target = "http://127.0.0.1:18081"
        confirmation = "CONFIRM prove_goal task=17 goal=91 evidence=81"
        with self.assertRaisesRegex(ValueError, "CONFIRM prove_goal task=17 goal=91 evidence=81"):
            artex_prove_goal(17, 91, 81, target, "Evidence confirms this goal", "wrong")
        with patch("artex_agent.desktop_diagnostic_writer._authenticated_client", return_value=client):
            result = json.loads(artex_prove_goal(17, 91, 81, target, "Evidence confirms this goal", confirmation))
        self.assertTrue(result["verified"])
        self.assertTrue(result["task_completed"])
        self.assertEqual(result["state"], "met")
        self.assertTrue(result["activity_verified"])
        self.assertEqual(calls[0][-3:], (target, "Evidence confirms this goal", confirmation))

    def test_cowork_intent_completion_requires_confirmation_and_native_session_record(self):
        client = FakeArtexClient()
        client.clear_token = lambda: None
        client.complete_cowork_intent = lambda *args: {"ok": True, "intent_id": "77", "state": "done"}
        client.get_activity_detail = lambda task_id, seq: {"detail": "Evidence summary"} if (task_id, seq) == (17, 148) else {"detail": ""}
        client.get_task_surface = lambda task_id, surface, **kwargs: (
            {"items": [{"id": "77", "state": "done"}]}
            if surface == "intents"
            else {"items": [{"worker": "cowork", "tool": "complete_intent", "tool_use_id": "cowork-intent-77"}]}
            if surface == "session_history" and kwargs.get("session") == "cowork"
            else {"items": [{"seq": 148, "intent_id": "77", "tool": "complete_intent", "summary": "Completed bounded review"}]}
        )
        confirmation = "CONFIRM complete_cowork_intent task=17 intent=77 state=done"
        with self.assertRaisesRegex(ValueError, "CONFIRM complete_cowork_intent"):
            artex_complete_cowork_intent(17, 77, "done", "Completed bounded review", "Evidence summary", "wrong")
        with patch("artex_agent.desktop_diagnostic_writer._authenticated_client", return_value=client):
            result = json.loads(artex_complete_cowork_intent(17, 77, "done", "Completed bounded review", "Evidence summary", confirmation))
        self.assertTrue(result["verified"])
        self.assertTrue(result["activity_verified"])
        self.assertEqual(result["session_key"], "intent:77")
        self.assertEqual(client.get_activity_detail(17, 148), {"detail": "Evidence summary"})
        with self.assertRaisesRegex(ValueError, "evidence"):
            artex_complete_cowork_intent(17, 77, "done", "Completed bounded review", "", confirmation)

    def test_cowork_intent_completion_reports_partial_when_native_state_differs(self):
        client = FakeArtexClient()
        client.clear_token = lambda: None
        client.complete_cowork_intent = lambda *args: {"ok": True, "intent_id": "77", "state": "done"}
        client.get_task_surface = lambda task_id, surface, **kwargs: {"items": [{"id": "77", "state": "open"}]}
        confirmation = "CONFIRM complete_cowork_intent task=17 intent=77 state=done"
        with patch("artex_agent.desktop_diagnostic_writer._authenticated_client", return_value=client):
            result = json.loads(artex_complete_cowork_intent(17, 77, "done", "Completed bounded review", "Evidence summary", confirmation))
        self.assertTrue(result["partial_write"])
        self.assertEqual(result["intent_id"], 77)

    def test_intent_writer_requires_confirmation_and_verifies_graph_ids(self):
        client = FakeArtexClient()
        client.clear_token = lambda: None
        client.add_cowork_intents = lambda *args: {"ok": True, "intent_ids": [77], "activity_updated": True}
        client.get_task_surface = lambda *args, **kwargs: {
            "items": [{"worker": "cowork", "tool": "add_intent", "tool_use_id": "cowork-intents-17-77"}]
            if kwargs.get("session") == "cowork"
            else None,
            "nodes": [{"id": 77, "type": "intent", "payload": '{"summary":"Inspect authorized response"}', "priority": 7}],
            "edges": [],
        }
        payload = json.dumps([{"summary": "Inspect authorized response", "priority": 7, "parent_ids": []}])
        with self.assertRaisesRegex(ValueError, "CONFIRM add_cowork_intents task=17"):
            artex_add_task_intents(17, payload, "http://127.0.0.1:18081", "wrong")
        with patch("artex_agent.desktop_diagnostic_writer._authenticated_client", return_value=client):
            result = json.loads(artex_add_task_intents(17, payload, "http://127.0.0.1:18081", "CONFIRM add_cowork_intents task=17"))
        self.assertTrue(result["verified"])
        self.assertTrue(result["activity_verified"])
        self.assertEqual(result["intent_ids"], [77])
        client.get_task_surface = lambda *args, **kwargs: {"nodes": []}
        with patch("artex_agent.desktop_diagnostic_writer._authenticated_client", return_value=client):
            partial = json.loads(artex_add_task_intents(17, payload, "http://127.0.0.1:18081", "CONFIRM add_cowork_intents task=17"))
        self.assertTrue(partial["partial_write"])
        self.assertEqual(partial["intent_ids"], [77])

    def test_intent_writer_accepts_native_graph_ids_encoded_as_strings(self):
        client = FakeArtexClient()
        client.clear_token = lambda: None
        client.add_cowork_intents = lambda *args: {"ok": True, "intent_ids": [77], "activity_updated": True}
        client.get_task_surface = lambda task_id, surface, **kwargs: (
            {"items": [{"worker": "cowork", "tool": "add_intent", "tool_use_id": "cowork-intents-17-77"}]}
            if surface == "session_history"
            else {
                "nodes": [{"id": "77", "type": "intent", "payload": {"summary": "Verify acceptance UI readback"}, "priority": 5}],
                "edges": [],
            }
        )
        payload = json.dumps([{"summary": "Verify acceptance UI readback", "priority": 5, "parent_ids": []}])
        with patch("artex_agent.desktop_diagnostic_writer._authenticated_client", return_value=client):
            result = json.loads(artex_add_task_intents(
                17, payload, "http://127.0.0.1:18081", "CONFIRM add_cowork_intents task=17",
            ))
        self.assertTrue(result["verified"])
        self.assertFalse(result["partial_write"])
        self.assertTrue(result["activity_verified"])

    def test_intent_writer_rejects_duplicate_summaries_in_one_batch(self):
        payload = json.dumps([
            {"summary": "Same work item", "priority": 4},
            {"summary": "Same work item", "priority": 8},
        ])
        with patch("artex_agent.desktop_diagnostic_writer._authenticated_client") as client_factory:
            with self.assertRaisesRegex(ValueError, "duplicates a summary"):
                artex_add_task_intents(17, payload, "http://127.0.0.1:18081", "CONFIRM add_cowork_intents task=17")
        client_factory.assert_not_called()

    def test_intercept_decision_requires_exact_user_confirmation_and_task_pending(self):
        client = FakeArtexClient()
        client.clear_token = lambda: None
        state = {"id": 8, "task_id": "17", "status": "pending"}
        client.get_task_surface = lambda *args, **kwargs: {"items": [state.copy()]}
        def decide(*args):
            state["status"] = "denied"
            return {"ok": True, "pending_id": 8, "decision": "denied"}
        client.decide_cowork_intercept = decide
        confirmation = "CONFIRM decide_intercept task=17 pending=8 decision=denied"
        with self.assertRaisesRegex(ValueError, "CONFIRM decide_intercept task=17"):
            artex_decide_intercept(17, 8, "denied", "wrong")
        with patch("artex_agent.desktop_diagnostic_writer._authenticated_client", return_value=client):
            result = json.loads(artex_decide_intercept(17, 8, "denied", confirmation))
        self.assertTrue(result["verified"])
        self.assertEqual(result["pending_id"], 8)
        client.get_task_surface = lambda *args, **kwargs: {"items": [{"id": 8, "task_id": "18", "status": "pending"}]}
        with patch("artex_agent.desktop_diagnostic_writer._authenticated_client", return_value=client), self.assertRaisesRegex(ValueError, "해당 Task"):
            artex_decide_intercept(17, 8, "denied", confirmation)

    def test_cowork_retest_requires_confirmation_and_verifies_native_history(self):
        client = FakeArtexClient()
        client.clear_token = lambda: None
        client.record_cowork_finding_retest = lambda *args: {"ok": True, "retest": {"id": 12, "status": "completed", "verdict": "reproduced"}, "activity_updated": True}
        client.get_task_surface = lambda *args, **kwargs: {"retests": [{
            "id": 12, "finding_id": 9, "status": "completed", "verdict": "reproduced",
            "summary": "still present", "evidence": "observed response",
        }]}
        with self.assertRaisesRegex(ValueError, "CONFIRM record_cowork_retest task=17 finding=9"):
            artex_record_finding_retest_result(17, 9, "http://127.0.0.1:18081", "reproduced", "still present", "observed response", "wrong")
        with patch("artex_agent.desktop_diagnostic_writer._authenticated_client", return_value=client):
            result = json.loads(artex_record_finding_retest_result(17, 9, "http://127.0.0.1:18081", "reproduced", "still present", "observed response", "CONFIRM record_cowork_retest task=17 finding=9"))
        self.assertTrue(result["verified"])
        self.assertEqual(result["retest_id"], 12)
        self.assertEqual(result["surface"], "finding_retests")

    def test_cowork_retest_retry_reuses_native_record_and_activity(self):
        client = FakeArtexClient()
        client.clear_token = lambda: None
        client.record_cowork_finding_retest = lambda *args: {
            "ok": True,
            "retest": {"id": 12, "status": "completed", "verdict": "reproduced"},
            "activity_updated": False,
            "idempotent_reuse": True,
        }
        client.get_task_surface = lambda task_id, surface, **kwargs: (
            {"retests": [{
                "id": 12, "finding_id": 9, "status": "completed", "verdict": "reproduced",
                "summary": "still present", "evidence": "observed response",
            }]}
            if surface == "retests"
            else {"items": [{
                "worker": "cowork", "tool": "record_finding_retest_result", "tool_use_id": "cowork-retest-12",
            }]}
        )
        confirmation = "CONFIRM record_cowork_retest task=17 finding=9"
        with patch("artex_agent.desktop_diagnostic_writer._authenticated_client", return_value=client):
            result = json.loads(artex_record_finding_retest_result(
                17, 9, "http://127.0.0.1:18081", "reproduced", "still present", "observed response", confirmation,
            ))
        self.assertTrue(result["verified"])
        self.assertTrue(result["idempotent_reuse"])
        self.assertFalse(result["activity_updated"])
        self.assertTrue(result["activity_verified"])
        self.assertFalse(result["partial_write"])

    def test_cowork_retest_reports_partial_when_readback_evidence_differs(self):
        client = FakeArtexClient()
        client.clear_token = lambda: None
        client.record_cowork_finding_retest = lambda *args: {"ok": True, "retest": {"id": 12, "status": "completed", "verdict": "reproduced"}}
        client.get_task_surface = lambda *args, **kwargs: {"retests": [{
            "id": 12, "finding_id": 9, "status": "completed", "verdict": "reproduced",
            "summary": "still present", "evidence": "different evidence",
        }]}
        confirmation = "CONFIRM record_cowork_retest task=17 finding=9"
        with patch("artex_agent.desktop_diagnostic_writer._authenticated_client", return_value=client):
            result = json.loads(artex_record_finding_retest_result(17, 9, "http://127.0.0.1:18081", "reproduced", "still present", "observed response", confirmation))
        self.assertTrue(result["partial_write"])
        self.assertEqual(result["retest_id"], 12)

    def test_finding_report_writer_requires_exact_confirmation(self):
        with self.assertRaisesRegex(ValueError, "CONFIRM update_finding_report task=17"):
            artex_update_finding_report(17, 42, "# Report", "wrong")

    def test_finding_report_writer_rejects_credentials_before_connecting(self):
        with self.assertRaisesRegex(ValueError, "자격 증명"):
            artex_update_finding_report(17, 42, "Authorization: Bearer abcdefghijklmnop", "CONFIRM update_finding_report task=17")

    def test_accepts_expected_task_and_human_allow(self):
        client = FakeArtexClient()
        _verify_context(client, 17)
        self.assertEqual(client.scope_task_ids, [17])
        self.assertEqual(client.constraint_task_ids, [17])

    def test_accepts_task_with_security_checklist_goals_and_host_port_allow(self):
        client = FakeArtexClient(
            goals=[
                {"text": "어떤 기법 및 우회 기법 등을 동원해서 xss, csrf 공격 확인"},
                {"text": "백업 및 임시파일 관리 미흡 확인"},
            ]
        )
        _verify_context(client, 3)
        self.assertEqual(client.scope_task_ids, [3])
        self.assertEqual(client.constraint_task_ids, [3])

    def test_accepts_other_explicitly_scoped_and_human_allowed_target(self):
        client = FakeArtexClient(
            scope=[{"kind": "domain", "value": "app.example.test"}],
            constraints=[{"kind": "allow", "source": "human", "text": "https://app.example.test:8443 허용"}],
        )
        _verify_context(client, 9, "https://app.example.test:8443")

    def test_rejects_target_outside_scope_even_when_allow_mentions_it(self):
        client = FakeArtexClient(
            scope=[{"kind": "domain", "value": "other.example.test"}],
            constraints=[{"kind": "allow", "source": "human", "text": "https://app.example.test:8443 허용"}],
        )
        with self.assertRaisesRegex(RuntimeError, "범위에 포함되지"):
            _verify_context(client, 9, "https://app.example.test:8443")

    def test_matching_deny_overrides_allow(self):
        client = FakeArtexClient(constraints=[
            {"kind": "allow", "source": "human", "text": "127.0.0.1:18081 허용"},
            {"kind": "deny", "source": "human", "text": "127.0.0.1:18081 금지"},
        ])
        with self.assertRaisesRegex(RuntimeError, "deny 제약"):
            _verify_context(client, 17)

    def test_rejects_target_with_path_or_userinfo(self):
        for target in ("http://user@127.0.0.1:18081", "http://127.0.0.1:18081/path"):
            with self.subTest(target=target), self.assertRaisesRegex(ValueError, "origin"):
                _verify_context(FakeArtexClient(), 17, target)

    def test_task_asset_metadata_is_limited_to_approved_origin_and_safe_types(self):
        assets = _validate_task_assets(json.dumps([
            {"type": "service", "url": "http://127.0.0.1:18081", "technologies": ["Angular"], "status_code": 200},
            {"type": "endpoint", "url": "http://127.0.0.1:18081/api/products/search", "method": "GET"},
            {"type": "ip", "ip": "127.0.0.1"},
        ]), "http://127.0.0.1:18081")
        self.assertEqual([asset["type"] for asset in assets], ["service", "endpoint", "ip"])

    def test_task_asset_metadata_rejects_out_of_origin_urls_secrets_and_write_methods(self):
        cases = [
            [{"type": "endpoint", "url": "https://outside.example/path", "method": "GET"}],
            [{"type": "endpoint", "url": "http://127.0.0.1:18081/path?token=secret", "method": "GET"}],
            [{"type": "endpoint", "url": "http://127.0.0.1:18081/path", "method": "POST"}],
            [{"type": "service", "url": "http://127.0.0.1:18081", "authorization": "Bearer abc"}],
        ]
        for assets in cases:
            with self.subTest(assets=assets), self.assertRaises(ValueError):
                _validate_task_assets(json.dumps(assets), "http://127.0.0.1:18081")

    def test_task_asset_writer_registers_and_verifies_native_asset_ids(self):
        class FakeWriter(FakeArtexClient):
            def __init__(self):
                super().__init__()
                self.inserted = None
                self.cleared = False

            def register_cowork_assets(self, task_id, target, assets, confirmation):
                self.inserted = (task_id, target, assets, confirmation)
                return {"results": [{"index": i, "id": 101 + i, "type": asset["type"]} for i, asset in enumerate(assets)], "errors": [], "activity_updated": True}

            def get_task_surface(self, task_id, surface, **kwargs):
                if surface == "session_history":
                    return {"items": [{"worker": "cowork", "tool": "insert_assets", "tool_use_id": "cowork-assets-17-101"}]}
                self.asserted_surface = (task_id, surface)
                return {"assets": [
                    {"id": 101, "type": "service", "url": "http://127.0.0.1:18081", "task_ids": [17]},
                    {"id": 102, "type": "endpoint", "url": "http://127.0.0.1:18081/api/items", "method": "GET", "task_ids": [17]},
                ]}

            def clear_token(self):
                self.cleared = True

        fake = FakeWriter()
        payload = json.dumps([
            {"type": "service", "url": "http://127.0.0.1:18081"},
            {"type": "endpoint", "url": "http://127.0.0.1:18081/api/items", "method": "GET"},
        ])
        with patch("artex_agent.desktop_diagnostic_writer._authenticated_client", return_value=fake):
            result = json.loads(artex_register_task_assets(
                17, "http://127.0.0.1:18081", payload, "CONFIRM insert_assets task=17"
            ))
        self.assertTrue(result["verified"])
        self.assertTrue(result["activity_verified"])
        self.assertFalse(result["target_contacted"])
        self.assertEqual(result["asset_ids"], [101, 102])
        self.assertEqual(fake.inserted[0], 17)
        self.assertEqual(fake.inserted[1], "http://127.0.0.1:18081")
        self.assertEqual(fake.inserted[3], "CONFIRM insert_assets task=17")
        self.assertEqual(len(fake.inserted[2]), 2)
        self.assertEqual(fake.asserted_surface, (17, "assets"))
        self.assertTrue(fake.cleared)

    def test_task_asset_writer_reports_partial_when_readback_has_mismatched_metadata(self):
        class MismatchedAssetClient(FakeArtexClient):
            def register_cowork_assets(self, task_id, target, assets, confirmation):
                return {"results": [{"index": 0, "id": 101, "type": "service"}], "errors": []}

            def get_task_surface(self, task_id, surface, **kwargs):
                return {"assets": [{
                    "id": 101, "type": "service", "url": "http://127.0.0.1:18081",
                    "status_code": 500, "task_ids": [task_id],
                }]}

        payload = json.dumps([{"type": "service", "url": "http://127.0.0.1:18081", "status_code": 200}])
        with patch("artex_agent.desktop_diagnostic_writer._authenticated_client", return_value=MismatchedAssetClient()):
            result = json.loads(artex_register_task_assets(17, "http://127.0.0.1:18081", payload, "CONFIRM insert_assets task=17"))
        self.assertTrue(result["partial_write"])
        self.assertEqual(result["asset_ids"], [101])

    def test_task_asset_writer_reports_partial_when_readback_lacks_task_provenance(self):
        class WrongTaskAssetClient(FakeArtexClient):
            def register_cowork_assets(self, task_id, target, assets, confirmation):
                return {"results": [{"index": 0, "id": 101, "type": "ip"}], "errors": []}

            def get_task_surface(self, task_id, surface, **kwargs):
                return {"assets": [{"id": 101, "type": "ip", "ip": "127.0.0.1", "task_ids": [99]}]}

        payload = json.dumps([{"type": "ip", "ip": "127.0.0.1"}])
        with patch("artex_agent.desktop_diagnostic_writer._authenticated_client", return_value=WrongTaskAssetClient()):
            result = json.loads(artex_register_task_assets(17, "http://127.0.0.1:18081", payload, "CONFIRM insert_assets task=17"))
        self.assertTrue(result["partial_write"])
        self.assertEqual(result["asset_ids"], [101])

    def test_task_asset_writer_requires_confirmation_before_connecting(self):
        with patch("artex_agent.desktop_diagnostic_writer._authenticated_client") as connect:
            with self.assertRaisesRegex(ValueError, "CONFIRM insert_assets task=17"):
                artex_register_task_assets(
                    17, "http://127.0.0.1:18081", "[]", "wrong"
                )
        connect.assert_not_called()

    def test_rejects_missing_approval(self):
        with self.assertRaisesRegex(RuntimeError, "사람 승인"):
            _verify_context(FakeArtexClient(constraints=[]), 17)

    def test_rejects_wrong_task(self):
        with self.assertRaisesRegex(RuntimeError, "찾을 수 없습니다"):
            _verify_context(FakeArtexClient(task={}), 17)

    def test_rejects_read_only_smoke_goal(self):
        class ReadOnlyGoalClient(FakeArtexClient):
            def list_goals(self, task_id):
                return [{"text": "공개 페이지를 읽기 전용으로 확인"}]

        with self.assertRaisesRegex(RuntimeError, "읽기 전용 ARTEx 작업"):
            _verify_context(ReadOnlyGoalClient(), 17)

    def test_rejects_goal_without_diagnostic_intent(self):
        client = FakeArtexClient(goals=[{"text": "일반 작업"}])
        with self.assertRaisesRegex(RuntimeError, "진단 목표가 있는 작업"):
            _verify_context(client, 17)

    def test_goal_less_task_still_requires_structured_scope_and_human_allow(self):
        client = FakeArtexClient(goals=[])
        _verify_context(client, 17, "http://127.0.0.1:18081")
        self.assertEqual(client.scope_task_ids, [17])
        self.assertEqual(client.constraint_task_ids, [17])

    def test_goal_less_task_still_rejects_missing_scope_or_allow(self):
        cases = [
            FakeArtexClient(scope=[], goals=[]),
            FakeArtexClient(constraints=[], goals=[]),
        ]
        for client in cases:
            with self.subTest(client=client), self.assertRaises(RuntimeError):
                _verify_context(client, 17, "http://127.0.0.1:18081")

    def test_unrecognized_goal_response_shape_fails_closed(self):
        class MalformedGoalsClient(FakeArtexClient):
            def list_goals(self, task_id):
                return {"unexpected": []}

        with self.assertRaisesRegex(RuntimeError, "목표 응답 형식"):
            _verify_context(MalformedGoalsClient(), 17, "http://127.0.0.1:18081")

    def test_rejects_credential_like_content(self):
        with self.assertRaisesRegex(ValueError, "자격 증명"):
            _clean_field("evidence", "Authorization: Bearer abcdefghijklmnop")

    def test_confirmation_is_documented_and_specific(self):
        self.assertEqual(CONFIRMATION, "WRITE_DIAGNOSTIC_EVIDENCE_TO_ARTEX")

    def test_graph_fact_requires_task_specific_confirmation(self):
        with self.assertRaisesRegex(ValueError, "CONFIRM record_fact task=3"):
            artex_record_task_fact(3, "s", "d", "e", "observed", "http://127.0.0.1:18081", "wrong")

    def test_fact_and_finding_writers_forward_target_after_preflight(self):
        client = FakeArtexClient()
        client.clear_token = lambda: None
        calls = []
        def record_fact(*args):
            calls.append(("fact", args))
            client.fact = {
                "summary": args[1], "detail": args[2], "evidence": args[3], "confidence": args[4],
            }
            return {"ok": True, "node_id": "81", "activity_updated": True}
        client.record_task_fact = record_fact
        client.report_confirmed_finding = lambda *args: calls.append(("finding", args)) or {"ok": True, "finding_id": "82", "finding_node_id": "83"}
        client.get_task_surface = lambda task_id, surface, **kwargs: (
            {"facts": [{
                "id": "81", "type": "fact", "payload": {
                    "summary": "Observed", "detail": "Detail", "evidence": "Evidence", "confidence": "observed",
                },
            }]}
            if surface == "records"
            else {"items": [{"worker": "cowork", "tool": "record_fact", "tool_use_id": "cowork-fact-81"}]}
        )
        client.get_finding = lambda finding_id, context_task_id=None: {
            "finding_id": str(finding_id), "task_id": str(context_task_id), "vulnclass": "xss",
            "name": "Confirmed XSS", "severity": "high", "summary": "Summary", "evidence": "Evidence",
        }
        target = "http://127.0.0.1:18081"
        with patch("artex_agent.desktop_diagnostic_writer._authenticated_client", return_value=client):
            fact = json.loads(artex_record_task_fact(17, "Observed", "Detail", "Evidence", "observed", target, "CONFIRM record_fact task=17"))
            finding = json.loads(artex_report_confirmed_finding(17, "xss", "Confirmed XSS", "high", "Summary", "Evidence", target, "CONFIRM report_finding task=17"))
        self.assertTrue(fact["verified"])
        self.assertTrue(fact["dashboard_record_verified"])
        self.assertTrue(finding["verified"])
        self.assertEqual(calls[0][1][-2], target)
        self.assertEqual(calls[1][1][-2], target)

    def test_fact_write_reports_partial_when_native_records_readback_misses_node(self):
        client = FakeArtexClient()
        client.clear_token = lambda: None
        client.record_task_fact = lambda *args: {"ok": True, "node_id": "81"}
        client.get_task_surface = lambda *args, **kwargs: {"facts": []}
        with patch("artex_agent.desktop_diagnostic_writer._authenticated_client", return_value=client):
            result = json.loads(artex_record_task_fact(17, "Observed", "Detail", "Evidence", "observed", "http://127.0.0.1:18081", "CONFIRM record_fact task=17"))
        self.assertTrue(result["partial_write"])
        self.assertEqual(result["node_id"], 81)
        self.assertFalse(result["native_record_verified"])

    def test_fact_write_reports_partial_when_dashboard_latest_record_is_stale(self):
        client = FakeArtexClient()
        client.clear_token = lambda: None
        fact = {"summary": "Observed", "detail": "Detail", "evidence": "Evidence", "confidence": "observed"}
        client.record_task_fact = lambda *args: {"ok": True, "node_id": "81", "activity_updated": True}
        client.get_task_surface = lambda task_id, surface, **kwargs: (
            {"facts": [{"id": "81", "type": "fact", "payload": fact.copy()}]}
            if surface == "records"
            else {"items": [{"worker": "cowork", "tool": "record_fact", "tool_use_id": "cowork-fact-81"}]}
        )
        client.list_tasks = lambda: {"tasks": [{
            "id": "17", "latest_record_summary": "Older record", "latest_record_unix": 1,
        }]}
        with patch("artex_agent.desktop_diagnostic_writer._authenticated_client", return_value=client):
            result = json.loads(artex_record_task_fact(
                17, "Observed", "Detail", "Evidence", "observed",
                "http://127.0.0.1:18081", "CONFIRM record_fact task=17",
            ))
        self.assertTrue(result["partial_write"])
        self.assertTrue(result["native_record_verified"])
        self.assertTrue(result["activity_verified"])
        self.assertFalse(result["dashboard_record_verified"])

    def test_fact_writer_rejects_readback_with_different_content(self):
        client = FakeArtexClient()
        client.clear_token = lambda: None
        client.record_task_fact = lambda *args: {"ok": True, "node_id": "81"}
        client.get_task_surface = lambda *args, **kwargs: {"facts": [{
            "id": "81", "type": "fact", "payload": {
                "summary": "Other", "detail": "Detail", "evidence": "Evidence", "confidence": "observed",
            },
        }]}
        with patch("artex_agent.desktop_diagnostic_writer._authenticated_client", return_value=client):
            result = json.loads(artex_record_task_fact(17, "Observed", "Detail", "Evidence", "observed", "http://127.0.0.1:18081", "CONFIRM record_fact task=17"))
        self.assertTrue(result["partial_write"])
        self.assertEqual(result["node_id"], 81)

    def test_finding_write_reports_partial_when_native_detail_readback_misses_task(self):
        client = FakeArtexClient()
        client.clear_token = lambda: None
        client.report_confirmed_finding = lambda *args: {"ok": True, "finding_id": "82", "finding_node_id": "83"}
        client.get_finding = lambda *args, **kwargs: {"finding_id": "82", "task_id": "18"}
        with patch("artex_agent.desktop_diagnostic_writer._authenticated_client", return_value=client):
            result = json.loads(artex_report_confirmed_finding(17, "xss", "Confirmed XSS", "high", "Summary", "Evidence", "http://127.0.0.1:18081", "CONFIRM report_finding task=17"))
        self.assertTrue(result["partial_write"])
        self.assertEqual(result["finding_id"], "82")
        self.assertEqual(result["formal_finding_created"], "unknown")

    def test_finding_retry_reuses_existing_record_and_activity(self):
        client = FakeArtexClient()
        client.clear_token = lambda: None
        client.report_confirmed_finding = lambda *args: {
            "ok": True, "finding_id": "82", "finding_node_id": "83",
            "idempotent_reuse": True, "activity_updated": False,
        }
        client.get_finding = lambda finding_id, context_task_id=None: {
            "finding_id": str(finding_id), "task_id": str(context_task_id),
            "vulnclass": "xss", "name": "Confirmed XSS", "severity": "high",
            "summary": "Summary", "evidence": "Evidence",
        }
        client.get_task_surface = lambda task_id, surface, **kwargs: {
            "items": [{"worker": "cowork", "tool": "report_finding", "tool_use_id": "cowork-finding-82"}]
        }
        with patch("artex_agent.desktop_diagnostic_writer._authenticated_client", return_value=client):
            result = json.loads(artex_report_confirmed_finding(
                17, "xss", "Confirmed XSS", "high", "Summary", "Evidence",
                "http://127.0.0.1:18081", "CONFIRM report_finding task=17",
            ))
        self.assertTrue(result["verified"])
        self.assertTrue(result["idempotent_reuse"])
        self.assertFalse(result["formal_finding_created"])
        self.assertTrue(result["activity_verified"])

    def test_finding_write_reports_partial_when_readback_content_differs(self):
        client = FakeArtexClient()
        client.clear_token = lambda: None
        client.report_confirmed_finding = lambda *args: {"ok": True, "finding_id": "82", "finding_node_id": "83"}
        client.get_finding = lambda *args, **kwargs: {
            "finding_id": "82", "task_id": "17", "vulnclass": "xss", "name": "Other finding",
            "severity": "high", "summary": "Summary", "evidence": "Evidence",
        }
        with patch("artex_agent.desktop_diagnostic_writer._authenticated_client", return_value=client):
            result = json.loads(artex_report_confirmed_finding(17, "xss", "Confirmed XSS", "high", "Summary", "Evidence", "http://127.0.0.1:18081", "CONFIRM report_finding task=17"))
        self.assertTrue(result["partial_write"])
        self.assertEqual(result["finding_id"], "82")

    def test_finding_report_returns_partial_when_native_detail_readback_differs(self):
        client = FakeArtexClient()
        client.clear_token = lambda: None
        client.update_finding_report = lambda *args: {"ok": True, "updated": True}
        client.get_cowork_finding_report = lambda *args, **kwargs: {"report": "# Different report"}
        with patch("artex_agent.desktop_diagnostic_writer._authenticated_client", return_value=client):
            result = json.loads(artex_update_finding_report(17, 42, "# Verified", "CONFIRM update_finding_report task=17"))
        self.assertTrue(result["partial_write"])
        self.assertEqual(result["finding_node_id"], 42)

    def test_finding_status_change_requires_task_membership_confirmation_and_readback(self):
        client = FakeArtexClient()
        client.clear_token = lambda: None
        client.status = "pending"
        def surface_read(task_id, surface, **kwargs):
            if surface == "findings":
                return {"findings": [{"finding_id": 82, "status": client.status}]}
            return {"items": [{"seq": 410, "worker": "cowork", "tool": "update_finding_status", "intent_id": "83"}]}
        client.get_task_surface = surface_read
        calls = []
        def update_status(task_id, finding_id, status, confirmation):
            calls.append((task_id, finding_id, status, confirmation))
            client.status = status
            return {"ok": True, "finding_id": finding_id, "finding_node_id": 83, "status": status, "from": "pending", "changed": True, "notified": True, "activity_updated": True, "activity_seq": 410}
        client.update_cowork_finding_status = update_status
        confirmation = "CONFIRM update_finding_status task=17 finding=82 status=confirmed"
        with self.assertRaisesRegex(ValueError, "CONFIRM update_finding_status task=17 finding=82 status=confirmed"):
            artex_update_finding_status(17, 82, "confirmed", "wrong")
        with patch("artex_agent.desktop_diagnostic_writer._authenticated_client", return_value=client):
            result = json.loads(artex_update_finding_status(17, 82, "confirmed", confirmation))
        self.assertTrue(result["verified"])
        self.assertEqual(result["status"], "confirmed")
        self.assertTrue(result["changed"])
        self.assertTrue(result["notified"])
        self.assertTrue(result["activity_verified"])
        self.assertEqual(calls, [(17, 82, "confirmed", confirmation)])

    def test_formal_finding_requires_task_specific_confirmation(self):
        with self.assertRaisesRegex(ValueError, "CONFIRM report_finding task=3"):
            artex_report_confirmed_finding(3, "xss", "name", "high", "summary", "evidence", "http://127.0.0.1:18081", "wrong")

    def test_cowork_traffic_binding_requires_exact_confirmation_and_task_owned_ids(self):
        refs = json.dumps([{"traffic_id": "cowork-t3-0123456789abcdef0123456789abcdef-1", "role": "proof"}])
        target = "http://127.0.0.1:18081"
        with self.assertRaisesRegex(ValueError, "CONFIRM bind_cowork_traffic task=3 finding=42"):
            artex_bind_cowork_traffic_to_finding(3, 42, target, refs, "wrong")
        foreign = json.dumps([{"traffic_id": "cowork-t4-0123456789abcdef0123456789abcdef-1"}])
        with self.assertRaisesRegex(ValueError, "이 Task에 속하지 않습니다"):
            artex_bind_cowork_traffic_to_finding(
                3, 42, target, foreign, "CONFIRM bind_cowork_traffic task=3 finding=42",
            )
        secret_note = json.dumps([{
            "traffic_id": "cowork-t3-0123456789abcdef0123456789abcdef-1",
            "note": "password=fixture-secret",
        }])
        with self.assertRaisesRegex(ValueError, "민감정보"):
            artex_bind_cowork_traffic_to_finding(
                3, 42, target, secret_note, "CONFIRM bind_cowork_traffic task=3 finding=42",
            )
        duplicates = json.dumps([
            {"traffic_id": "cowork-t3-0123456789abcdef0123456789abcdef-1"},
            {"traffic_id": "cowork-t3-0123456789abcdef0123456789abcdef-1"},
        ])
        with self.assertRaisesRegex(ValueError, "중복"):
            artex_bind_cowork_traffic_to_finding(
                3, 42, target, duplicates, "CONFIRM bind_cowork_traffic task=3 finding=42",
            )


if __name__ == "__main__":
    unittest.main()

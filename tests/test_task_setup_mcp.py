import json
from unittest import TestCase
from unittest.mock import Mock, patch

from artex_agent.artex_api import ArtexClient, task_intercept_rule_confirmation, task_setup_confirmation
from artex_agent.desktop_task_setup_mcp import (
    _verify_cowork_activity,
    artex_add_constraint,
    artex_add_goal,
    artex_add_task_scope,
    artex_manage_task_intercept_rule,
)
from artex_agent.desktop_mcp import artex_get_finding


class TaskSetupAPITests(TestCase):
    def test_cowork_activity_verification_paginates_with_a_bounded_cap(self):
        client = ArtexClient()
        client.get_task_surface = Mock(side_effect=[
            {"items": [{"tool": "older"}], "has_more": True, "earliest_cursor": 101},
            {"items": [{
                "worker": "cowork", "tool": "manage_task_intercept_rule",
                "tool_use_id": "cowork-rule-event-1",
            }], "has_more": False, "earliest_cursor": 1},
        ])
        self.assertTrue(_verify_cowork_activity(
            client, 3, "manage_task_intercept_rule", "cowork-rule-event-1",
        ))
        self.assertEqual(client.get_task_surface.call_count, 2)
        self.assertEqual(client.get_task_surface.call_args_list[0].kwargs["before"], 0)
        self.assertEqual(client.get_task_surface.call_args_list[1].kwargs["before"], 101)

    def test_cowork_traffic_capture_uses_authenticated_task_route(self):
        client = ArtexClient()
        payload = {
            "confirmation": "CONFIRM record_cowork_traffic task=3",
            "target": "http://127.0.0.1:18081",
            "capture_id": "cowork-run123-1",
        }
        with patch.object(client, "_request", return_value={"ok": True, "traffic_id": "cowork-run123-1"}) as request:
            result = client.record_cowork_traffic(3, payload)
        self.assertTrue(result["ok"])
        request.assert_called_once_with("POST", "/api/tasks/3/cowork/traffic", payload)

    def test_add_goal_uses_non_resuming_cowork_route_and_confirmation(self):
        client = ArtexClient()
        confirmation = "CONFIRM add_goal task=4"
        with patch.object(client, "_request", return_value={"goal": {"id": "11"}, "task_may_resume": False}) as request:
            result = client.add_goal(4, "Check access control", confirmation, "authorization")
        self.assertEqual(result["goal"]["id"], "11")
        request.assert_called_once_with("POST", "/api/tasks/4/cowork/goals", {
            "text": "Check access control", "vulnclass": "authorization", "confirmation": confirmation,
        })
        request.reset_mock()
        with self.assertRaises(ValueError):
            client.add_goal(4, "Check access control", "CONFIRM add_goal task=5")
        request.assert_not_called()

    def test_task_setup_update_and_delete_are_task_and_row_scoped(self):
        client = ArtexClient()
        confirmation = task_setup_confirmation(4, "update_goal", object_id=11, text="Updated goal", vulnclass="xss")
        with patch.object(client, "_request", return_value={"goal": {"id": "11"}}) as request:
            client.manage_task_goal(4, 11, "update", confirmation, text="Updated goal", vulnclass="xss")
        request.assert_called_once_with("POST", "/api/tasks/4/cowork/goals/11", {
            "operation": "update", "confirmation": confirmation,
            "text": "Updated goal", "vulnclass": "xss",
        })

        with patch.object(client, "_request") as request:
            with self.assertRaisesRegex(ValueError, "operation-specific confirmation"):
                client.manage_task_goal(4, 11, "update", confirmation, text="Changed after approval", vulnclass="xss")
        request.assert_not_called()

        confirmation = "CONFIRM delete_constraint task=4 constraint=12"
        with patch.object(client, "_request", return_value={"ok": True}) as request:
            client.manage_task_constraint(4, 12, "delete", confirmation)
        request.assert_called_once_with("POST", "/api/tasks/4/cowork/constraints/12", {
            "operation": "delete", "confirmation": confirmation,
        })

        confirmation = "CONFIRM delete_scope task=4 scope=13"
        with patch.object(client, "_request", return_value={"ok": True}) as request:
            client.delete_task_scope(4, 13, confirmation)
        request.assert_called_once_with("DELETE", "/api/tasks/4/cowork/scope/13", {
            "confirmation": confirmation,
        })

        with patch.object(client, "_request") as request:
            with self.assertRaisesRegex(ValueError, "operation-specific confirmation"):
                client.manage_task_goal(4, 11, "delete", "CONFIRM delete_goal task=4")
        request.assert_not_called()

    def test_task_intercept_rule_operations_are_task_scoped_and_confirmed(self):
        client = ArtexClient()
        payload = {
            "enabled": True, "action": "block", "kind": "exact_domain",
            "pattern": "example.test", "note": "approved block rule",
        }
        confirmation = task_intercept_rule_confirmation(4, "create", **payload)
        with patch.object(client, "_request", return_value={
            "result": {"id": 12}, "activity_updated": True,
            "activity_tool_use_id": "cowork-rule-event-1",
        }) as request:
            result = client.manage_task_intercept_rule(
                4, "create", confirmation, **payload
            )
        self.assertEqual(result["id"], 12)
        self.assertTrue(result["activity_updated"])
        self.assertEqual(result["activity_tool_use_id"], "cowork-rule-event-1")
        request.assert_called_once_with("POST", "/api/tasks/4/cowork/intercept-rules", {
            "operation": "create", "rule_id": 0, "confirmation": confirmation, **payload,
        })

        delete_confirmation = task_intercept_rule_confirmation(4, "delete", rule_id=12)
        with patch.object(client, "_request", return_value={"result": {"deleted": True}, "activity_updated": True}) as request:
            client.manage_task_intercept_rule(
                4, "delete", delete_confirmation, rule_id=12
            )
        request.assert_called_once_with("POST", "/api/tasks/4/cowork/intercept-rules", {
            "operation": "delete", "rule_id": 12, "confirmation": delete_confirmation,
            "enabled": True, "action": "block", "kind": "", "pattern": "", "note": "",
        })

        with self.assertRaises(ValueError):
            client.manage_task_intercept_rule(
                4, "delete", "CONFIRM delete_intercept_rule task=4", rule_id=12
            )

        create_confirmation = task_intercept_rule_confirmation(4, "create", **payload)
        with patch.object(client, "_request") as request:
            with self.assertRaisesRegex(ValueError, "payload confirmation"):
                client.manage_task_intercept_rule(
                    4, "create", create_confirmation, **{**payload, "pattern": "other.test"}
                )
        request.assert_not_called()

    def test_task_intercept_rule_rejects_unrecognized_matchers(self):
        client = ArtexClient()
        with self.assertRaises(ValueError):
            client.manage_task_intercept_rule(
                4, "create", task_intercept_rule_confirmation(
                    4, "create", action="block", kind="regex", pattern=".*"
                ),
                action="block", kind="regex", pattern=".*",
            )

    def test_intercept_rule_writer_verifies_native_task_readback(self):
        client = ArtexClient()
        activity_id = "cowork-intercept-rule-test"
        client.manage_task_intercept_rule = lambda *args, **kwargs: {
            "id": 12, "activity_updated": True, "activity_tool_use_id": activity_id,
        }
        def read_surface(_task_id, surface, **_kwargs):
            if surface == "intercept_rules":
                return {"rules": [{
                    "id": 12, "action": "block", "kind": "exact_domain",
                    "pattern": "example.test", "enabled": True,
                }]}
            return {"items": [{
                "worker": "cowork", "tool": "manage_task_intercept_rule",
                "tool_use_id": activity_id,
            }]}
        client.get_task_surface = read_surface
        client.clear_token = lambda: None
        with patch("artex_agent.desktop_task_setup_mcp._authenticated_client", return_value=client):
            confirmation = task_intercept_rule_confirmation(
                4, "create", action="block", kind="exact_domain", pattern="example.test"
            )
            result = json.loads(artex_manage_task_intercept_rule(
                4, "create", confirmation,
                action="block", kind="exact_domain", pattern="example.test",
            ))
        self.assertTrue(result["ok"])
        self.assertTrue(result["verified"])
        self.assertEqual(result["rule"]["id"], 12)

    def test_intercept_rule_writer_refuses_rule_missing_from_task_before_write(self):
        client = ArtexClient()
        client.get_task_surface = lambda *_args, **_kwargs: {"rules": [{"id": 99}]}
        client.manage_task_intercept_rule = Mock()
        client.clear_token = lambda: None
        with patch("artex_agent.desktop_task_setup_mcp._authenticated_client", return_value=client):
            confirmation = task_intercept_rule_confirmation(4, "delete", rule_id=12)
            with self.assertRaisesRegex(ValueError, "쓰기를 수행하지 않았습니다"):
                artex_manage_task_intercept_rule(
                    4, "delete", confirmation, rule_id=12
                )
        client.manage_task_intercept_rule.assert_not_called()

    def test_add_constraint_is_append_only_payload(self):
        client = ArtexClient()
        with patch.object(client, "_request", return_value={"id": "5"}) as request:
            result = client.add_constraint(2, "stay on loopback", "ALLOW", "CONFIRM add_constraint task=2")
        self.assertEqual(result, {"id": "5"})
        request.assert_called_once_with(
            "POST", "/api/tasks/2/cowork/constraints", {
                "text": "stay on loopback", "kind": "allow", "confirmation": "CONFIRM add_constraint task=2",
            }
        )

    def test_add_constraint_rejects_empty_or_invalid(self):
        client = ArtexClient()
        with patch.object(client, "_request") as request:
            for text, kind in ((" ", "allow"), ("text", "maybe")):
                with self.subTest(text=text, kind=kind), self.assertRaises(ValueError):
                    client.add_constraint(1, text, kind, "CONFIRM add_constraint task=1")
        request.assert_not_called()

    def test_add_scope_is_endpoint_and_payload_allowlisted(self):
        client = ArtexClient()
        with patch.object(client, "_request", return_value={"id": 7}) as request:
            result = client.add_task_scope(3, "subdomain", "http://127.0.0.1:18081", "CONFIRM add_scope task=3", "approved local target")
        self.assertEqual(result, {"id": 7})
        request.assert_called_once_with(
            "POST", "/api/tasks/3/cowork/scope",
            {"kind": "subdomain", "value": "http://127.0.0.1:18081", "reason": "approved local target", "confirmation": "CONFIRM add_scope task=3"},
        )

    def test_add_scope_rejects_unknown_kind(self):
        client = ArtexClient()
        with patch.object(client, "_request") as request:
            with self.assertRaises(ValueError):
                client.add_task_scope(3, "url", "http://127.0.0.1:18081", "CONFIRM add_scope task=3")
        request.assert_not_called()

    def test_finding_reads_use_task_provenance_and_read_only_verbs(self):
        client = ArtexClient()
        with patch.object(client, "_request", return_value=[]) as request:
            client.list_task_findings(6)
            client.get_finding(12, 6)
        self.assertEqual(request.call_args_list[0].args, ("GET", "/api/exploration/findings?task=6"))
        self.assertEqual(request.call_args_list[1].args, ("GET", "/api/exploration/findings/12?context_task=6"))

    def test_workspace_read_rejects_windows_drive_paths(self):
        client = ArtexClient()
        with patch.object(client, "_request") as request:
            with self.assertRaises(ValueError):
                client.read_workspace_file(r"C:\Users\fixture\secret.txt")
        request.assert_not_called()

    def test_task_workspace_read_is_limited_to_that_task(self):
        client = ArtexClient()
        with patch.object(client, "_request", return_value={"content": "evidence"}) as request:
            client.read_task_workspace_file(2, "tasks/2/evidence/one.md")
        request.assert_called_once_with("GET", "/api/workspace/read?path=tasks%2F2%2Fevidence%2Fone.md")
        request.reset_mock()
        with self.assertRaises(ValueError):
            client.read_task_workspace_file(2, "tasks/3/evidence/other.md")
        request.assert_not_called()

    def test_finding_mcp_requires_task_context(self):
        with patch("artex_agent.desktop_mcp._authenticated_client") as client_factory:
            with self.assertRaises(ValueError):
                artex_get_finding(12, 0)
        client_factory.assert_not_called()

    def test_write_tools_require_operation_specific_confirmation(self):
        with patch("artex_agent.desktop_task_setup_mcp._authenticated_client") as client_factory:
            for action in (
                lambda: artex_add_goal(4, "goal", "CONFIRM add_constraint task=4"),
                lambda: artex_add_constraint(4, "allow", "constraint", "CONFIRM add_scope task=4"),
                lambda: artex_add_task_scope(4, "ip", "127.0.0.1/32", "CONFIRM add_goal task=4"),
            ):
                with self.subTest(action=action), self.assertRaises(ValueError):
                    action()
        client_factory.assert_not_called()

    def test_task_setup_confirmation_does_not_trim_operator_input(self):
        with patch("artex_agent.desktop_task_setup_mcp._authenticated_client") as client_factory:
            with self.assertRaises(ValueError):
                artex_add_constraint(4, "deny", "No lockout tests", "CONFIRM add_constraint task=4 ")
        client_factory.assert_not_called()

    def test_task_setup_mcp_computes_payload_bound_confirmation_internally(self):
        import json
        from artex_agent.desktop_task_setup_mcp import artex_manage_task_setup

        class Client:
            def __init__(self):
                self.confirmation = None

            def clear_token(self):
                pass

            def manage_task_goal(self, task_id, goal_id, operation, confirmation, *, text, vulnclass):
                self.confirmation = confirmation
                return {"goal": {"id": str(goal_id)}, "activity_updated": True}

            def list_goals(self, task_id):
                return {"goals": [{"id": "11", "text": "Updated goal", "vulnclass": "xss"}]}

            def get_task_surface(self, task_id, surface, *, session, **kwargs):
                return {"items": [{"worker": "cowork", "tool": "update_goal", "tool_use_id": "cowork-goal-update-11"}]}

        client = Client()
        with patch("artex_agent.desktop_task_setup_mcp._authenticated_client", return_value=client):
            result = json.loads(artex_manage_task_setup(
                4, "goal", "update", 11, "CONFIRM update_goal task=4 goal=11",
                text="Updated goal", vulnclass="xss",
            ))
        self.assertTrue(result["verified"])
        self.assertEqual(client.confirmation, task_setup_confirmation(
            4, "update_goal", object_id=11, text="Updated goal", vulnclass="xss",
        ))

    def test_task_setup_writes_verify_native_task_lists(self):
        import json

        class Client:
            def clear_token(self):
                pass

            def add_goal(self, task_id, text, confirmation, vulnclass):
                return {"goal": {"id": "11"}, "task_may_resume": False, "activity_updated": True}

            def list_goals(self, task_id):
                return {"goals": [{"id": "11", "text": "Check access control", "vulnclass": "authorization"}]}

            def add_constraint(self, task_id, text, kind, confirmation):
                return {"constraint": {"id": "12"}, "activity_updated": True}

            def list_constraints(self, task_id):
                return {"constraints": [{"id": "12", "kind": "deny", "text": "No account lockout tests"}]}

            def add_task_scope(self, task_id, kind, value, confirmation, reason):
                return {"scope": {"id": 13, "kind": kind, "value": value, "reason": reason}, "task_may_resume": False, "activity_updated": True}

            def list_task_scope(self, task_id):
                return {"scope": [{"id": 13, "kind": "ip", "value": "127.0.0.1/32", "reason": "local fixture"}]}

            def get_task_surface(self, task_id, surface, *, session="main", page=1, size=50, **kwargs):
                if surface != "session_history" or session != "cowork":
                    raise AssertionError("unexpected activity surface")
                return {"items": [
                    {"worker": "cowork", "tool": "add_goal", "tool_use_id": "cowork-goal-11"},
                    {"worker": "cowork", "tool": "add_constraint", "tool_use_id": "cowork-constraint-12"},
                    {"worker": "cowork", "tool": "add_task_scope", "tool_use_id": "cowork-scope-4-13"},
                ]}

        with patch("artex_agent.desktop_task_setup_mcp._authenticated_client", return_value=Client()):
            goal = json.loads(artex_add_goal(4, "Check access control", "CONFIRM add_goal task=4", "authorization"))
            constraint = json.loads(artex_add_constraint(4, "deny", "No account lockout tests", "CONFIRM add_constraint task=4"))
            scope = json.loads(artex_add_task_scope(4, "ip", "127.0.0.1/32", "CONFIRM add_scope task=4", "local fixture"))
        self.assertTrue(goal["verified"])
        self.assertTrue(goal["activity_verified"])
        self.assertTrue(constraint["verified"])
        self.assertTrue(constraint["activity_verified"])
        self.assertTrue(scope["verified"])
        self.assertTrue(scope["activity_verified"])
        self.assertTrue(scope["scope_may_widen"])

    def test_task_setup_write_reports_partial_state_when_activity_is_missing(self):
        class Client:
            def clear_token(self):
                pass

            def add_goal(self, task_id, text, confirmation, vulnclass):
                return {"goal": {"id": "11"}, "activity_updated": True}

            def list_goals(self, task_id):
                return {"goals": [{"id": "11", "text": "goal", "vulnclass": ""}]}

            def get_task_surface(self, task_id, surface, *, session="main", **kwargs):
                return {"items": []}

        with patch("artex_agent.desktop_task_setup_mcp._authenticated_client", return_value=Client()):
            result = json.loads(artex_add_goal(4, "goal", "CONFIRM add_goal task=4"))
        self.assertTrue(result["native_record_verified"])
        self.assertTrue(result["partial_write"])
        self.assertFalse(result["activity_verified"])
        self.assertIn("재시도 전에 Task 화면을 확인", result["activity_error"])

    def test_task_setup_write_reports_unknown_when_native_readback_misses_new_record(self):
        class Client:
            def clear_token(self):
                pass

            def add_constraint(self, task_id, text, kind, confirmation):
                return {"constraint": {"id": "12"}}

            def list_constraints(self, task_id):
                return {"constraints": []}

        with patch("artex_agent.desktop_task_setup_mcp._authenticated_client", return_value=Client()):
            result = json.loads(artex_add_constraint(4, "deny", "No account lockout tests", "CONFIRM add_constraint task=4"))
        self.assertTrue(result["partial_write"])
        self.assertFalse(result["native_record_verified"])
        self.assertIn("재시도 전에 Task 화면을 확인", result["retry_guidance"])

    def test_task_setup_write_error_returns_unknown_outcome_without_retry(self):
        class Client:
            def clear_token(self):
                pass

            def add_task_scope(self, *args):
                raise TimeoutError("fixture timeout")

        with patch("artex_agent.desktop_task_setup_mcp._authenticated_client", return_value=Client()):
            result = json.loads(artex_add_task_scope(4, "ip", "127.0.0.1/32", "CONFIRM add_scope task=4"))
        self.assertFalse(result["ok"])
        self.assertTrue(result["partial_write"])
        self.assertEqual(result["operation"], "add_task_scope")

if __name__ == "__main__":
    import unittest

    unittest.main()


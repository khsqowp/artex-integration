import json
import threading
import time
import unittest

from artex_agent import desktop_target_mcp as target


class TargetRequestPolicyTests(unittest.TestCase):
    def test_each_assessment_class_has_a_method_ceiling(self):
        self.assertEqual(set(target._TEST_CLASSES), set(target._CLASS_METHODS))
        self.assertIn("injection", target._TEST_CLASSES)
        self.assertIn("xss_csrf", target._TEST_CLASSES)
        self.assertIn("security_headers", target._TEST_CLASSES)

    def test_confirmation_binds_origin_budget_methods_and_rate(self):
        self.assertEqual(
            target._confirmation(3, "http://127.0.0.1:18081", 12, ["GET", "POST"], 6, ["passive_recon"], "none", True),
            "CONFIRM authorize_target_run task=3 origin=http://127.0.0.1:18081 "
            "max_requests=12 methods=GET,POST requests_per_minute=6 "
            "test_classes=passive_recon session_mode=none record_traffic=yes",
        )
        self.assertTrue(target._confirmation(
            3, "http://127.0.0.1:18081", 12, ["GET"], 6, ["passive_recon"], "none", False
        ).endswith("record_traffic=no"))

    def test_access_token_extraction_is_limited_to_named_fields(self):
        self.assertEqual(target._find_access_token({"data": {"accessToken": "header.payload.signature"}}), "header.payload.signature")
        self.assertIsNone(target._find_access_token({"password": "not-a-token", "display": "header.payload.signature"}))

    def test_method_must_match_authorized_test_class(self):
        self.assertIn("GET", target._CLASS_METHODS["passive_recon"])
        self.assertNotIn("DELETE", target._CLASS_METHODS["passive_recon"])
        self.assertIn("DELETE", target._CLASS_METHODS["method_handling"])
        self.assertIn("POST", target._CLASS_METHODS["injection"])
        self.assertNotIn("DELETE", target._CLASS_METHODS["injection"])
        self.assertIn("GET", target._CLASS_METHODS["directory_indexing"])
        self.assertNotIn("POST", target._CLASS_METHODS["directory_indexing"])

    def test_path_cannot_override_authorized_origin(self):
        for path in ("//evil.example/path", "http://evil.example/", "/a\\b", "/x#fragment"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                target._request_url("http://127.0.0.1:18081", path)

    def test_relative_request_path_is_joined_to_fixed_origin(self):
        self.assertEqual(
            target._request_url("http://127.0.0.1:18081", "/api/products?q=tea"),
            "http://127.0.0.1:18081/api/products?q=tea",
        )

    def test_sensitive_query_values_are_redacted_in_reported_url(self):
        self.assertEqual(
            target._redacted_url("http://127.0.0.1:18081/reset?token=secret&email=user%40example.test&mode=check"),
            "http://127.0.0.1:18081/reset?token=%5BREDACTED%5D&email=%5BREDACTED%5D&mode=check",
        )

    def test_authentication_query_variants_are_redacted(self):
        self.assertEqual(
            target._redacted_url("http://127.0.0.1:18081/callback?auth=secret&session_id=abc123&jwt=header.payload.sig&state=opaque&next=%2Fhome"),
            "http://127.0.0.1:18081/callback?auth=%5BREDACTED%5D&session_id=%5BREDACTED%5D&jwt=%5BREDACTED%5D&state=%5BREDACTED%5D&next=%2Fhome",
        )

    def test_personal_identifier_query_variants_are_redacted(self):
        self.assertEqual(
            target._redacted_url(
                "http://127.0.0.1:18081/search?user=alice&account_id=42&phone=01012345678&dob=2000-01-02&mode=check"
            ),
            "http://127.0.0.1:18081/search?user=%5BREDACTED%5D&account_id=%5BREDACTED%5D&phone=%5BREDACTED%5D&dob=%5BREDACTED%5D&mode=check",
        )

    def test_sensitive_response_headers_are_redacted(self):
        self.assertEqual(
            target._redacted_headers({
                "set-cookie": "session=private",
                "x-auth-user": "person@example.test",
                "x-user-id": "42",
                "x-account-name": "alice",
                "x-date-of-birth": "2000-01-02",
                "location": "http://127.0.0.1:18081/reset?token=private",
                "content-type": "application/json",
            }),
            {
                "set-cookie": "[REDACTED]",
                "x-auth-user": "[REDACTED]",
                "x-user-id": "[REDACTED]",
                "x-account-name": "[REDACTED]",
                "x-date-of-birth": "[REDACTED]",
                "location": "http://127.0.0.1:18081/reset?token=%5BREDACTED%5D",
                "content-type": "application/json",
            },
        )

    def test_json_secret_fields_are_redacted(self):
        body = b'{"user":"demo","email":"user@example.test","account_id":42,"date_of_birth":"2000-01-02","access_token":"secret-value","nested":{"password":"pw"}}'
        self.assertEqual(
            target._redacted_body(body),
            '{"user": "[REDACTED]", "email": "[REDACTED]", "account_id": "[REDACTED]", "date_of_birth": "[REDACTED]", "access_token": "[REDACTED]", "nested": {"password": "[REDACTED]"}}',
        )

    def test_reflected_credentials_and_contact_values_are_redacted(self):
        request = '{"email":"test@example.test","password":"test1","username":"test@test.com"}'
        response = b'{"message":"Welcome test@test.com; password was test1","display":"test@example.test"}'
        redacted = target._redacted_body(response, target._sensitive_request_values(request))
        self.assertNotIn("test@test.com", redacted)
        self.assertNotIn("test@example.test", redacted)
        self.assertNotIn("test1", redacted)
        self.assertIn("[REQUEST VALUE REDACTED]", redacted)

    def test_safe_headers_allow_origin_but_reject_host_and_credentials(self):
        self.assertEqual(
            target._validated_headers('{"Origin":"https://example.test","X-Requested-With":"XMLHttpRequest"}'),
            {"Origin": "https://example.test", "X-Requested-With": "XMLHttpRequest"},
        )
        for headers in (
            '{"Host":"evil.example"}',
            '{"Cookie":"session=secret"}',
            '{"Authorization":"Bearer secret"}',
            '{"X-Test":"one\\r\\ntwo"}',
        ):
            with self.subTest(headers=headers), self.assertRaises(ValueError):
                target._validated_headers(headers)

    def test_batch_over_remaining_budget_is_rejected_before_any_request(self):
        run_id = "unit-test-budget"
        with target._lock:
            previous = target._runs.get(run_id)
            target._runs[run_id] = {
                "stopped": False,
                "origin": "http://127.0.0.1:18081",
                "methods": ["GET"],
                "test_classes": ["passive_recon"],
                "max_requests": 2,
                "count": 1,
            }
        try:
            with self.assertRaisesRegex(ValueError, "only 1 remain"):
                target.artex_send_target_batch(run_id, '[{"test_class":"passive_recon","method":"GET","path":"/"},{"test_class":"passive_recon","method":"GET","path":"/robots.txt"}]')
            with target._lock:
                self.assertEqual(target._runs[run_id]["count"], 1)
        finally:
            with target._lock:
                target._runs.pop(run_id, None)
                if previous is not None:
                    target._runs[run_id] = previous

    def test_close_interrupts_a_long_rate_limit_wait_without_sending(self):
        class SignalingStopEvent(threading.Event):
            def __init__(self):
                super().__init__()
                self.waiting = threading.Event()

            def wait(self, timeout=None):
                self.waiting.set()
                return super().wait(timeout)

        run_id = "unit-test-interruptible-rate-wait"
        stop_event = SignalingStopEvent()
        run = {
            "task_id": 3,
            "origin": "http://127.0.0.1:18081",
            "methods": ["GET"],
            "test_classes": ["passive_recon"],
            "max_requests": 2,
            "requests_per_minute": 1,
            "session_mode": "none",
            "record_traffic": False,
            "cookie_jar": None,
            "bearer_token": None,
            "started_at": time.monotonic(),
            "count": 0,
            "stopped": False,
            "stop_reason": None,
            "stop_event": stop_event,
            "request_in_flight": False,
        }
        with target._lock:
            previous = target._runs.get(run_id)
            previous_last_request_at = target._last_request_at
            target._runs[run_id] = run
            target._last_request_at = time.monotonic()
        result = []

        def send():
            try:
                target.artex_send_target_request(run_id, "passive_recon", "GET", "/")
            except Exception as exc:
                result.append(exc)

        worker = threading.Thread(target=send, daemon=True)
        worker.start()
        try:
            self.assertTrue(stop_event.waiting.wait(1), "request did not enter the rate-limit wait")
            closed = json.loads(target.artex_close_target_run(run_id))
            worker.join(1)
            self.assertFalse(worker.is_alive(), "close should interrupt the wait without waiting for the request lock")
            self.assertEqual(closed["requests_used"], 0)
            self.assertFalse(closed["request_in_flight"])
            self.assertEqual(len(result), 1)
            self.assertRegex(str(result[0]), "closed during rate-limit wait")
            self.assertEqual(run["count"], 0, "an interrupted wait must not consume a request")
        finally:
            stop_event.set()
            worker.join(1)
            with target._lock:
                target._runs.pop(run_id, None)
                target._last_request_at = previous_last_request_at
                if previous is not None:
                    target._runs[run_id] = previous


if __name__ == "__main__":
    unittest.main()

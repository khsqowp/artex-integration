import unittest

from artex_agent.desktop_observation_mcp import TARGET, TASK_NAME, _verify_context


class FakeArtexClient:
    def __init__(self, scope=None, constraints=None, task=None):
        self.scope = scope if scope is not None else [{"kind": "ip", "net": "127.0.0.1/32"}]
        self.constraints = constraints if constraints is not None else [
            {"kind": "allow", "source": "human", "text": f"{TARGET}의 공개 페이지 진단 범위 허용"}
        ]
        self.task = task if task is not None else {"name": TASK_NAME}

    def get_task(self, task_id):
        self.assert_task_id = task_id
        return self.task

    def list_task_scope(self, task_id):
        return self.scope

    def list_constraints(self, task_id):
        return self.constraints


class ObservationContextTests(unittest.TestCase):
    def test_accepts_expected_task_scope_and_human_allow(self):
        result = _verify_context(FakeArtexClient())
        self.assertEqual(result["task"]["name"], TASK_NAME)

    def test_rejects_missing_exact_target_allow_constraint(self):
        client = FakeArtexClient(constraints=[{"kind": "allow", "text": "127.0.0.1 only"}])
        with self.assertRaisesRegex(RuntimeError, "사람 승인 allow"):
            _verify_context(client)

    def test_rejects_wrong_task(self):
        client = FakeArtexClient(task={"name": "other-task"})
        with self.assertRaisesRegex(RuntimeError, "예상한 스모크 테스트"):
            _verify_context(client)


if __name__ == "__main__":
    unittest.main()

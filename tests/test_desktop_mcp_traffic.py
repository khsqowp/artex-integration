import base64
import json
import unittest
from unittest.mock import Mock, patch

from artex_agent.desktop_mcp import artex_get_task_activity_detail, artex_read_cowork_traffic_blob


class CoworkTrafficBlobToolTests(unittest.TestCase):
    def _call(self, body: bytes) -> dict:
        client = Mock()
        client.read_cowork_traffic_blob.return_value = {
            "task_id": 3,
            "capture_id": "cowork-t3-0123456789abcdef0123456789abcdef-1",
            "hash": "a" * 64,
            "offset": 0,
            "length": len(body),
            "total": len(body),
            "data_b64": base64.b64encode(body).decode("ascii"),
        }
        with patch("artex_agent.desktop_mcp._authenticated_client", return_value=client):
            result = json.loads(artex_read_cowork_traffic_blob(
                3,
                "cowork-t3-0123456789abcdef0123456789abcdef-1",
                "a" * 64,
            ))
        client.clear_token.assert_called_once_with()
        return result

    def test_text_body_has_readable_preview_and_retains_bounded_base64(self):
        result = self._call(b'{"message":"hello"}')
        self.assertEqual(result["text_preview"], '{"message":"hello"}')
        self.assertFalse(result["text_preview_lossy"])
        self.assertEqual(base64.b64decode(result["data_b64"]), b'{"message":"hello"}')

    def test_binary_body_does_not_get_a_misleading_text_preview(self):
        result = self._call(bytes(range(256)))
        self.assertIsNone(result["text_preview"])
        self.assertEqual(result["content_kind"], "binary_or_non_text")


class TaskActivityDetailToolTests(unittest.TestCase):
    def test_reads_only_the_requested_task_activity_detail(self):
        client = Mock()
        client.get_activity_detail.return_value = {"detail": "synthetic completion evidence"}
        with patch("artex_agent.desktop_mcp._authenticated_client", return_value=client):
            result = json.loads(artex_get_task_activity_detail(7, 148))
        self.assertEqual(result, {"detail": "synthetic completion evidence"})
        client.get_activity_detail.assert_called_once_with(7, 148)
        client.clear_token.assert_called_once_with()

    def test_rejects_invalid_ids_before_authentication(self):
        with patch("artex_agent.desktop_mcp._authenticated_client") as authenticate:
            for task_id, seq in ((0, 1), (1, 0), (-1, 1), (1, -1)):
                with self.subTest(task_id=task_id, seq=seq), self.assertRaises(ValueError):
                    artex_get_task_activity_detail(task_id, seq)
        authenticate.assert_not_called()


if __name__ == "__main__":
    unittest.main()

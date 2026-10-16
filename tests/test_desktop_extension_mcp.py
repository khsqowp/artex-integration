from __future__ import annotations

import os
import unittest
from unittest.mock import patch

from artex_agent import desktop_extension_mcp
from artex_agent.auth_store import get_admin_password


class DesktopExtensionTests(unittest.TestCase):
    def test_combined_server_exposes_all_four_connectors_without_name_collisions(self) -> None:
        names = [tool.name for tool in desktop_extension_mcp.server._tool_manager.list_tools()]
        self.assertEqual(len(names), 40)
        self.assertEqual(len(names), len(set(names)))
        for expected in (
            "artex_health",
            "artex_record_diagnostic_evidence",
            "artex_add_goal",
            "artex_send_target_request",
        ):
            self.assertIn(expected, names)

    def test_extension_password_takes_precedence_without_persisting_it(self) -> None:
        with patch.dict(os.environ, {"ARTEX_ADMIN_PASSWORD": "fixture-secret"}), patch(
            "artex_agent.auth_store.keyring.get_password", return_value="stored-secret"
        ) as get_password:
            self.assertEqual(get_admin_password(), "fixture-secret")
            get_password.assert_not_called()

    def test_manual_installation_still_falls_back_to_os_credential_store(self) -> None:
        with patch.dict(os.environ, {}, clear=True), patch(
            "artex_agent.auth_store.keyring.get_password", return_value="stored-secret"
        ) as get_password:
            self.assertEqual(get_admin_password(), "stored-secret")
            get_password.assert_called_once()


if __name__ == "__main__":
    unittest.main()

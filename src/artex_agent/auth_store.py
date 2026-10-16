"""Interactively verify ARTEx credentials and store them in Windows Credential Manager."""

from __future__ import annotations

import getpass
import sys

import keyring
from keyring.backends.Windows import WinVaultKeyring

from .artex_api import ArtexClient


SERVICE = "artex-agent-local"
USERNAME = "ARTEX"


def main() -> None:
    if sys.platform != "win32" or not isinstance(keyring.get_keyring(), WinVaultKeyring):
        raise SystemExit("Windows Credential Manager backend를 사용할 수 없습니다. 비밀번호는 저장하지 않았습니다.")

    client = ArtexClient()
    status = client.auth_status()
    if not isinstance(status, dict) or not status.get("initialized"):
        raise SystemExit("ARTEx 관리자 계정이 초기화되지 않았습니다. 자격 증명을 저장하지 않았습니다.")

    password = getpass.getpass("ARTEx 관리자 비밀번호 (입력은 표시/출력되지 않음): ")
    if not password:
        raise SystemExit("빈 비밀번호입니다. 저장하지 않았습니다.")
    try:
        client.login(password)
        tasks = client.list_tasks()
        keyring.set_password(SERVICE, USERNAME, password)
    except Exception as exc:
        client.clear_token()
        raise SystemExit(f"ARTEx 로그인/읽기 확인에 실패했습니다. 저장하지 않았습니다: {exc}") from exc
    finally:
        password = ""
        client.clear_token()

    items = tasks.get("tasks", []) if isinstance(tasks, dict) else tasks
    count = len(items) if isinstance(items, list) else "확인 불가"
    print(f"로그인과 작업 목록 읽기를 확인했습니다. 작업 수: {count}.")
    print("자격 증명은 Windows Credential Manager에 저장했습니다. ARTEx 데이터는 변경하지 않았습니다.")


if __name__ == "__main__":
    main()

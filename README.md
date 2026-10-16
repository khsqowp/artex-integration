# ARTEx Agent Profiles for Claude Desktop

한국어 · [English](README.en.md) · [日本語](README.ja.md) · [简体中文](README.zh.md)

운영자가 설정한 ARTEx 서버를 로컬 Claude Desktop 세션에서 사용하기 위한 연동 저장소입니다. Claude 에이전트 프로필, 스킬, 명령과 Python MCP 커넥터를 제공합니다.

> 커넥터는 접근 권한이 있는 ARTEx 인스턴스와 진단 작업에만 사용하세요. 대상 요청 커넥터에는 범위와 예산 제한이 있지만 범용 스캐너가 아닙니다. 대상 요청을 활성화하기 전에 작업 범위, allow/deny 규칙, 요청 예산 및 중단 조건을 검토하세요.

## 목적 및 책임

이 프로젝트는 증가하는 침해 사고에 대비해, 본인이 개발·운영하거나 명시적으로 점검 권한을 받은 서비스의 자체 보안 진단, 유지보수 및 침해사고 대응 준비를 지원하기 위한 것입니다. 본인이 소유·운영하거나 사전에 서면 승인을 받은 시스템에서, 승인된 범위 안에서만 사용해야 합니다. 업무 목적으로 사용할 경우 소속 조직의 정책과 승인을 확인해야 합니다. 공개 또는 다운로드는 제3자 시스템을 점검할 권한을 부여하지 않습니다.

사용자는 대상 선정, 허가 취득과 확인, 범위 및 안전장치 설정, 관련 법률과 제3자 약관 준수, 사용으로 인한 결과에 대해 책임집니다. 관리자는 사용자의 활동을 지시·승인·감시하거나 보증하지 않으며, 배포 후 사용을 통제하지 않습니다.

소프트웨어와 자료는 적용 가능한 법률이 허용하는 최대 범위에서 어떠한 보증도 없이 **“있는 그대로(AS IS)”** 제공됩니다. 같은 범위에서 관리자는 사용 또는 사용 불능으로 발생하는 청구, 손실 또는 손해에 대한 책임을 부인합니다. 이 고지는 법적으로 배제할 수 없는 책임을 배제하거나, 구성 요소에 적용되는 라이선스 또는 법률상 권리와 의무를 변경하지 않습니다.

이 고지는 프로젝트가 의도하는 책임 배분을 설명할 뿐이며, 관리자가 조사·소송을 당하거나 책임을 지지 않는다고 보장하지 않습니다. 법적 결과는 사실관계, 관할권, 행위 및 적용 법률에 따라 달라집니다. 자료를 공개했다고 해서 사용이 허가되는 것은 아닙니다.

## 포함 내용

- `claude-cowork-plugin/agents/`: 조율, 계획, 진단, 보고 및 재검증 역할 프로필
- `claude-cowork-plugin/skills/`: ARTEx 워크플로, API 정찰, 브라우저 및 범위 안내
- `claude-cowork-plugin/commands/`: 진단 워크플로 명령
- `src/artex_agent/`: 읽기 전용, 증거 기록, 작업 설정 및 대상 요청 MCP 커넥터
- `tests/`: 오프라인 커넥터 테스트
- `scripts/package_cowork_plugin.py`: `dist/` 아래 플러그인 ZIP 생성
- `desktop-extension/`, `scripts/package_desktop_extension.py`, `releases/artex-desktop-extension-0.4.0.mcpb`: 네 MCP 커넥터를 하나로 묶은 설치형 Claude Desktop 확장
- `scripts/smoke_mcp_stdio.py`: ARTEx에 쓰거나 대상에 접속하지 않고 MCP 시작과 도구 목록 확인

## 요구 사항

- Claude Desktop의 로컬 MCP/데스크톱 확장 지원
- 별도로 설치되어 실행 중인 ARTEx 서버
- 소스에서 MCPB를 다시 만들 때 Node.js/npm 또는 Python 패키징 스크립트에 필요한 도구

이 저장소에는 ARTEx 서버, Claude 계정, API 키, 자격 증명 또는 작업 데이터가 포함되지 않습니다. Claude 세션 인증과 ARTEx 자체 LLM 설정은 서로 다른 실행 환경입니다.

## Claude Desktop 설치

### 로컬 MCP 확장

1. `releases/artex-desktop-extension-0.4.0.mcpb`를 Claude Desktop의 **Settings → Extensions → Advanced settings → Install Extension**에서 설치합니다.
2. 확장 설정에서 ARTEx 주소(기본값 `http://127.0.0.1:8787`)와 ARTEx 비밀번호를 입력합니다. 비밀번호는 민감 설정으로 전달되며 MCP JSON이나 저장소에 넣지 않습니다.
3. ARTEx를 별도로 실행하고 Claude Desktop에서 Cowork 작업을 시작한 뒤, 커넥터 도구가 표시되는지 확인합니다.

이 확장은 네 MCP 서버의 도구를 하나의 로컬 MCP 서버로 묶습니다. ARTEx 서버를 설치·시작하지 않으며, 접근 가능한 ARTEx 주소가 없으면 연결할 수 없습니다.

### 역할·스킬 플러그인

에이전트 역할과 스킬이 필요하면 `python scripts/package_cowork_plugin.py`로 생성한 플러그인 ZIP도 별도로 설치합니다. MCP 확장은 도구 연결을, Cowork 플러그인은 역할·스킬 지침을 제공합니다.

### 수동 MCP 설정

기존 네 개 MCP 프로세스를 따로 설정하려면 Python 3.11 이상 환경에서 `python -m pip install -e .`을 실행하고 `claude-cowork-plugin/.mcp.json.example`의 자리표시자 경로를 바꿉니다. ARTEx 주소를 설정하고 비밀번호는 `artex-auth-store` 명령으로 Windows Credential Manager에 저장하세요.

## 점검

오프라인 테스트:

```powershell
python -m unittest discover -s tests -v
```

로컬 MCP 시작 및 도구 목록 확인:

```powershell
python scripts/smoke_mcp_stdio.py
```

테스트와 smoke 확인은 ARTEx 배포 환경과의 종단 간 Cowork 인수 시험을 대신하지 않습니다. 기록 기능은 지정된 합성 작업으로 확인하고 합성 취약점 Finding을 만들지 마세요.

## 실행 환경 경계

에이전트 프로필은 이를 호출한 Claude 세션에서 실행되며 설정된 로컬 MCP 커넥터를 사용할 수 있습니다. 이 연동은 Claude 구독 인증 정보를 ARTEx 네이티브 planner/worker로 전달하지 않으며 ARTEx 자체 무인 실행을 켜지 않습니다. 로컬 MCP는 Claude Desktop이 중계하므로 앱을 통해 작업을 시작하고 연결을 유지해야 합니다.

## 공개 전 참고

이 저장소는 새 Git 이력으로 정리한 소스 스냅샷입니다. 로컬 가상 환경, 자격 증명, 컴퓨터별 경로, 로그 및 작업별 진단 자료는 제외했습니다. 조직 전용 웹 침투 테스트 스킬도 공개 복사본에서 제외했습니다. 공개 전에 의존성 및 재배포 라이선스를 검토하고 포함된 AGPL-3.0 라이선스와 배포 기본값을 확인하세요.

## 개발·검증 자료

- `agents/`: ARTEx 역할별 프롬프트 정의
- `docs/ARTEX_CODE_DIAGNOSTIC_TEMPLATE.md`: 대상 정보를 사용자가 채우는 Code 진단 템플릿
- `docs/COWORK_CAPABILITY_MATRIX.md`: ARTEx 기능과 Claude Cowork 연동 경계 표
- `docs/COWORK_READ_ONLY_ACCEPTANCE_PROMPT.md`: 선택한 합성 작업에서 사용하는 읽기 전용 연결 확인 프롬프트
- `scripts/e2e_*readonly*.py`: ARTEx MCP 읽기 전용 수락 점검 스크립트
- `scripts/extract_prompts.go`: ARTEx 소스의 기본 역할 프롬프트 추출 도구

내부 웹 진단 스킬, 로컬 MCP 설정, 자격 증명 및 작업별 진단 자료는 공개 복사본에 포함하지 않았습니다.

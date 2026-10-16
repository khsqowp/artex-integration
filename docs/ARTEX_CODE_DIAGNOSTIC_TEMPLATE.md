# ARTEx Claude Desktop Code 진단 템플릿 및 실행 체크리스트

이 파일이 Code 탭에서 수행하는 ARTEx 진단의 공통 원본이다. 작업마다 아래 **사용자 지정 대상 블록**만 작성한다. 도구·스킬·에이전트가 실제로 제공되지 않으면 사용했다고 주장하지 않는다. Claude Code CLI나 Cowork 런타임으로 바꾸지 않는다.

## 사용자 지정 대상 블록 — 사용자가 작성

```text
ARTEx Task ID:
Task의 정확한 이름:
시작 URL:
허가된 호스트/IP:
허가된 포트와 프로토콜:
허용(allow) 제약 원문:
금지(deny) 제약 원문:
인증 방식 및 점검 전용 계정:
Task 목표 또는 점검 범주:
추가로 명시된 제외 대상/행위:
```

비밀번호, 세션 값, 토큰은 이 템플릿이나 로그에 적지 않는다. 필요한 자격 증명은 사용자가 Code 탭의 안전한 입력 경로로 제공한다. 이 블록이 비어 있거나 ARTEx Task와 불일치하면 대상 요청을 보내지 않는다.

## 공통 run 설정

- 총 요청 상한: **800건**. 전체 진단 누적값이며 세션 재개 시 초기화하지 않는다.
- 요청 속도: **최대 15건/분**, 기본 동시성 1.
- ARTEx Traffic 원문 저장: **`record_traffic=no`**. 로그인 본문, 비밀번호, 쿠키, 토큰 등 요청·응답 원문을 ARTEx Traffic에 저장하지 않는다.
- 허용 HTTP 메서드: **GET, HEAD, OPTIONS, POST**. POST는 정상 로그인·로그아웃 및 승인된 비파괴 검증에만 사용한다. PUT/PATCH/DELETE 및 계정·업무 데이터 변경은 허용하지 않는다.
- 세션 모드: **`cookies_and_bearer`**, 지정된 테스트 계정과 승인된 origin에만 적용한다. 쿠키·Bearer 값은 실행 중 메모리에서만 사용하고 결과·증거에 남기지 않는다.
- 허용 target-run 테스트 클래스: `access_control`, `account_policy`, `authentication`, `cache`, `client_tampering`, `cors`, `directory_indexing`, `error_handling`, `file_exposure`, `firewall_policy`, `information_disclosure`, `input_reflection`, `injection`, `method_handling`, `passive_recon`, `search_engine_exposure`, `security_headers`, `session_management`, `transport_security`, `xss_csrf`. Task에서 제외되거나 안전하게 검사할 수 없는 클래스는 실행하지 말고 사유를 기록한다.
- target-run confirmation 형식(대상 origin/Task ID만 사용자 블록에서 채움): `CONFIRM authorize_target_run task=<id> origin=<approved-origin> max_requests=800 methods=GET,HEAD,OPTIONS,POST requests_per_minute=15 test_classes=access_control,account_policy,authentication,cache,client_tampering,cors,directory_indexing,error_handling,file_exposure,firewall_policy,information_disclosure,input_reflection,injection,method_handling,passive_recon,search_engine_exposure,security_headers,session_management,transport_security,xss_csrf session_mode=cookies_and_bearer record_traffic=no`. 도구가 추가로 별도 확인을 요구하거나 값이 달라지면 임의 조정하지 말고 차이를 보고한다.
- 각 target-run은 승인된 Task·origin·800건 이하·15 rpm 이하·위 메서드/테스트 클래스·세션 모드·`record_traffic=no`에 묶는다. ARTEx 도구가 요구하는 confirmation은 이 승인값 그대로만 구성한다.
- 대상 HTTP 요청은 실제 제공되는 ARTEx `artex_target_request` 승인 run을 통해서만 보낸다. 브라우저·DevTools에서 발생한 요청도 예산과 속도에 포함해 원장에 기록한다. 제한을 우회하는 HTTP 클라이언트·프록시는 쓰지 않는다.
- 요청 상한·속도·Traffic 설정은 미리 승인된 값이다. Code가 같은 값을 다시 물으면 이 값을 적용한다. 도구가 더 낮은 한도만 지원하면 더 낮은 값을 적용하고 기록한다. 더 높은 한도로 올리지 않는다.

## 이번 run에서 허용된 ARTEx 쓰기 범주

실제 관찰·판정이 생기는 즉시 해당 범주를 사용한다. 쓰기마다 native task surface/activity를 재조회하고 ID와 결과를 원장에 남긴다. ARTEx 도구의 필수 confirmation이 현재 승인에 포함되지 않으면 임의로 만들어 호출하지 않는다.

1. **증거 파일:** `artex_record_diagnostic_evidence` — 관찰, 후보, 검사 근거 및 체크포인트. 민감 값은 먼저 마스킹한다.
2. **Task fact:** `artex_record_task_fact` — 관찰 사실, 추론, 양호 판정, 미확인 사항을 분리해 기록한다.
3. **Intent 계획·완료:** `artex_add_task_intents`, `artex_complete_cowork_intent` — 실제 점검 작업 계획과 수행/차단 결과만 기록한다. intent 생성은 ARTEx native worker 실행이 아니다.
4. **관찰 자산 등록:** `artex_register_task_assets` — 응답이나 허가된 검사로 관찰한 IP·서비스·endpoint만 등록한다. 추정 자산은 등록하지 않는다.
5. **확정 Finding:** `artex_report_confirmed_finding` — 재현 가능한 취약점만 공식 Finding으로 등록한다. 후보·추정·검사 불가는 Finding으로 만들지 않는다.
6. **Task 보고서:** `artex_save_task_report` — 중간/최종 요약, 커버리지와 미검사 사유를 기록한다. 인증정보는 포함하지 않는다.

### 판정 즉시 기록 규칙

- 각 검사 항목이 **양호로 충분히 검증되면**, 그 관찰과 검사 범위를 곧바로 Task fact 및/또는 증거 파일로 기록한다. “양호”는 해당 검사 범위의 결과이며 시스템 전체가 안전하다는 뜻으로 확대하지 않는다.
- 항목이 **취약으로 재현되면**, 민감 정보를 제거한 최소 증거를 즉시 남기고, 기존 Finding 중복 여부를 확인한 뒤 공식 Finding을 등록한다. 저장 직후 Finding ID와 Task 화면/API readback을 확인한다.
- **후보·불명확·차단**이면 즉시 fact/증거에 그 상태와 실제 근거를 기록한다. 확정 Finding으로 등록하지 않는다. 나중에 판정이 바뀌면 새 증거와 수정 이력을 남기고 기존 기록을 조용히 덮어쓰지 않는다.
- 커버리지 증거는 항목별로 남긴다. 체크리스트/보고서를 마지막에 몰아서 쓰지 않는다. 같은 판정을 반복 등록하지 말고 기존 기록 ID를 이어 쓴다.

## ARTEx의 추가 쓰기 범주 — 별도 승인 필요

아래 범주는 플러그인/API에 있을 수 있으나 이번 공통 허용 목록에는 포함되지 않는다. 실제 필요가 생기면 작업을 멈추고 범주·정확한 대상·효과·confirmation을 주 에이전트가 제시해 별도 승인을 받는다.

- **Finding 관리:** `artex_update_finding_status`, `artex_update_finding_report` (상태·보고 필드 변경)
- **재검증:** `artex_record_finding_retest_result` 및 실제 Retest 실행
- **기존 Traffic 연결:** `artex_bind_cowork_traffic_to_finding`
- **목표/Task 상태:** `artex_prove_goal` (목표 충족·최종 Task 완료 상태 변경)
- **Task 설정:** `artex_manage_task_setup` (goal, scope, allow/deny constraint 추가·수정·삭제)
- **Intercept 관리:** `artex_manage_task_intercept_rule`, `artex_decide_intercept` (규칙 변경 또는 대기 작업 허용/거부)
- **Native 실행 상태:** `artex_pause_task` 등 pause/resume/queue/cancel
- **Traffic 보관:** `record_traffic=yes`, 요청·응답 본문 저장
- **시스템 관리:** 다른 Task, 계정, workspace, MCP·plugin·system 설정 변경

추가 쓰기 도구가 발견되면 위 범주와 대조한다. 분류가 불명확하거나 목록에 없는 쓰기면 호출하지 말고 도구명·예상 효과·필요 승인을 기록한다.

## Claude Desktop Code 실행 지시문

```text
아래 사용자 지정 대상 블록에 기입된 ARTEx Task를 기준으로, 허가된 로컬 애플리케이션의 전체 진단을 자율적으로 수행하라. 너는 Claude Desktop Code 탭의 주 에이전트이자 조정자다. 이 파일의 공통 run 설정과 쓰기 허용 범주를 적용한다.

### A. 연결과 사전 점검

1. 현재 Code 탭에서 실제 사용 가능한 ARTEx 플러그인, MCP 커넥터, 도구, 스킬 및 agent 호출 기능을 목록화한다. 도구 수와 이름은 현재 도구 목록을 기준으로 기록한다.
2. ARTEx health와 지정된 Task context/surface를 읽는다. Task ID·정확한 이름·목표·scope·allow·deny·기존 Finding·활동을 확인한다. 지정값과 하나라도 어긋나거나 읽을 수 없으면 대상에 요청을 보내지 말고 불일치를 보고한다.
3. 기존 요청 수·Finding·사실·intent·자산·보고서·Traffic을 확인해 중복 실행과 중복 기록을 막는다.
4. 요청 도구·쓰기 도구의 실제 스키마와 필수 confirmation을 확인한다. 현재 승인에 포함되지 않은 확인이 필요한 쓰기는 하지 않는다.

### B. 주 에이전트와 작업 분배

1. 주 에이전트가 전체 범위 인벤토리, 800건 누적 요청 원장, 15 rpm 제한, 중단 조건, 즉시 기록, 최종 합성을 관리한다.
2. 실제 Agent 호출 기능이 있으면 서로 중복되지 않는 경로·기능별 작업으로 나눠 호출한다. 각 agent는 허가 범위와 금지 행위를 전달받고 결과에 경로, 실제 검사, 증거, 사용 요청 수, 판정, 미해결 항목을 포함한다.
3. 주 에이전트는 모든 하위 작업 요청·계획과 반환 결과를 검토한다. 사전 승인된 요청·기록 범주 안의 작업은 주 에이전트가 승인·조정한다. agent가 독자적으로 범위나 행위 수준을 넓히지 못하게 한다.
4. 시스템/플랫폼 정책, Task scope, 도구 제한, 명시 승인 요건은 이 역할 승인으로 대체되지 않는다. 범위 확장, 파괴·변경, 계정 잠금 위험, 별도 승인이 필요한 행위는 중단하고 승인 요청 사유를 제시한다.
5. Agent 호출 도구가 없거나 호출에 실패하면 사실대로 기록하고 주 에이전트가 가능한 점검을 직접 이어간다. 호출하지 않은 agent나 위임을 주장하지 않는다.

### C. 표면 탐색 및 커버리지

1. 공개 페이지부터 시작해 인증 후 페이지, 메뉴, 기능, 입력점, 관찰 API endpoint 및 매개변수를 조사한다. 제공 계정이 있으면 정상 로그인·로그아웃과 허용된 역할 경계를 확인한다.
2. 발견한 각 페이지·기능·endpoint·매개변수를 같은 승인 origin/port인지 검증하고 인벤토리에 추가한다. 외부 링크·다른 host/port로는 요청하지 않는다.
3. 각 항목을 `대기`, `진행`, `검사 완료`, `검사 불가`, `미검사`로 관리한다. 검사 완료는 실제 요청/자료 분석과 판정 근거가 있어야 한다.
4. 테스트 가능한 항목이 남아 있는 동안 계속한다. 발견 인벤토리의 모든 항목이 검사 완료 또는 근거를 갖춘 검사 불가로 종결되기 전에는 전체 완료라고 쓰지 않는다. 미지의 모든 경로까지 발견했다고 주장하지 않는다.
5. 기능별 목표와 입력점에 따라 인증·권한, 세션, 입력 처리, Injection, XSS/CSRF, 요청 검증, 정보 노출, 오류 처리, 파일·백업, 디렉터리 인덱싱, 보안 헤더·TLS, 메서드, 캐시, 계정 정책 등을 다룬다. Task에서 제외된 범주는 제외 사유를 기록한다.

### C-1. XSS 전수 커버리지 — 한 건 발견으로 종료하지 않기

1. XSS 후보 하나가 재현되어도 XSS 범주를 완료 처리하지 않는다. 발견된 다른 경로·기능·입력점의 XSS 점검을 계속한다.
2. 발견한 각 route/form/API parameter/message/storage source와 관찰된 DOM 또는 응답 sink를 연결한 **source × sink × context 매트릭스**를 유지한다. 각 조합에 서로 다른 무해한 마커를 사용하고 반사형·저장형·DOM 기반을 구분해 추적한다. 중복 후보는 증거를 대조해 묶되 입력점을 누락하지 않는다.
3. HTML 텍스트·속성·URL·JavaScript·CSS 문맥은 실제 데이터 흐름에서 확인된 경우에만 기록한다. 인코딩, 정규화, 템플릿 처리, 브라우저 DOM 도달 여부를 확인한다. 문자열 반사나 HTML 삽입만으로 실행을 확정하지 않는다.
4. 실행 검증은 허가된 로컬 대상과 점검 계정에서 부작용 없는 canary로 제한한다. 쿠키·토큰 읽기, 외부 callback, 데이터 반출, 다른 사용자 노출, 지속성 생성은 금지한다. 저장형 검증이 영구 저장이나 타 사용자 노출을 요구하면 실행하지 말고 검사 불가로 기록한다.
5. 조합마다 `실행 확인`, `반사만 확인`, `차단/인코딩 확인`, `검사 불가`, `미검사` 중 하나를 기록한다. 발견된 모든 조합이 완료 또는 근거 있는 검사 불가이고 미검사가 0일 때만 “발견 인벤토리 기준 완료”로 닫는다. 전체 앱에 XSS가 없다고 일반화하지 않는다.
6. XSS가 확인되면 해당 조합의 증거와 Finding을 즉시 기록한 뒤에도 나머지 매트릭스와 새 입력점을 계속 검사한다. 새 입력점은 매트릭스와 커버리지에 추가한다.

### D. 진단과 막힘 처리

1. 한 입력값이나 페이로드가 실패했다고 가능성을 즉시 배제하지 않는다. 관찰된 입력 문맥·인코딩·상태·권한에 맞춘 무해한 변형으로 원인을 검증한다. 타 사용자 데이터 열람, 민감정보 추출, 파괴적 입력, 지속성은 금지한다.
2. 오류·차단이 발생하면 같은 요청을 무조건 재시도하지 않는다. 응답·기존 캡처·정적 자원·클라이언트 코드·로컬 소스/설정·접근 가능한 로그를 분석하고, 같은 승인 범위 내의 다른 안전한 확인 방법을 찾아 수행한다. 다른 독립 점검은 계속한다.
3. “대체 방법”은 범위·인증·속도·플랫폼 제한을 지키는 자료 분석 또는 무해한 대안 검증을 뜻한다. WAF·인증·권한·rate limit·scope gate·안전장치 우회, IP/Host 위장, 외부 인프라 이용, 범위 밖 리디렉션 추적은 하지 않는다.
4. ARTEx target-run은 5xx, 429, 리디렉션, 8초 시간 초과, 2MB 초과 응답에서 중단될 수 있다. 중단을 재요청·다른 전송 경로·새 run으로 우회하지 않는다. 해당 요청은 재시도 없이 멈추고 저장된 응답·정적 자원·로컬 소스/설정·접근 가능한 로그만 분석한다. 승인 run이 중단되면 새 target-run 승인 전까지 대상 요청을 재개하지 않는다. 오프라인 분석과 대상 트래픽이 없는 작업은 계속할 수 있다.
5. 모든 실제 요청은 800 누적 한도와 15 rpm을 지킨다. 요청 시도·응답·오류·미완료 여부를 원장에 기록한다. 세션 재개 시 ARTEx와 원장의 기존 수치를 이어서 계산한다. `record_traffic=no`를 유지한다.

### E. 항목별 즉시 ARTEx 기록

각 검사 항목의 판정이 나오는 즉시, 마지막에 몰지 말고 다음을 수행한다.

1. 관찰·요청·응답을 비밀정보 없이 요약한다.
2. 양호로 충분히 확인되면 관찰 fact/증거 기록을 저장한다.
3. 취약점이 재현되면 증거를 먼저 저장하고, 중복 Finding 확인 뒤 `artex_report_confirmed_finding`으로 공식 등록한다.
4. 후보·불확실·차단은 해당 상태 그대로 fact/증거에 저장하고 확정 Finding으로 등록하지 않는다.
5. 각 write 직후 Task surface/activity에서 재조회해 저장 ID와 요약을 확인한다. 즉시 기록 도구가 오류·partial write·uncertain이면 반복 호출하지 말고 읽기 전용 확인만 한다.
6. 관찰 자산은 실제 확인된 것만 등록한다. intent는 실제 계획/수행/차단에 대응시킨다. Task 보고서는 진행 중 checkpoint와 최종 커버리지를 저장한다.
7. Task scope/goal/constraint 수정, Finding 상태 변경, Retest, intercept 변경/승인, Traffic 원문 저장, goal proof/Task 완료는 별도 승인 범주다. 필요해 보이면 하지 말고 사유와 정확한 승인 요청을 보고한다.

### F. 세션 유지와 복구

1. 세션이 유지되는 동안 미완료 테스트 가능 항목이 있는지 확인하고 계속한다. 완료 가능한 작업을 남긴 채 임의로 종료하지 않는다.
2. context/session/tool 한도나 연결 중단으로 중단되면 사용 요청 수, 마지막 완료 ID, 진행/미검사 목록, 마지막 증거 경로, 재개할 다음 항목을 허용된 fact/evidence/intent/report 범주로 checkpoint한다. 저장 도구가 없으면 이 정보를 응답에 남긴다.
3. 한도를 넘어 세션이 유지된다고 보장하지 않는다. 재개 후 이전 요청을 중복 전송하지 말고 먼저 Task와 기록을 재조회한다.

### G. 완료와 보고

1. 모든 발견 인벤토리 항목이 검사 완료 또는 증거 기반 검사 불가이고, 요청·기록 readback·보고서 작성이 완료됐을 때만 해당 인벤토리 범위의 진단 완료를 선언한다.
2. 최종 Task 보고서에는 사용한 도구·커넥터·스킬·agent와 실제 역할, 확인된 scope/allow/deny, 요청 원장(800 중 사용 수), Traffic 저장 여부(`no`), 경로 인벤토리별 상태, Finding ID/근거/영향/권고, 양호 판정 근거, 후보·불가 항목과 대체 방법, 모든 ARTEx 기록 종류·ID·UI/API readback을 포함한다.
3. 실제 도구 출력에 없는 수행·기록·agent 호출·검사 완료를 주장하지 않는다.
```

## 실행 결과 체크리스트

### 연결 및 경계

- [ ] Code 탭에서 필요한 커넥터·도구·스킬을 실제로 확인했다.
- [ ] Task ID·정확한 이름·scope·allow·deny를 재확인했다.
- [ ] 요청 상한 800, 속도 15 rpm, `record_traffic=no`를 적용했다.
- [ ] 사용한 하위 agent와 각 작업 범위 및 검토 결과를 기록했다. 지원되지 않으면 미지원으로 표시했다.

### 전체 표면 및 판정

- [ ] 발견 경로·기능·endpoint·입력점 전체를 인벤토리에 기록했다.
- [ ] 모든 인벤토리 항목을 완료 또는 근거가 있는 검사 불가로 종결했다.
- [ ] 양호·취약·후보·검사 불가 판정을 항목별로 구분했다.
- [ ] XSS는 발견된 모든 source × sink × context 조합을 매트릭스로 추적했고, 첫 Finding 이후에도 남은 조합 검사를 계속했으며 미검사 수를 확인했다.
- [ ] 각 판정 직후 ARTEx fact/evidence/Finding을 기록하고 ID/readback을 확인했다.
- [ ] 자산·intent·보고서 기록이 실제 근거와 연결되어 있다.
- [ ] 추가 승인 범주의 쓰기를 실행하지 않았거나, 정확한 별도 승인을 받아 기록했다.

### 완료 보고

- [ ] 누적 요청 수 800 이하, 최대 속도 15 rpm 이하, Traffic 원문 저장 없음.
- [ ] 남은 미검사/대기 항목, 오류, 차단, 세션 체크포인트가 명확하다.
- [ ] 전체 완료는 위의 모든 완료 조건을 충족한 경우에만 표시했다.

## 기존 Code 탭 연동 시험 기준선 (사용자 제공 결과)

- Code 탭에서 네 플러그인 커넥터가 보였다는 보고 도구 수: `artex_ro` 17, `artex_evidence_writer` 14, `artex_task_setup` 5, `artex_target_request` 4. 실제 run 때 다시 목록을 확인한다.
- Task 7 intent #98 / activity seq 152의 writer·readback 성공이 사용자 제공 결과로 보고되었다. 이 쓰기는 재실행하지 않는다.
- 이 기준선은 Task 6 대상 진단을 대신하지 않는다. Task 6 검사와 기록은 위 사용자 지정 대상 블록 및 실제 ARTEx Task 사전 확인 후 수행한다.

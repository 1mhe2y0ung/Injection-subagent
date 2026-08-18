# Injection Subagent

`dast-harness`의 정찰 결과를 입력으로 받아 SQL Injection과 OS Command Injection을
검사하는 injection 에이전트 구현이다. 요청을 직접 만들지 않고 프로젝트의
`AgentHttpClient`를 사용하며, 모든 결과를 `AgentFinding`/`AgentResult` 계약에 맞춰
반환한다.

이 저장소는 **통합용 산출물 저장소**다. 두 Python 파일은 단독 패키지가 아니며
`dast-harness` 저장소의 아래 위치에 배치했을 때 실행된다.

| 이 저장소 | `dast-harness` 배치 위치 |
|---|---|
| `injection.py` | `dast_harness/agent_kit/injection.py` |
| `test_injection.py` | `tests/test_injection.py` |

## 주요 기능

- 정찰 에이전트의 `RequestSeed` 중 query/body 파라미터 검사
- GET query, POST query, URL-encoded form, JSON body 재생
- 한 번에 파라미터 하나만 변경하고 나머지 요청 형태 보존
- SQL 오류와 주석 복구를 대조하는 error-based SQLi 탐지
- 셸 산술 결과와 음성 대조군을 사용하는 Command Injection 탐지
- 중복 finding 억제와 파라미터 단위 coverage 제공
- 요청 예산, 인증 부재, 미지원 요청 형식에 대한 skip reason 기록
- 위험한 추출·파일 조작·OOB 페이로드 미실행

## 동작 구조

```text
ReconAgent
  └─ request_seeds
       └─ InjectionAgent
            ├─ 정상 기준선 재생
            ├─ SQLi 공격 + 주석 복구 대조
            ├─ CMDi 연산 마커 + 구분자 제거 대조
            └─ AgentResult
                 ├─ findings
                 ├─ coverage
                 └─ completion
```

모든 HTTP 요청은 `AgentHttpClient`를 통과한다. 이 클라이언트는 매 요청마다 대상
허가 범위를 검사하고, 리다이렉트를 따라가지 않으며, actor별 쿠키 격리와 요청 예산을
강제한다. `requests`, `httpx`, `urllib.request`를 직접 사용하지 않는다.

## 통합

`dast-harness` 저장소 루트에서 파일을 대응 위치로 복사한다. 이미 파일이 있다면
내용을 먼저 비교하고 필요한 변경만 병합한다.

```text
Injection-subagent/injection.py
    → dast-harness/dast_harness/agent_kit/injection.py

Injection-subagent/test_injection.py
    → dast-harness/tests/test_injection.py
```

추가 런타임 의존성은 없다. 구현은 Python 표준 라이브러리와 `dast-harness`의
`agent_kit`만 사용한다.

## 빠른 실행

통합 후 `dast-harness` 저장소 루트에서 통제 취약 앱을 실행한다.

```bash
python3 targets/vulnerable_app/app.py
```

다른 터미널에서 injection 에이전트를 실행한다.

```bash
python3 -m dast_harness.agent_kit.injection http://127.0.0.1:8080
```

모듈 엔트리포인트는 먼저 `ReconAgent`를 실행한 뒤 발견한 query/body 파라미터를
검사한다. 통제 앱에서는 `/search?q=`의 SQLi를 탐지하고, 음성 대조군인
`/lookup?q=`은 finding으로 보고하지 않아야 한다.

## 코드에서 사용

```python
from dast_harness.agent_kit import AgentHttpClient
from dast_harness.agent_kit.injection import InjectionAgent
from dast_harness.agent_kit.recon import ReconAgent

base = "http://127.0.0.1:8080"
client = AgentHttpClient(allowlist=set(), max_requests=300)

recon_result = ReconAgent(client).run(base)
result = InjectionAgent(
    client,
    seeds=recon_result.request_seeds,
).run(base)

for finding in result.findings:
    print(finding.finding_id, finding.severity, finding.confidence)

print(result.coverage)
```

기존 인증 세션이 있는 actor를 사용하려면 다음처럼 전달한다.

```python
result = InjectionAgent(client, seeds=seeds, actor="alice").run(base)
```

에이전트가 로그인 절차를 수행하지는 않는다. `auth_required=True`인 seed를 익명
actor로 실행하면 `authentication-unavailable`로 건너뛴다.

## 탐지 기준

### SQL Injection

각 파라미터에 대해 다음 세 요청을 비교한다.

1. 정찰에서 관측한 원래 값으로 기준선 요청
2. 값 뒤에 홑따옴표(`'`)를 붙인 공격 요청
3. 값 뒤에 SQL 주석(`'--`)을 붙인 복구 대조 요청

공격 응답에 알려진 DB 오류 문구가 나타나고, 복구 대조가 기준선과 같은 상태로
돌아올 때만 `CONFIRMED` finding을 생성한다. 단순한 HTTP 500, 검증 오류 또는
SQL처럼 보이는 문구 하나만으로는 보고하지 않는다.

다음 공격은 의도적으로 실행하지 않고 `Probe.withheld`에 기록한다.

- UNION 기반 데이터 추출
- stacked query를 사용한 쓰기
- time-based blind SQLi
- 실제 데이터 추출

### OS Command Injection

`;`, `|`, backtick 뒤에 셸 산술식을 실행하는 비파괴 페이로드를 붙인다. 페이로드
원문에는 없는 계산 결과가 응답에 나타나고, 명령 구분자를 제거한 대조 요청에서는
사라질 때 실제 실행으로 판정한다. 이 방식으로 입력의 단순 반사와 셸 실행을 구별한다.

다음 동작은 실행하지 않는다.

- reverse shell
- 파일 읽기·쓰기
- 데이터 유출
- 지속성 확보
- 긴 sleep 기반 탐지
- OOB callback

## 지원 요청

| 파라미터 위치 | 지원 형식 |
|---|---|
| query | GET, POST |
| body | POST `application/x-www-form-urlencoded` |
| body | POST `application/json` |

JSON 배열 경로는 지원하지 않는다. 미지원 method나 Content-Type은 다른 형식으로
임의 변환하지 않고 coverage의 `skipped`에 기록한다.

주요 skip reason:

| 사유 | 의미 |
|---|---|
| `missing-baseline-value` | 비교할 정상 값이 없음 |
| `unsupported-method` | GET/POST가 아닌 요청 |
| `unsupported-content-type` | 재생할 수 없는 본문 인코딩 |
| `unsupported-json-path` | 배열을 포함한 JSON 경로 |
| `authentication-unavailable` | 필요한 인증 세션이 없음 |
| `baseline-unavailable` | 기준선 요청 전송 실패 |
| `method-not-allowed` | 기준선 응답이 405 |
| `request-budget-exceeded` | 검사 도중 요청 예산 소진 |

## 결과 계약

finding은 다음 형태를 따른다.

- `scanner`: `agent:injection`
- `category`: `injection`
- `severity`: 확인된 SQLi/CMDi는 `critical`
- `confidence`: 대조가 성립한 finding은 `confirmed`
- `evidence`: 기준선·공격·대조 요청과 판정 근거
- `agent_data["injection"]`: 전략, 대상, 시도, 적중, 보류한 공격

`coverage.unit`은 `parameter`다. 검사를 완료한 파라미터는 `tested`, 판정할 수 없어
넘긴 파라미터는 `skipped`로 집계한다. 요청 예산이 중간에 끝난 현재 파라미터를 두
항목에 중복 집계하지 않는다.

## 테스트

파일을 `dast-harness`에 통합한 뒤 저장소 루트에서 실행한다.

```bash
python3 -m unittest tests.test_injection -v
python3 -m unittest discover -s tests -v
```

`test_injection.py`는 실제 네트워크 대신 `FakeClient`를 사용해 다음을 검증한다.

- SQLi 양성 탐지와 `/lookup` 오탐 방지
- 주석 복구가 없는 SQL 오류의 오탐 방지
- Command Injection 연산 마커와 단순 입력 반사 구별
- GET query, POST form, POST JSON 요청 보존
- 중복 finding, skip reason, 요청 예산 집계
- out-of-scope 요청의 안전 차단

## 제한사항

- error-based SQLi와 응답 기반 Command Injection만 지원한다.
- blind/time-based/OOB 탐지는 수행하지 않는다.
- JSON 배열 경로(`$.items[0].id`)는 지원하지 않는다.
- Command Injection 페이로드는 POSIX 계열 셸의 `echo`와 산술 확장을 전제로 한다.
- 로그인과 자격증명 관리는 호출자가 준비해야 한다.
- 기본 `dast-harness scan` CLI와 오케스트레이터 자동 등록은 이 저장소의 범위 밖이다.

프로젝트 전체 계약과 안전 규칙은 `dast-harness`의 `AGENT_GUIDE.md`와
`CLAUDE.md`를 따른다.

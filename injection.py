"""독립 Injection Agent — SQL Injection과 Command Injection을 1차로 다룬다.

`recon.py`의 골격을 복사해 만들었다. 고칠 곳은 `_test_sqli()`/`_test_cmdi()`
쪽이다. 세 에이전트의 모양이 같아야 마지막에 합칠 수 있다 (AGENT_GUIDE.md).

정찰의 `request_seeds` 중 query/body 파라미터가 있는 것만 받아, **한 번에
파라미터 하나만** 갈아끼워 재생한다 — 나머지 파라미터·method·인증 상태는
그대로 보존한다 (AGENT_GUIDE.md §6). 증거는 항상 "기준선 + 공격 + 통제(또는
복구)"로 만든다. 500 한 번, timeout 한 번, 일반 검증 오류 하나만으로는
취약하다고 판정하지 않는다 — 통제 타겟의 `/lookup`이 이 함정이다
(AGENT_GUIDE.md §8).

지금 상태로 통제 앱에 대해 동작한다 (SQLi만 — 앱에는 Command Injection
엔드포인트가 없다. FakeClient 픽스처로만 검증됨. `tests/test_injection.py` 참고):
    python3 targets/vulnerable_app/app.py &
    python3 -m dast_harness.agent_kit.injection http://127.0.0.1:8080
"""

from __future__ import annotations

import json
import sys
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from ..models import Severity
from .base import Agent
from .contract import (AgentFinding, AgentResult, Confidence, Evidence, Probe,
                       RequestParameter, RequestSeed)
from .http import AgentHttpClient, RequestBudgetExceeded

# --------------------------------------------------------------------- SQLi
#
# 진짜 SQL 오류 문구만 잡는다. 그냥 500은 증거가 아니다 — `/lookup`은 100자
# 넘는 입력에 500을 뱉지만 이 문구는 절대 안 나온다 (AGENT_GUIDE.md §8,
# ground_truth.json의 `must_not_detect`).
SQL_ERROR_MARKERS = (
    "sql syntax", "sqlstate", "sqlite3.operationalerror",
    "unclosed quotation mark", "quoted string not properly terminated",
    "pg::syntaxerror", "syntax error at or near",
    "ora-00933", "ora-01756", "microsoft ole db provider for sql server",
    "odbc sql server driver", "you have an error in your sql",
    "warning: mysql", "mysql_fetch", "mysqli_",
)

SQLI_ATTACK_SUFFIX = "'"          # 구문 경계를 깨는 최소 입력
SQLI_RECOVERY_SUFFIX = "'--"      # 같은 자리를 주석으로 되돌리는 대조 입력


def _has_sql_marker(text: str) -> bool:
    low = text.lower()
    return any(m in low for m in SQL_ERROR_MARKERS)


# ------------------------------------------------------- Command Injection
#
# "500이 떴다"나 "입력이 그대로 반사됐다"는 증거가 아니다. 페이로드에 셸이
# **계산해야만** 나올 수 있는 값(a*b)을 마커로 심는다 — 취약하지 않은 앱이
# 입력을 그대로 반사해도 계산 결과는 절대 못 만든다. 대조는 같은 글자를
# 담되 명령 구분자만 뺀 입력이다: 그래도 마커가 나오면 원인이 구분자가
# 아니라는 뜻이라 confidence를 낮춘다.
CMD_METACHAR_PAYLOADS = (";", "|", "`")


def _cmd_marker(a: int, b: int) -> str:
    return f"CMDPROBE{a}x{b}IS{a * b}"


def _cmd_expr(a: int, b: int) -> str:
    """페이로드 문자열 자체에는 계산된 값이 없다 — 셸 산술식만 있다."""
    return f"echo CMDPROBE{a}x{b}IS$(( {a} * {b} ))"


def _cmd_attack_value(base_value: str, metachar: str, a: int, b: int) -> str:
    if metachar == "`":
        return f"{base_value}`{_cmd_expr(a, b)}`"
    return f"{base_value} {metachar} {_cmd_expr(a, b)}"


def _cmd_control_value(base_value: str, a: int, b: int) -> str:
    """공격과 같은 글자를 담되 명령 구분자가 없다. 문자열이 그대로 반사돼도
    산술식은 미평가 텍스트로만 남아야 한다."""
    return f"{base_value} {_cmd_expr(a, b)}"


# --------------------------------------------------------------- JSON body

def _json_set(doc: dict, json_path: str, value) -> None:
    """`$.user.id` 같은 얕은 경로만 지원한다. 배열 인덱스는 지원하지 않는다
    (`_replayer`가 그런 파라미터를 미리 걸러 `unsupported-json-path`로 넘긴다)."""
    path = json_path[2:] if json_path.startswith("$.") else json_path
    keys = [k for k in path.split(".") if k]
    if not keys:
        return
    node = doc
    for k in keys[:-1]:
        node = node.setdefault(k, {})
    node[keys[-1]] = value


def _coerce(value: str, type_: str):
    try:
        if type_ == "int":
            return int(value)
        if type_ == "float":
            return float(value)
        if type_ == "bool":
            return value.lower() in ("1", "true", "yes", "on")
    except ValueError:
        pass
    return value


class InjectionAgent(Agent):
    """정찰 씨앗의 query/body 파라미터를 하나씩 갈아끼워 SQLi·Command
    Injection을 시험한다."""

    name = "injection"
    unit = "parameter"

    def __init__(self, client: AgentHttpClient, *, seeds=(),
                actor: str = "anon") -> None:
        super().__init__(client)
        self.actor = actor
        # injection 대상은 query/body뿐이다 — path는 idor의 몫이다.
        self.seeds = [s for s in seeds
                     if any(p.location in ("query", "body") for p in s.params)]
        self.tested = 0
        self.skipped = 0
        self.skip_reasons: dict[str, int] = {}
        self._reported: set[str] = set()   # finding_id 중복 방지

    def _skip(self, reason: str, n: int = 1) -> None:
        self.skipped += n
        self.skip_reasons[reason] = self.skip_reasons.get(reason, 0) + n

    # -------------------------------------------------------------------- 실행
    def run(self, base: str) -> AgentResult:
        pairs: list[tuple[RequestSeed, RequestParameter]] = []
        for seed in self.seeds:
            targets = [p for p in seed.params if p.location in ("query", "body")]
            if not targets:
                continue
            if seed.method.upper() not in ("GET", "POST"):
                # 타겟은 /login 외 POST에 405를 준다 — 재생해도 검사가 안 된다.
                self._skip("unsupported-method", len(targets))
                continue
            if seed.auth_required and self.actor == "anon":
                # 이 에이전트는 로그인을 하지 않는다. 세션이 필요한 씨앗은
                # "못 찾음"이 아니라 "안 봄"으로 남긴다.
                self._skip("authentication-unavailable", len(targets))
                continue
            pairs.extend((seed, p) for p in targets)

        for i, (seed, param) in enumerate(pairs):
            tested_before = self.tested
            try:
                self._probe_param(seed, param)
            except RequestBudgetExceeded:
                # 기준선만 보낸 뒤 공격/대조 요청의 예산이 바닥난 경우에도
                # _probe_param()은 이미 tested를 올렸을 수 있다. 검사를 끝내지
                # 못한 현재 파라미터는 나머지와 함께 skipped로 집계한다.
                self.tested = tested_before
                self._skip("request-budget-exceeded", len(pairs) - i)
                break

        return self.finish(self.findings, tested=self.tested,
                           skipped=self.skipped, skip_reasons=self.skip_reasons)

    # ------------------------------------------------------------------ 재생
    def _replayer(self, seed: RequestSeed, param: RequestParameter):
        """`(callable, None)` 또는 `(None, skip_reason)`.

        callable은 `value -> HttpExchange`다 — 씨앗을 그대로 재생하되 `param`
        하나만 `value`로 바꾸고 나머지는 보존한다."""
        if param.location == "query":
            if seed.method.upper() == "POST":
                ct = self._body_content_type(seed)
                if ct not in ("", "application/x-www-form-urlencoded",
                              "application/json"):
                    return (None, "unsupported-content-type")
            return (lambda value, note="": self._replay_query(seed, param, value, note),
                    None)

        ct = self._body_content_type(seed)
        if ct in ("", "application/x-www-form-urlencoded"):
            return (lambda value, note="": self._replay_form(seed, param, value, note),
                    None)
        if ct == "application/json":
            if "[" in (param.json_path or ""):
                return (None, "unsupported-json-path")   # 배열 경로는 미지원
            return (lambda value, note="": self._replay_json(seed, param, value, note),
                    None)
        return (None, "unsupported-content-type")

    def _replay_query(self, seed: RequestSeed, param: RequestParameter,
                      value: str, note: str):
        parts = urlsplit(seed.url)
        pairs = parse_qsl(parts.query, keep_blank_values=True)
        replaced = False
        new_pairs = []
        for k, v in pairs:
            if not replaced and k == param.name:
                new_pairs.append((k, value))
                replaced = True
            else:
                new_pairs.append((k, v))
        if not replaced:
            new_pairs.append((param.name, value))
        url = urlunsplit((parts.scheme, parts.netloc, parts.path,
                          urlencode(new_pairs), parts.fragment))
        if seed.method.upper() == "POST":
            # 쿼리 파라미터가 있는 POST 씨앗 — 몸통은 원래 값 그대로 보존한다.
            ct = self._body_content_type(seed)
            if ct == "application/json":
                body = self._render_json_body(seed)
            else:
                body = self._render_form_body(seed)
            headers = ({"Content-Type": seed.body_content_type}
                       if seed.body_content_type else None)
            return self.client.post(url, actor=self.actor,
                                    headers=headers, body=body, note=note)
        return self.client.get(url, actor=self.actor, note=note)

    def _replay_form(self, seed: RequestSeed, param: RequestParameter,
                     value: str, note: str):
        body_params = [p for p in seed.params if p.location == "body"]
        pairs = []
        replaced = False
        for p in body_params:
            if p.name == param.name and not replaced:
                pairs.append((p.name, value))
                replaced = True
            else:
                pairs.append((p.name, p.value))
        return self.client.post(seed.url, actor=self.actor,
                                body=urlencode(pairs), note=note)

    def _replay_json(self, seed: RequestSeed, param: RequestParameter,
                     value: str, note: str):
        body_params = [p for p in seed.params if p.location == "body"]
        doc: dict = {}
        for p in body_params:
            path = p.json_path or f"$.{p.name}"
            if p is param:
                _json_set(doc, path, value)     # 페이로드는 항상 원문 문자열
            else:
                _json_set(doc, path, _coerce(p.value, p.type))
        return self.client.post(seed.url, actor=self.actor,
                                headers={"Content-Type": "application/json"},
                                body=json.dumps(doc), note=note)

    def _render_form_body(self, seed: RequestSeed) -> str:
        body_params = [p for p in seed.params if p.location == "body"]
        return urlencode([(p.name, p.value) for p in body_params])

    def _render_json_body(self, seed: RequestSeed) -> str:
        body_params = [p for p in seed.params if p.location == "body"]
        doc: dict = {}
        for p in body_params:
            _json_set(doc, p.json_path or f"$.{p.name}",
                      _coerce(p.value, p.type))
        return json.dumps(doc)

    @staticmethod
    def _body_content_type(seed: RequestSeed) -> str:
        return (seed.body_content_type or "").split(";")[0].strip().lower()

    # -------------------------------------------------------------------- 판정
    def _probe_param(self, seed: RequestSeed, param: RequestParameter) -> None:
        if not param.value:
            # 빈 값은 기준선이 없다 — 대조할 "정상"이 없으므로 검사할 수 없다.
            self._skip("missing-baseline-value")
            return

        replay, reason = self._replayer(seed, param)
        if replay is None:
            self._skip(reason)
            return

        baseline = replay(param.value,
                          note=f"기준선: {seed.template} {param.name} 원래 값으로 재생")
        if baseline.status is None:
            # 전송 자체가 실패했다 — "안 취약함"이 아니라 "판단 불가".
            self._skip("baseline-unavailable")
            return
        if baseline.status == 405:
            # 타겟이 이 method/경로 조합 자체를 받지 않는다 (예: 통제 앱은
            # POST를 /login에만 허용한다 — AGENT_GUIDE.md §8). 대조할 "정상"이
            # 없으므로 검사할 수 없다.
            self._skip("method-not-allowed")
            return

        self.tested += 1
        if self._test_sqli(seed, param, replay, baseline):
            return
        self._test_cmdi(seed, param, replay, baseline)

    def _test_sqli(self, seed: RequestSeed, param: RequestParameter,
                   replay, baseline) -> bool:
        """오류 기반 SQLi: 홑따옴표로 구문을 깨고 `--` 주석으로 복구되는지 본다."""
        if _has_sql_marker(baseline.response_excerpt):
            return False   # 기준선부터 오류 문구가 있으면 대조가 안 된다

        attack = replay(param.value + SQLI_ATTACK_SUFFIX,
                        note=f"공격: {param.name}에 홑따옴표 하나만 추가")
        if attack.status is None or not _has_sql_marker(attack.response_excerpt):
            return False   # 500 한 번, 검증 오류 하나만으로는 판정하지 않는다

        control = replay(param.value + SQLI_RECOVERY_SUFFIX,
                         note=f"대조: {param.name}를 `--` 주석으로 구문 복구")
        recovered = (control.status == baseline.status
                    and not _has_sql_marker(control.response_excerpt))

        # 오류 문구 하나만으로는 SQLi 증거가 아니다. 주석을 붙였을 때 정상
        # 기준선으로 복구되어야 구문 경계를 실제로 건드렸다고 판정할 수 있다.
        if not recovered:
            return False

        finding_id = f"sqli-error-based-{seed.template}-{param.name}"
        if finding_id in self._reported:
            return True
        self._reported.add(finding_id)

        self.findings.append(AgentFinding(
            scanner=f"agent:{self.name}",
            finding_id=finding_id,
            name=f"{seed.template}의 {param.name} 파라미터가 SQL Injection에 취약함",
            severity=Severity.CRITICAL,
            confidence=Confidence.CONFIRMED,
            category="injection",
            matched_at=attack.url,
            description=(
                f"{param.name} 파라미터에 홑따옴표 하나만 추가하면 SQL 구문 오류가 "
                "발생하고, 응답에 DB 오류 문구가 그대로 드러난다."
            ),
            tags=["injection", "sqli", "error-based"],
            evidence=Evidence(
                baseline_index=0,
                rationale=(
                    f"기준선({baseline.status})에는 SQL 오류 문구가 없고, "
                    f"{param.name}에 홑따옴표 하나만 추가한 공격({attack.status})에서 "
                    "SQL 오류 문구가 나타났다. "
                    f"`--` 주석으로 구문을 닫은 대조 요청은 오류 없이 기준선과 "
                    f"같은 상태({control.status})로 복구되어, 구문 자체가 깨진 "
                    "것이지 우연한 서버 오류가 아님을 보여준다."
                ),
                exchanges=[baseline, attack, control],
            ),
            agent_data={self.name: Probe(
                strategy="error-based-sqli",
                target=param.name,
                target_kind="parameter",
                attempts=3,
                hits=[attack.url],
                actors=[self.actor],
                withheld=["union-based-extraction", "stacked-write",
                         "time-based-blind", "data-extraction"],
                extra={"seed": seed.template, "baseline_value": param.value},
            )},
        ))
        return True

    def _test_cmdi(self, seed: RequestSeed, param: RequestParameter,
                   replay, baseline) -> bool:
        """마커+연산 기반 Command Injection: 반사가 아니라 실행됐는지를 본다.

        `a*b`처럼 셸이 계산해야만 나오는 값을 마커로 쓴다. 취약하지 않은
        (입력을 그대로 반사만 하는) 앱은 페이로드 문자열을 돌려줄 뿐 계산
        결과는 만들 수 없다."""
        a, b = 6, 13
        marker = _cmd_marker(a, b)
        if marker in baseline.response_excerpt:
            return False   # 우연히 기준선에 마커가 있으면 판정 불가

        for metachar in CMD_METACHAR_PAYLOADS:
            attack_value = _cmd_attack_value(param.value, metachar, a, b)
            attack = replay(attack_value,
                            note=f"공격: {param.name}에 `{metachar}` 명령 구분자 삽입")
            if attack.status is None or marker not in attack.response_excerpt:
                continue

            control_value = _cmd_control_value(param.value, a, b)
            control = replay(control_value,
                             note=f"대조: 같은 문자열이되 `{metachar}` 명령 구분자는 없음")
            recovered = marker not in control.response_excerpt

            finding_id = f"cmdi-marker-based-{seed.template}-{param.name}"
            if finding_id in self._reported:
                return True
            self._reported.add(finding_id)

            self.findings.append(AgentFinding(
                scanner=f"agent:{self.name}",
                finding_id=finding_id,
                name=f"{seed.template}의 {param.name} 파라미터가 Command Injection에 취약함",
                severity=Severity.CRITICAL,
                confidence=Confidence.CONFIRMED if recovered else Confidence.FIRM,
                category="injection",
                matched_at=attack.url,
                description=(
                    f"{param.name} 파라미터에 `{metachar}` 명령 구분자를 넣으면 뒤에 "
                    "붙인 산술식이 실제로 계산되어 응답에 나타난다 — 입력이 그대로 "
                    "반사된 것이 아니라 셸이 실행한 결과다."
                ),
                tags=["injection", "command-injection", "os-command-injection"],
                evidence=Evidence(
                    baseline_index=0,
                    rationale=(
                        f"공격 페이로드는 `{a} * {b}`를 계산하는 셸 산술식을 담고 "
                        f"있고, 페이로드 문자열 자체에는 계산 결과({a * b})가 없다. "
                        f"그런데 응답에 '{marker}'가 그대로 나타났다 — 문자열이 "
                        "반사된 게 아니라 실행됐다는 뜻이다. " + (
                            f"같은 문자열에서 명령 구분자 `{metachar}`만 뺀 대조 "
                            "요청에서는 마커가 사라져, 구분자가 원인임을 보여준다."
                            if recovered else
                            "대조 요청에서도 마커가 남아 원인을 완전히 확정하지는 "
                            "못했다."
                        )
                    ),
                    exchanges=[baseline, attack, control],
                ),
                agent_data={self.name: Probe(
                    strategy="marker-based-cmdi",
                    target=param.name,
                    target_kind="parameter",
                    attempts=3,
                    hits=[attack.url],
                    actors=[self.actor],
                    withheld=["reverse-shell", "file-write", "file-read",
                             "data-exfiltration", "persistence",
                             "long-sleep-timing", "oob-callback"],
                    extra={"seed": seed.template, "metachar": metachar,
                          "marker": marker},
                )},
            ))
            return True
        return False


def main(argv: list[str]) -> int:
    from .recon import ReconAgent

    base = argv[1] if len(argv) > 1 else "http://127.0.0.1:8080"
    client = AgentHttpClient(allowlist=set(), max_requests=300)
    recon = ReconAgent(client).run(base)
    result = InjectionAgent(client, seeds=recon.request_seeds).run(base)

    cov = result.coverage
    print(f"injection: {cov.tested}건 검사, {cov.skipped}건 건너뜀 {cov.skip_reasons}")
    print(f"findings {len(result.findings)}건")
    for f in result.findings:
        print(f"  [{f.severity.value}/{f.confidence.value}] {f.finding_id} @ {f.matched_at}")
        print(f"      {f.description}")

    done = result.completion
    if done.blocked:
        print(f"\n안전장치가 거부한 요청 {len(done.blocked)}건:")
        for url, why in done.blocked:
            print(f"  {url} — {why}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

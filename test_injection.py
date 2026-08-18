"""Behaviour of the injection agent. Copied from `tests/test_recon.py`.

The pattern: drive the agent with a `FakeClient` (no server, no sockets), then
assert on the `AgentResult` it returns. `tests/test_agent_contract.py` already
checks that the result obeys the contract, so here we only check what *this*
agent is supposed to find — and, just as importantly, what it must NOT find
(`/lookup` is a deliberate false-positive trap, AGENT_GUIDE.md §8).

The vulnerable app has no Command Injection endpoint (only SQL Injection and
IDOR are wired up), so the Command Injection tests build their own FakeClient
fixtures rather than exercising `targets/vulnerable_app/app.py`. This is
called out again in the completion report.
"""

import json
import unittest
from urllib.parse import parse_qsl, urlencode

from dast_harness.agent_kit import (HttpExchange, RequestParameter,
                                    RequestSeed, validate_result)
from dast_harness.agent_kit.injection import (InjectionAgent, _cmd_attack_value,
                                              _cmd_control_value, _cmd_marker)
from dast_harness.safety import TargetNotAuthorizedError
from dast_harness.agent_kit.http import AgentHttpClient, RequestBudgetExceeded

from tests.agent_fakes import ORIGIN, FakeClient

# SQL error text `/search` actually returns (targets/vulnerable_app/app.py
# `SQL_ERROR`), reused here so the fixture matches the real target's shape.
SQL_ERROR_TEXT = (
    "You have an error in your SQL syntax; check the manual that corresponds "
    'to your MySQL server version for the right syntax to use near "\'%invoice\'%" '
    "at line 1"
)


class BodyAwareFakeClient(FakeClient):
    """`FakeClient` looks up POST responses by URL only, which cannot express a
    body-based SQLi differential (baseline/attack/control all hit the same
    URL). This variant keys canned POST responses by `(url, body)` instead,
    falling back to the plain URL table when a body isn't registered."""

    def __init__(self, pages=None, *, post_body_pages=None):
        super().__init__(pages)
        self.post_body_pages = dict(post_body_pages or {})

    def post(self, url, **kw):
        key = (url, kw.get("body"))
        if key not in self.post_body_pages:
            return super().post(url, **kw)
        self.request_count += 1
        self.sent.append(("POST", url, kw.get("actor", "anon"), kw.get("body")))
        status, content_type, body = self.post_body_pages[key]
        return HttpExchange(
            method="POST", url=url, status=status, actor=kw.get("actor", "anon"),
            request_body=kw.get("body"),
            response_headers={"Content-Type": content_type},
            response_excerpt=body, note=kw.get("note", ""))


def _query_seed(path, param_name, value, *, method="GET", auth_required=False):
    return RequestSeed(
        method=method, url=f"{ORIGIN}{path}?{param_name}={value}",
        params=(RequestParameter(name=param_name, location="query",
                                 value=value, type="string"),),
        observed_status=200, auth_required=auth_required)


# ------------------------------------------------------------- SQLi: /search

class SqlInjectionPositiveTest(unittest.TestCase):
    """`/search?q=` is the control target's real SQLi (AGENT_GUIDE.md §8):
    an unbalanced quote breaks the query and a `--` comment repairs it."""

    def setUp(self):
        pages = {
            f"{ORIGIN}/search?q=invoice": (200, "text/html", "<h1>3 results for invoice</h1>"),
            f"{ORIGIN}/search?q=invoice%27": (500, "text/plain", SQL_ERROR_TEXT),
            f"{ORIGIN}/search?q=invoice%27--": (200, "text/html", "<h1>3 results for invoice</h1>"),
        }
        seed = _query_seed("/search", "q", "invoice")
        self.result = InjectionAgent(FakeClient(pages), seeds=[seed]).run(ORIGIN)

    def test_validates(self):
        self.assertEqual(validate_result(self.result), [])

    def test_finds_confirmed_sqli(self):
        self.assertEqual(len(self.result.findings), 1)
        f = self.result.findings[0]
        self.assertIn("sqli", f.finding_id)
        self.assertEqual(f.category, "injection")
        self.assertEqual(f.confidence.value, "confirmed")
        self.assertEqual(f.scanner, "agent:injection")

    def test_evidence_is_baseline_attack_control(self):
        ev = self.result.findings[0].evidence
        self.assertEqual(ev.baseline_index, 0)
        self.assertEqual(len(ev.exchanges), 3)
        baseline, attack, control = ev.exchanges
        self.assertEqual(baseline.url, f"{ORIGIN}/search?q=invoice")
        self.assertEqual(attack.url, f"{ORIGIN}/search?q=invoice%27")
        self.assertEqual(control.url, f"{ORIGIN}/search?q=invoice%27--")
        self.assertTrue(ev.rationale.strip())

    def test_probe_shape(self):
        probe = self.result.findings[0].agent_data["injection"]
        self.assertEqual(probe.strategy, "error-based-sqli")
        self.assertEqual(probe.target, "q")
        self.assertEqual(probe.target_kind, "parameter")
        self.assertTrue(probe.withheld)   # data extraction etc. never attempted

    def test_coverage_counts_the_parameter(self):
        self.assertEqual(self.result.coverage.unit, "parameter")
        self.assertEqual(self.result.coverage.tested, 1)
        self.assertEqual(self.result.coverage.findings, 1)


class LookupFalsePositiveTest(unittest.TestCase):
    """`/lookup` is a deliberate trap: quotes are handled correctly and it
    never echoes a SQL error, so no finding may appear here."""

    def test_normal_lookup_produces_no_finding(self):
        pages = {
            f"{ORIGIN}/lookup?q=alice": (200, "text/html", "<h1>1 people matching alice</h1>"),
            f"{ORIGIN}/lookup?q=alice%27": (200, "text/html", "<h1>0 people matching alice'</h1>"),
            f"{ORIGIN}/lookup?q=alice%27--": (200, "text/html", "<h1>0 people matching alice'--</h1>"),
        }
        seed = _query_seed("/lookup", "q", "alice")
        result = InjectionAgent(FakeClient(pages), seeds=[seed]).run(ORIGIN)
        self.assertEqual(result.findings, [])
        self.assertEqual(validate_result(result), [])

    def test_generic_500_without_sql_marker_is_not_flagged(self):
        """A single unrelated 500 (long input, whatever) must not be enough —
        the response body must actually carry a DB error signature."""
        pages = {
            f"{ORIGIN}/lookup?q=alice": (200, "text/html", "<h1>1 people matching alice</h1>"),
            f"{ORIGIN}/lookup?q=alice%27": (500, "text/plain", "Internal Server Error: lookup failed"),
            f"{ORIGIN}/lookup?q=alice%27--": (200, "text/html", "<h1>0 people matching alice'--</h1>"),
        }
        seed = _query_seed("/lookup", "q", "alice")
        result = InjectionAgent(FakeClient(pages), seeds=[seed]).run(ORIGIN)
        self.assertEqual(result.findings, [])
        # It was still examined, not skipped — the agent looked and found nothing.
        self.assertEqual(result.coverage.tested, 1)

    def test_sql_marker_without_comment_recovery_is_not_flagged(self):
        pages = {
            f"{ORIGIN}/lookup?q=alice": (200, "text/html", "<h1>ok</h1>"),
            f"{ORIGIN}/lookup?q=alice%27": (500, "text/plain", SQL_ERROR_TEXT),
            f"{ORIGIN}/lookup?q=alice%27--": (500, "text/plain", SQL_ERROR_TEXT),
        }
        seed = _query_seed("/lookup", "q", "alice")
        result = InjectionAgent(FakeClient(pages), seeds=[seed]).run(ORIGIN)
        self.assertEqual(result.findings, [])
        self.assertEqual(result.coverage.tested, 1)


# --------------------------------------------------------- Command Injection

class CommandInjectionPositiveTest(unittest.TestCase):
    """No real endpoint exists for this yet (see module docstring), so the
    fixture is invented here. The marker is an arithmetic result (`a*b`) that
    only a shell can produce — a naive echo of the raw input can never
    contain it, which is what separates "executed" from "merely reflected"."""

    def setUp(self):
        self.a, self.b = 6, 13
        self.marker = _cmd_marker(self.a, self.b)
        base_url = f"{ORIGIN}/ping?host=127.0.0.1"
        attack_value = _cmd_attack_value("127.0.0.1", ";", self.a, self.b)
        attack_url = f"{ORIGIN}/ping?" + urlencode([("host", attack_value)])
        control_value = _cmd_control_value("127.0.0.1", self.a, self.b)
        control_url = f"{ORIGIN}/ping?" + urlencode([("host", control_value)])

        pages = {
            base_url: (200, "text/plain", "pong from 127.0.0.1"),
            # Vulnerable: the shell evaluates the arithmetic and its stdout
            # lands in the response.
            attack_url: (200, "text/plain", f"pong from 127.0.0.1\n{self.marker}\n"),
            # Control: same characters, no command separator — never executes.
            control_url: (200, "text/plain", f"pong from {control_value}"),
        }
        seed = _query_seed("/ping", "host", "127.0.0.1")
        self.result = InjectionAgent(FakeClient(pages), seeds=[seed]).run(ORIGIN)

    def test_finds_confirmed_command_injection(self):
        self.assertEqual(len(self.result.findings), 1)
        f = self.result.findings[0]
        self.assertIn("cmdi", f.finding_id)
        self.assertEqual(f.category, "injection")
        self.assertIn("command-injection", f.tags)
        self.assertEqual(f.confidence.value, "confirmed")

    def test_probe_withholds_dangerous_extensions(self):
        probe = self.result.findings[0].agent_data["injection"]
        self.assertEqual(probe.strategy, "marker-based-cmdi")
        for dangerous in ("reverse-shell", "file-write", "data-exfiltration"):
            self.assertIn(dangerous, probe.withheld)

    def test_validates(self):
        self.assertEqual(validate_result(self.result), [])


class CommandInjectionNegativeTest(unittest.TestCase):
    """A handler that reflects the raw value verbatim (never executes it)
    must not be flagged — the payload text alone can't fake the marker."""

    def test_verbatim_reflection_is_not_flagged(self):
        a, b = 6, 13
        base_url = f"{ORIGIN}/ping?host=127.0.0.1"
        attack_value = _cmd_attack_value("127.0.0.1", ";", a, b)
        attack_url = f"{ORIGIN}/ping?" + urlencode([("host", attack_value)])
        pages = {
            base_url: (200, "text/plain", "pong from 127.0.0.1"),
            # Safe: input is echoed back exactly as sent, never evaluated.
            attack_url: (200, "text/plain", f"pong from {attack_value}"),
        }
        seed = _query_seed("/ping", "host", "127.0.0.1")
        result = InjectionAgent(FakeClient(pages), seeds=[seed]).run(ORIGIN)
        self.assertEqual(result.findings, [])
        self.assertEqual(result.coverage.tested, 1)


# ------------------------------------------------------------- request shape

class RequestReplayTest(unittest.TestCase):
    """One parameter changes at a time; everything else survives the replay."""

    def test_get_query_preserves_other_params(self):
        pages = {
            f"{ORIGIN}/search?q=invoice&sort=asc": (200, "text/html", "<h1>ok</h1>"),
            f"{ORIGIN}/search?q=invoice%27&sort=asc": (500, "text/plain", SQL_ERROR_TEXT),
            f"{ORIGIN}/search?q=invoice%27--&sort=asc": (200, "text/html", "<h1>ok</h1>"),
        }
        seed = RequestSeed(
            method="GET", url=f"{ORIGIN}/search?q=invoice&sort=asc",
            params=(RequestParameter(name="q", location="query", value="invoice"),
                    RequestParameter(name="sort", location="query", value="asc")),
            observed_status=200)
        client = FakeClient(pages)
        result = InjectionAgent(client, seeds=[seed]).run(ORIGIN)

        self.assertEqual(len(result.findings), 1)
        for _method, url, _actor, _body in client.sent:
            self.assertIn("sort=asc", url)     # bystander query param untouched

    def test_post_form_changes_only_the_target_field(self):
        baseline_body = urlencode([("id", "7"), ("token", "abc123")])
        attack_body = urlencode([("id", "7'"), ("token", "abc123")])
        control_body = urlencode([("id", "7'--"), ("token", "abc123")])
        url = f"{ORIGIN}/query"
        client = BodyAwareFakeClient(post_body_pages={
            (url, baseline_body): (200, "text/html", "<h1>ok</h1>"),
            (url, attack_body): (500, "text/plain", SQL_ERROR_TEXT),
            (url, control_body): (200, "text/html", "<h1>ok</h1>"),
        })
        seed = RequestSeed(
            method="POST", url=url,
            params=(RequestParameter(name="id", location="body", value="7"),
                    RequestParameter(name="token", location="body", value="abc123")),
            body_content_type="application/x-www-form-urlencoded")
        result = InjectionAgent(client, seeds=[seed]).run(ORIGIN)

        self.assertEqual(len(result.findings), 1)
        baseline_fields = {"id": "7", "token": "abc123"}
        seen_ids = set()
        for _method, _url, _actor, body in client.sent:
            fields = dict(parse_qsl(body))
            # Every replay changes at most one field from the baseline —
            # never both at once, regardless of which parameter is the
            # current target.
            differing = [k for k in baseline_fields if fields.get(k) != baseline_fields[k]]
            self.assertLessEqual(len(differing), 1, f"more than one field changed: {fields}")
            if not differing or differing == ["id"]:
                seen_ids.add(fields["id"])
        self.assertEqual(seen_ids, {"7", "7'", "7'--"})    # target changed each time

    def test_json_body_changes_only_the_target_field(self):
        """`구현한 경우 JSON body 재생` — only the target field's value moves;
        the sibling field's value and type-coercion are untouched."""
        url = f"{ORIGIN}/query.json"
        pages = {}   # no differential needed; this test checks request shape
        client = FakeClient(pages)
        seed = RequestSeed(
            method="POST", url=url,
            params=(RequestParameter(name="id", location="body", value="7",
                                     type="string", json_path="$.id"),
                    RequestParameter(name="mode", location="body", value="fast",
                                     type="string", json_path="$.mode")),
            body_content_type="application/json")
        InjectionAgent(client, seeds=[seed]).run(ORIGIN)

        baseline_fields = {"id": "7", "mode": "fast"}
        bodies = [json.loads(body) for _m, _u, _a, body in client.sent]
        self.assertGreaterEqual(len(bodies), 1)
        ids = set()
        for doc in bodies:
            differing = [k for k in baseline_fields if doc.get(k) != baseline_fields[k]]
            self.assertLessEqual(len(differing), 1, f"more than one field changed: {doc}")
            if not differing or differing == ["id"]:
                ids.add(doc["id"])
        # SQLi's baseline and attack requests must be in there (no recovery
        # request is sent because this fixture never shows a SQL error — the
        # Command Injection probe also runs and contributes its own no-hit
        # attempts, which is fine too).
        self.assertLessEqual({"7", "7'"}, ids)

    def test_post_query_preserves_json_body(self):
        url = f"{ORIGIN}/query.json?q=invoice"
        client = FakeClient({})
        seed = RequestSeed(
            method="POST", url=url,
            params=(RequestParameter(name="q", location="query", value="invoice"),
                    RequestParameter(name="id", location="body", value="7",
                                     type="int", json_path="$.id"),
                    RequestParameter(name="mode", location="body", value="fast",
                                     json_path="$.mode")),
            body_content_type="application/json; charset=utf-8")

        InjectionAgent(client, seeds=[seed]).run(ORIGIN)

        self.assertGreaterEqual(len(client.sent), 1)
        query_probe_requests = [sent for sent in client.sent
                                if sent[1] != seed.url]
        self.assertGreaterEqual(len(query_probe_requests), 1)
        for method, _url, _actor, body in query_probe_requests:
            self.assertEqual(method, "POST")
            self.assertEqual(json.loads(body), {"id": 7, "mode": "fast"})


# ------------------------------------------------------------------ coverage

class SkipReasonTest(unittest.TestCase):
    def test_empty_baseline_value_is_skipped(self):
        seed = RequestSeed(
            method="GET", url=f"{ORIGIN}/search?q=",
            params=(RequestParameter(name="q", location="query", value=""),),
            observed_status=200)
        result = InjectionAgent(FakeClient({}), seeds=[seed]).run(ORIGIN)
        self.assertEqual(result.coverage.tested, 0)
        self.assertEqual(result.coverage.skipped, 1)
        self.assertEqual(result.coverage.skip_reasons, {"missing-baseline-value": 1})

    def test_unsupported_content_type_is_skipped(self):
        seed = RequestSeed(
            method="POST", url=f"{ORIGIN}/upload",
            params=(RequestParameter(name="file", location="body", value="x"),),
            body_content_type="multipart/form-data; boundary=x")
        result = InjectionAgent(FakeClient({}), seeds=[seed]).run(ORIGIN)
        self.assertEqual(result.coverage.skip_reasons, {"unsupported-content-type": 1})

    def test_unsupported_method_is_skipped(self):
        seed = RequestSeed(
            method="PUT", url=f"{ORIGIN}/api/thing?x=1",
            params=(RequestParameter(name="x", location="query", value="1"),),
            observed_status=200)
        result = InjectionAgent(FakeClient({}), seeds=[seed]).run(ORIGIN)
        self.assertEqual(result.coverage.skip_reasons, {"unsupported-method": 1})

    def test_method_not_allowed_response_is_skipped_not_tested(self):
        # Mirrors the control target: POST is only accepted at /login
        # (AGENT_GUIDE.md §8) — everything else 405s.
        pages = {f"{ORIGIN}/admin/": (405, "text/plain", "405 Method Not Allowed")}
        seed = RequestSeed(
            method="POST", url=f"{ORIGIN}/admin/",
            params=(RequestParameter(name="username", location="body", value="admin"),),
            body_content_type="application/x-www-form-urlencoded")
        result = InjectionAgent(FakeClient({}, post_pages=pages), seeds=[seed]).run(ORIGIN)
        self.assertEqual(result.coverage.tested, 0)
        self.assertEqual(result.coverage.skip_reasons, {"method-not-allowed": 1})

    def test_auth_required_without_a_session_is_skipped(self):
        seed = _query_seed("/api/secret", "id", "1", auth_required=True)
        result = InjectionAgent(FakeClient({}), seeds=[seed]).run(ORIGIN)
        self.assertEqual(result.coverage.tested, 0)
        self.assertEqual(result.coverage.skip_reasons, {"authentication-unavailable": 1})

    def test_budget_exhausted_mid_probe_is_skipped_not_also_tested(self):
        class OneRequestClient(FakeClient):
            def get(self, url, **kw):
                if self.request_count >= 1:
                    raise RequestBudgetExceeded("test budget exhausted")
                return super().get(url, **kw)

        pages = {
            f"{ORIGIN}/search?q=invoice": (200, "text/html", "<h1>ok</h1>"),
        }
        seed = _query_seed("/search", "q", "invoice")
        result = InjectionAgent(OneRequestClient(pages), seeds=[seed]).run(ORIGIN)

        self.assertEqual(result.coverage.tested, 0)
        self.assertEqual(result.coverage.skipped, 1)
        self.assertEqual(result.coverage.skip_reasons,
                         {"request-budget-exceeded": 1})


class DuplicateFindingTest(unittest.TestCase):
    def test_the_same_seed_twice_only_reports_once(self):
        pages = {
            f"{ORIGIN}/search?q=invoice": (200, "text/html", "<h1>3 results for invoice</h1>"),
            f"{ORIGIN}/search?q=invoice%27": (500, "text/plain", SQL_ERROR_TEXT),
            f"{ORIGIN}/search?q=invoice%27--": (200, "text/html", "<h1>3 results for invoice</h1>"),
        }
        seed = _query_seed("/search", "q", "invoice")
        result = InjectionAgent(FakeClient(pages), seeds=[seed, seed]).run(ORIGIN)
        self.assertEqual(len(result.findings), 1)


# -------------------------------------------------------------------- safety

class ScopeTest(unittest.TestCase):
    def test_out_of_scope_seed_is_blocked_not_swallowed(self):
        # A real client (not the fake) so the safety check actually runs.
        # example.com resolves the "not localhost" branch instantly, no
        # network call is made before the rejection.
        client = AgentHttpClient(allowlist=set(), max_requests=50)
        seed = _query_seed_absolute("http://example.com/search", "q", "invoice")
        with self.assertRaises(TargetNotAuthorizedError):
            InjectionAgent(client, seeds=[seed]).run("http://example.com")
        self.assertTrue(client.blocked)   # the rejection is on record, not silent


def _query_seed_absolute(url_no_query, name, value):
    return RequestSeed(
        method="GET", url=f"{url_no_query}?{name}={value}",
        params=(RequestParameter(name=name, location="query", value=value),),
        observed_status=200)


if __name__ == "__main__":
    unittest.main()

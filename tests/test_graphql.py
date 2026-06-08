"""Unit tests for the GraphQL introspection and misconfiguration module."""

import json
import unittest
from unittest.mock import MagicMock

from scanner.modules.graphql import GraphQLScanner


def _make_response(body, status=200, content_type="application/json", headers=None):
    resp = MagicMock()
    resp.text = body if isinstance(body, str) else json.dumps(body)
    resp.status_code = status
    resp.headers = {"Content-Type": content_type}
    if headers:
        resp.headers.update(headers)
    try:
        resp.json.return_value = json.loads(resp.text)
    except Exception:
        resp.json.side_effect = ValueError("not json")
    return resp


def _scanner():
    return GraphQLScanner(MagicMock(), {})


# ---------------------------------------------------------------------------
# Introspection enabled
# ---------------------------------------------------------------------------

class TestGraphQLIntrospection(unittest.TestCase):

    def test_introspection_open_detected(self):
        """Full __schema response → high confidence finding."""
        scanner = _scanner()
        schema_resp = _make_response({
            "data": {
                "__schema": {
                    "queryType": {"name": "Query"},
                    "types": [{"name": "Query", "kind": "OBJECT"}] * 42,
                }
            }
        })
        # GET (IDE check) → 404; POST (introspection) → schema
        scanner.http.get.return_value = _make_response("", status=404)
        scanner.http.post.return_value = schema_resp

        findings = scanner.scan_parameter("http://target.local/graphql", "GET", {}, "q")
        intr = [f for f in findings if "Introspection" in f.vuln_type]
        self.assertEqual(len(intr), 1)
        self.assertEqual(intr[0].confidence, "high")
        self.assertIn("42", intr[0].evidence)

    def test_no_introspection_no_finding(self):
        """Server returns errors for __schema → no finding."""
        scanner = _scanner()
        scanner.http.get.return_value = _make_response("", status=404)
        scanner.http.post.return_value = _make_response(
            {"errors": [{"message": "Introspection is disabled"}]}
        )
        findings = scanner.scan_parameter("http://target.local/graphql", "GET", {}, "q")
        intr = [f for f in findings if "Introspection" in f.vuln_type]
        self.assertEqual(len(intr), 0)

    def test_non_json_response_no_crash(self):
        """HTML response does not crash the scanner."""
        scanner = _scanner()
        scanner.http.get.return_value = _make_response("<html>Not Found</html>", status=404, content_type="text/html")
        scanner.http.post.return_value = _make_response("<html>error</html>", status=400, content_type="text/html")
        findings = scanner.scan_parameter("http://target.local/graphql", "GET", {}, "q")
        self.assertIsInstance(findings, list)

    def test_none_get_response_handled(self):
        """None response on GET does not crash."""
        scanner = _scanner()
        scanner.http.get.return_value = None
        findings = scanner.scan_parameter("http://target.local/graphql", "GET", {}, "q")
        self.assertEqual(findings, [])


# ---------------------------------------------------------------------------
# IDE exposure
# ---------------------------------------------------------------------------

class TestGraphQLIDE(unittest.TestCase):

    def test_graphiql_exposed(self):
        """GraphiQL in GET response → medium confidence IDE finding."""
        scanner = _scanner()
        scanner.http.get.return_value = _make_response(
            "<html><title>GraphiQL</title><div id='graphiql'></div></html>",
            status=200, content_type="text/html",
        )
        scanner.http.post.return_value = _make_response(
            {"errors": [{"message": "no schema"}]}, status=400,
        )
        findings = scanner.scan_parameter("http://target.local/graphql", "GET", {}, "q")
        ide = [f for f in findings if "IDE" in f.vuln_type]
        self.assertEqual(len(ide), 1)
        self.assertEqual(ide[0].confidence, "medium")

    def test_playground_exposed(self):
        """Apollo/GraphQL Playground fingerprint triggers IDE finding."""
        scanner = _scanner()
        scanner.http.get.return_value = _make_response(
            "<html>GraphQL Playground</html>", status=200, content_type="text/html",
        )
        scanner.http.post.return_value = _make_response({"errors": []}, status=400)
        findings = scanner.scan_parameter("http://target.local/graphql", "GET", {}, "q")
        ide = [f for f in findings if "IDE" in f.vuln_type]
        self.assertGreater(len(ide), 0)


# ---------------------------------------------------------------------------
# Batch queries
# ---------------------------------------------------------------------------

class TestGraphQLBatch(unittest.TestCase):

    def test_batch_accepted(self):
        """Array response to batch request → Batch Queries finding."""
        scanner = _scanner()
        schema_resp = _make_response({
            "data": {
                "__schema": {
                    "queryType": {"name": "Query"},
                    "types": [{"name": "T", "kind": "OBJECT"}],
                }
            }
        })
        batch_resp = _make_response([
            {"data": {"__typename": "Query"}},
            {"data": {"__typename": "Query"}},
        ])
        scanner.http.get.return_value = _make_response("", status=404)
        # POST calls: introspection → schema, batch → array, suggestions → errors
        call_count = [0]
        def post_side(url, data=None, headers=None):
            call_count[0] += 1
            if call_count[0] == 1:
                return schema_resp
            if call_count[0] == 2:
                return batch_resp
            return _make_response({"errors": []})
        scanner.http.post.side_effect = post_side
        findings = scanner.scan_parameter("http://target.local/graphql", "GET", {}, "q")
        batch = [f for f in findings if "Batch" in f.vuln_type]
        self.assertEqual(len(batch), 1)

    def test_batch_not_accepted_no_finding(self):
        """Non-array response to batch → no batch finding."""
        scanner = _scanner()
        scanner.http.get.return_value = _make_response("", status=404)
        scanner.http.post.return_value = _make_response(
            {"errors": [{"message": "batch not supported"}]}, status=400
        )
        findings = scanner.scan_parameter("http://target.local/graphql", "GET", {}, "q")
        batch = [f for f in findings if "Batch" in f.vuln_type]
        self.assertEqual(len(batch), 0)


# ---------------------------------------------------------------------------
# Field suggestions
# ---------------------------------------------------------------------------

class TestGraphQLSuggestions(unittest.TestCase):

    def test_suggestions_detected(self):
        """'Did you mean X?' in errors → Field Suggestion Leak finding."""
        scanner = _scanner()
        schema_resp = _make_response({
            "data": {
                "__schema": {
                    "queryType": {"name": "Query"},
                    "types": [{"name": "T", "kind": "OBJECT"}],
                }
            }
        })
        sug_resp = _make_response({
            "errors": [{"message": "Cannot query field '__typenme'. Did you mean '__typename'?"}]
        }, status=400)
        call_count = [0]
        def post_side(url, data=None, headers=None):
            call_count[0] += 1
            if call_count[0] == 1:
                return schema_resp
            if call_count[0] == 2:
                return _make_response({"data": {}})  # batch not accepted
            return sug_resp
        scanner.http.get.return_value = _make_response("", status=404)
        scanner.http.post.side_effect = post_side
        findings = scanner.scan_parameter("http://target.local/graphql", "GET", {}, "q")
        sug = [f for f in findings if "Suggestion" in f.vuln_type]
        self.assertGreater(len(sug), 0)
        self.assertEqual(sug[0].confidence, "low")


# ---------------------------------------------------------------------------
# Deduplication and multi-endpoint behavior
# ---------------------------------------------------------------------------

class TestGraphQLDedup(unittest.TestCase):

    def test_scans_once_per_base_url(self):
        """GraphQL module only scans once per base URL regardless of param count."""
        scanner = _scanner()
        scanner.http.get.return_value = _make_response("", status=404)
        scanner.http.post.return_value = _make_response({"errors": []})

        findings1 = scanner.scan_parameter("http://t.local/page?a=1", "GET", {"a": "1"}, "a")
        findings2 = scanner.scan_parameter("http://t.local/other?b=2", "GET", {"b": "2"}, "b")

        # Second call should return [] (same base URL already scanned)
        self.assertEqual(findings2, [])

    def test_has_name(self):
        self.assertEqual(GraphQLScanner(MagicMock(), {}).NAME, "graphql")


if __name__ == "__main__":
    unittest.main()

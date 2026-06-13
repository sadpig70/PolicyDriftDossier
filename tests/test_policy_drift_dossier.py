"""Unit tests for PolicyDriftDossier."""

import json
import unittest
from pathlib import Path

from policy_drift_dossier import (
    DeploymentState,
    DiffEngine,
    Ledger,
    PolicyBaseline,
    Report,
    SeverityAggregate,
    evaluate,
    sample_baseline,
    sample_state,
)


class TestPolicyDriftDossier(unittest.TestCase):
    def test_aligned_verdict(self) -> None:
        result = evaluate(sample_baseline(), sample_state("aligned"))
        entry = json.loads(result["json"])
        self.assertEqual(entry["verdict"]["verdict"], "aligned")

    def test_drift_verdict(self) -> None:
        result = evaluate(sample_baseline(), sample_state("drift"))
        entry = json.loads(result["json"])
        self.assertEqual(entry["verdict"]["verdict"], "drift")
        drift_clause = next(c for c in entry["diff"] if c["field"] == "temperature")
        self.assertEqual(drift_clause["status"], "drift")

    def test_breach_verdict(self) -> None:
        result = evaluate(sample_baseline(), sample_state("breach"))
        entry = json.loads(result["json"])
        self.assertEqual(entry["verdict"]["verdict"], "breach")
        breach_clause = next(c for c in entry["diff"] if c["field"] == "max_tokens")
        self.assertEqual(breach_clause["status"], "breach")

    def test_missing_field_required_is_breach(self) -> None:
        baseline = {
            "id": "b",
            "clauses": [
                {"id": "c1", "field": "retrieval_enabled", "expected": True, "required": True}
            ],
        }
        state = {"id": "s"}
        diff = DiffEngine(PolicyBaseline(baseline), DeploymentState(state)).compare()
        self.assertEqual(diff[0]["status"], "breach")

    def test_missing_field_optional_is_drift(self) -> None:
        baseline = {
            "id": "b",
            "clauses": [
                {"id": "c1", "field": "log_level", "expected": "info", "required": False}
            ],
        }
        state = {"id": "s"}
        diff = DiffEngine(PolicyBaseline(baseline), DeploymentState(state)).compare()
        self.assertEqual(diff[0]["status"], "drift")

    def test_tolerance_boundary(self) -> None:
        baseline = {
            "id": "b",
            "clauses": [
                {"id": "c1", "field": "temperature", "expected": 0.7, "tolerance": 0.1, "required": True}
            ],
        }
        state = {"id": "s", "temperature": 0.8}
        diff = DiffEngine(PolicyBaseline(baseline), DeploymentState(state)).compare()
        self.assertEqual(diff[0]["status"], "drift")
        state["temperature"] = 0.81
        diff = DiffEngine(PolicyBaseline(baseline), DeploymentState(state)).compare()
        self.assertEqual(diff[0]["status"], "breach")

    def test_ledger_hash_chain(self) -> None:
        Ledger._chain.clear()
        evaluate(sample_baseline(), sample_state("aligned"))
        evaluate(sample_baseline(), sample_state("drift"))
        self.assertEqual(len(Ledger._chain), 2)
        self.assertEqual(Ledger._chain[1]["prev_hash"], Ledger._chain[0]["hash"])

    def test_report_markdown_contains_verdict(self) -> None:
        result = evaluate(sample_baseline(), sample_state("aligned"))
        entry = json.loads(result["json"])
        md = Report(entry).markdown()
        self.assertIn("aligned", md)
        self.assertIn(entry["hash"], md)

    def test_no_external_dependencies(self) -> None:
        source = Path(__file__).parent.parent / "policy_drift_dossier.py"
        text = source.read_text(encoding="utf-8")
        self.assertNotIn("import requests", text)
        self.assertNotIn("import yaml", text)


if __name__ == "__main__":
    unittest.main()

"""PolicyDriftDossier — AI deployment policy drift tracker.

A deterministic, stdlib-only tool that answers:
    "Has this AI deployment drifted from its approved policy baseline?"

Verdict scheme: aligned / drift / breach
Output: machine JSON + human Markdown
CLI triplet: sample / run / report
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class PolicyBaseline:
    """Policy baseline with required/recommended clauses."""

    def __init__(self, data: dict[str, Any]):
        self.id = data.get("id", "baseline")
        self.clauses = data.get("clauses", [])

    def to_dict(self) -> dict[str, Any]:
        return {"id": self.id, "clauses": self.clauses}


class DeploymentState:
    """Observed deployment attributes."""

    def __init__(self, data: dict[str, Any]):
        self.id = data.get("id", "deployment")
        self.fields = data

    def get(self, field: str) -> Any:
        return self.fields.get(field)

    def to_dict(self) -> dict[str, Any]:
        return dict(self.fields)


class DiffEngine:
    """Compare deployment state against policy baseline."""

    def __init__(self, baseline: PolicyBaseline, state: DeploymentState):
        self.baseline = baseline
        self.state = state

    def compare(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        for clause in self.baseline.clauses:
            field = clause["field"]
            actual = self.state.get(field)
            expected = clause.get("expected")
            tolerance = clause.get("tolerance")
            required = clause.get("required", False)
            status = self._classify(actual, expected, tolerance, required)
            results.append(
                {
                    "clause_id": clause.get("id", field),
                    "field": field,
                    "expected": expected,
                    "actual": actual,
                    "tolerance": tolerance,
                    "required": required,
                    "status": status,
                    "reason": self._reason(actual, expected, tolerance, status),
                }
            )
        return results

    def _classify(
        self, actual: Any, expected: Any, tolerance: Any, required: bool
    ) -> str:
        if actual is None:
            return "breach" if required else "drift"
        if expected is None:
            return "aligned"
        if actual == expected:
            return "aligned"
        if tolerance is not None and self._within_tolerance(actual, expected, tolerance):
            return "drift"
        return "breach" if required else "drift"

    def _within_tolerance(self, actual: Any, expected: Any, tolerance: Any) -> bool:
        try:
            return round(abs(float(actual) - float(expected)), 10) <= float(tolerance)
        except (TypeError, ValueError):
            return False

    def _reason(self, actual: Any, expected: Any, tolerance: Any, status: str) -> str:
        if status == "aligned":
            return "matches expected value"
        if actual is None:
            return "state field missing"
        if status == "drift" and tolerance is not None:
            return f"within tolerance {tolerance}"
        return f"expected {expected}, got {actual}"


class SeverityAggregate:
    """Aggregate per-clause status into a 3-way verdict."""

    def __init__(self, diff: list[dict[str, Any]]):
        self.diff = diff

    def verdict(self) -> dict[str, str]:
        if any(c["status"] == "breach" for c in self.diff):
            return {
                "verdict": "breach",
                "reason": "one or more required clauses breached",
            }
        if any(c["status"] == "drift" for c in self.diff):
            return {
                "verdict": "drift",
                "reason": "one or more clauses drifted within tolerance",
            }
        return {"verdict": "aligned", "reason": "all clauses match baseline"}


class Ledger:
    """Append-only hash-chained decision log."""

    _chain: list[dict[str, Any]] = []

    @classmethod
    def append(
        cls,
        baseline: PolicyBaseline,
        state: DeploymentState,
        diff: list[dict[str, Any]],
        verdict: dict[str, str],
    ) -> dict[str, Any]:
        entry: dict[str, Any] = {
            "seq": len(cls._chain) + 1,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "baseline_id": baseline.id,
            "state_id": state.id,
            "diff": diff,
            "verdict": verdict,
            "prev_hash": cls._chain[-1]["hash"] if cls._chain else "0" * 64,
        }
        entry["hash"] = cls._hash(entry)
        cls._chain.append(entry)
        return entry

    @staticmethod
    def _hash(entry: dict[str, Any]) -> str:
        payload = json.dumps(entry, sort_keys=True, default=str)
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class Report:
    """Dual JSON + Markdown output."""

    def __init__(self, entry: dict[str, Any]):
        self.entry = entry

    def json(self) -> str:
        return json.dumps(self.entry, indent=2, ensure_ascii=False)

    def markdown(self) -> str:
        v = self.entry["verdict"]
        lines = [
            "# PolicyDriftDossier Report",
            "",
            f"**Verdict:** {v['verdict']}",
            f"**Reason:** {v['reason']}",
            "",
            "| Clause | Field | Expected | Actual | Status | Reason |",
            "|---|---|---|---|---|---|",
        ]
        for c in self.entry["diff"]:
            lines.append(
                f"| {c['clause_id']} | {c['field']} | {c['expected']} | {c['actual']} | {c['status']} | {c['reason']} |"
            )
        lines.extend(
            [
                "",
                f"- Baseline: `{self.entry['baseline_id']}`",
                f"- State: `{self.entry['state_id']}`",
                f"- Sequence: {self.entry['seq']}",
                f"- Timestamp: {self.entry['timestamp']}",
                f"- Previous hash: `{self.entry['prev_hash']}`",
                f"- Entry hash: `{self.entry['hash']}`",
            ]
        )
        return "\n".join(lines)

    def dual_output(self) -> dict[str, str]:
        return {"json": self.json(), "markdown": self.markdown()}


def evaluate(baseline_data: dict[str, Any], state_data: dict[str, Any]) -> dict[str, str]:
    """Evaluate one baseline/state pair and return dual output."""
    baseline = PolicyBaseline(baseline_data)
    state = DeploymentState(state_data)
    diff = DiffEngine(baseline, state).compare()
    verdict = SeverityAggregate(diff).verdict()
    entry = Ledger.append(baseline, state, diff, verdict)
    return Report(entry).dual_output()


def sample_baseline() -> dict[str, Any]:
    return {
        "id": "baseline-001",
        "clauses": [
            {"id": "c1", "field": "max_tokens", "expected": 1024, "tolerance": 0, "required": True},
            {"id": "c2", "field": "temperature", "expected": 0.7, "tolerance": 0.1, "required": True},
            {"id": "c3", "field": "retrieval_enabled", "expected": True, "required": True},
            {"id": "c4", "field": "log_level", "expected": "info", "required": False},
        ],
    }


def sample_state(verdict: str = "aligned") -> dict[str, Any]:
    if verdict == "aligned":
        return {
            "id": "deployment-aligned",
            "max_tokens": 1024,
            "temperature": 0.7,
            "retrieval_enabled": True,
            "log_level": "info",
        }
    if verdict == "drift":
        return {
            "id": "deployment-drift",
            "max_tokens": 1024,
            "temperature": 0.75,
            "retrieval_enabled": True,
            "log_level": "debug",
        }
    # breach
    return {
        "id": "deployment-breach",
        "max_tokens": 2048,
        "temperature": 0.7,
        "retrieval_enabled": False,
        "log_level": "info",
    }


def write_sample(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    (path / "baseline.json").write_text(
        json.dumps(sample_baseline(), indent=2, ensure_ascii=False), encoding="utf-8"
    )
    for verdict in ("aligned", "drift", "breach"):
        (path / f"state_{verdict}.json").write_text(
            json.dumps(sample_state(verdict), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="PolicyDriftDossier: AI deployment policy drift tracker"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    sample_cmd = sub.add_parser("sample", help="Write sample baseline/state JSON files")
    sample_cmd.add_argument("--out", type=Path, default=Path("."))

    run_cmd = sub.add_parser("run", help="Evaluate a state against a baseline")
    run_cmd.add_argument("--baseline", type=Path, required=True)
    run_cmd.add_argument("--state", type=Path, required=True)
    run_cmd.add_argument("--format", choices=("json", "markdown"), default="json")

    report_cmd = sub.add_parser("report", help="Print markdown report from a JSON result")
    report_cmd.add_argument("--result", type=Path, required=True)

    args = parser.parse_args(argv)

    if args.command == "sample":
        write_sample(args.out)
        print(f"Samples written to {args.out.resolve()}")
        return 0

    if args.command == "run":
        baseline_data = json.loads(args.baseline.read_text(encoding="utf-8"))
        state_data = json.loads(args.state.read_text(encoding="utf-8"))
        output = evaluate(baseline_data, state_data)
        print(output[args.format])
        return 0

    if args.command == "report":
        entry = json.loads(args.result.read_text(encoding="utf-8"))
        print(Report(entry).markdown())
        return 0

    return 1


if __name__ == "__main__":
    sys.exit(main())

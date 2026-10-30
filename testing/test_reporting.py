import json

from commitguard.core import (
    attach_findings,
    build_pr_summary,
    save_results_to_file,
)
from commitguard.llm import Finding, FindingsReport

def test_findings_are_attached_by_id(tmp_path):
    records = [
        {
            "finding_id": "finding-0",
            "line": 'token = "example"',
            "location": "first.py:10",
        },
        {
            "finding_id": "finding-1",
            "line": 'token = "example"',
            "location": "second.py:20"
        }
    ]

    report = FindingsReport(
        findings=[
            Finding(
                finding_id="finding-1",
                level="HIGH",
                message="Hardcoded token",
                evidence='token = "example"'
            )
        ]
    )

    results = attach_findings(records, report)

    assert results[0]["llm_findings"] == []
    assert results[1]["llm_findings"][0]["level"] == "HIGH"

    assert "llm_findings" not in records[1]

    output = tmp_path / "report.json"
    save_results_to_file(results, output)

    assert json.loads(output.read_text(encoding="utf-8")) == results

    summary = build_pr_summary(report, len(records))

    assert "| HIGH | 1 |" in summary
    assert "| CRITICAL | 0 |" in summary


def test_empty_llm_report():
    records = [
        {
            "finding_id": "finding-0",
            "line": "some code",
            "location": "app.py:1"
        }
    ]
    report = FindingsReport(findings=[])

    results = attach_findings(records, report)

    assert len(results) == 1
    assert results[0]["llm_findings"] == []

    summary = build_pr_summary(report, len(records))

    assert "| HIGH | 0 |" in summary
    assert "The LLM returned no findings" in summary
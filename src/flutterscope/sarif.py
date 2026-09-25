"""SARIF 2.1.0 export, so results can be read by CI and code scanning tools.

Checks that were NOT_TESTED go out as tool execution notifications. A SARIF consumer that only
counts results would otherwise read an untested check as a clean one.
"""

from __future__ import annotations

from typing import Any

from . import __version__
from .model import Facts, Result, Status

_LEVEL = {"high": "error", "medium": "warning", "low": "note"}


def to_sarif(facts: Facts, result: Result) -> dict[str, Any]:
    rules: dict[str, dict[str, Any]] = {}
    for c in result.checks:
        rules.setdefault(c.check, {
            "id": c.check,
            "properties": {"masvs": c.control, "maswe": c.maswe},
        })
    results = []
    for f in result.findings:
        results.append({
            "ruleId": f.rule,
            "level": _LEVEL[f.severity.value],
            "message": {"text": f"{f.title}. {f.evidence}"},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": facts.artifact}}}],
            "properties": {"masvs": f.control, "maswe": f.maswe, "cwe": f.cwe,
                           "origin": f.origin, "severity": f.severity.value},
        })
    notes = [{
        "level": "warning",
        "message": {"text": f"{c.check} NOT_TESTED: {c.reason}"},
        "descriptor": {"id": c.check},
    } for c in result.checks if c.status is Status.NOT_TESTED]
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "flutterscope",
                "version": __version__,
                "informationUri": "https://github.com/vybebat/flutterscope",
                "rules": list(rules.values()),
            }},
            "invocations": [{"executionSuccessful": True,
                             "toolExecutionNotifications": notes}],
            "results": results,
        }],
    }

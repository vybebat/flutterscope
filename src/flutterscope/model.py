"""The data that passes between the two stages.

`Facts` is what recovery produces and judgement reads. It holds no opinions. `Result` is what
judgement produces. Keeping the two apart is what lets every check be tested against a
hand-built `Facts` with no binary and no Blutter.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class Status(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    # Evidence was collected but a human has to decide the verdict.
    REVIEW = "REVIEW"
    # The check could not be made. Always carries a reason. Never shown as a pass.
    NOT_TESTED = "NOT_TESTED"


class Severity(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class Snapshot:
    """The header of the Dart AOT snapshot inside libapp.so."""

    hash: str
    features: list[str]

    @property
    def is_product(self) -> bool:
        return "product" in self.features

    @property
    def dwarf_stack_traces(self) -> bool | None:
        """True when built with --split-debug-info. None when the flag is not in the header."""
        if "dwarf_stack_traces_mode" in self.features:
            return True
        if "no-dwarf_stack_traces_mode" in self.features:
            return False
        return None


@dataclass
class Signal:
    """A behaviour recovered from the compiled Dart, with the libraries that refer to it."""

    slug: str
    token: str
    referrers: list[str] = field(default_factory=list)
    # "app", "package:<name>", or "unknown" when library names were obfuscated away.
    origin: str = "unknown"


@dataclass
class Constant:
    """A string constant from the snapshot that looks like something worth judging."""

    kind: str
    value: str
    referrers: list[str] = field(default_factory=list)
    origin: str = "unknown"
    # True when the value is a placeholder published in vendor documentation.
    documented_example: bool = False


@dataclass
class Facts:
    artifact: str = ""
    sha256: str = ""
    platform: str = "android"
    is_flutter: bool = False
    abis: list[str] = field(default_factory=list)
    # Debug builds ship Dart as a kernel blob and run it in the JIT. There is no libapp.so.
    kernel_blob: bool = False
    snapshot: Snapshot | None = None
    dart_version: str | None = None
    packages: list[str] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    build_paths: list[str] = field(default_factory=list)
    constants: list[Constant] = field(default_factory=list)
    # Everything below needs Blutter output. `deep` stays False until it was actually read.
    deep: bool = False
    deep_reason: str = ""
    app_package: str | None = None
    libs_total: int = 0
    libs_readable: int = 0
    signals: list[Signal] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Facts":
        d = dict(d)
        snap = d.pop("snapshot", None)
        sigs = d.pop("signals", [])
        consts = d.pop("constants", [])
        f = cls(**d)
        f.snapshot = Snapshot(**snap) if snap else None
        f.signals = [Signal(**s) for s in sigs]
        f.constants = [Constant(**c) for c in consts]
        return f


@dataclass
class Finding:
    rule: str
    title: str
    severity: Severity
    control: str
    maswe: str
    cwe: str
    # "app", "package:<name>" or "unknown". A developer cannot fix what they did not write.
    origin: str
    evidence: str
    impact: str
    remediation: str

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d


@dataclass
class Observation:
    """Something worth knowing that is not a vulnerability. Never severity-rated."""

    rule: str
    control: str
    text: str


@dataclass
class Check:
    """One check and its verdict. A check covers a slice of a MASVS control, never the whole
    control, so a PASS here is a statement about this check only."""

    check: str
    control: str
    maswe: str
    status: Status
    reason: str

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["status"] = self.status.value
        return d


@dataclass
class Result:
    findings: list[Finding] = field(default_factory=list)
    observations: list[Observation] = field(default_factory=list)
    checks: list[Check] = field(default_factory=list)

    def check(self, cid: str) -> Check | None:
        for c in self.checks:
            if c.check == cid:
                return c
        return None

    def rules(self) -> set[str]:
        return {f.rule for f in self.findings} | {o.rule for o in self.observations}

    def to_dict(self) -> dict[str, Any]:
        return {
            "checks": [c.to_dict() for c in self.checks],
            "findings": [f.to_dict() for f in self.findings],
            "observations": [asdict(o) for o in self.observations],
        }

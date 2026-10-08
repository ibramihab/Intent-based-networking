"""Validation issues and reports shared by the Intent and Validation layers."""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, computed_field


class Severity(str, Enum):
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"


class Issue(BaseModel):
    severity: Severity
    message: str
    device: str | None = None

    def __str__(self) -> str:
        where = f"[{self.device}] " if self.device else ""
        return f"{self.severity.value.upper()}: {where}{self.message}"


def error(msg: str, device: str | None = None) -> Issue:
    return Issue(severity=Severity.ERROR, message=msg, device=device)


def warning(msg: str, device: str | None = None) -> Issue:
    return Issue(severity=Severity.WARNING, message=msg, device=device)


def info(msg: str, device: str | None = None) -> Issue:
    return Issue(severity=Severity.INFO, message=msg, device=device)


class StageResult(BaseModel):
    name: str
    issues: list[Issue] = Field(default_factory=list)
    skipped: bool = False
    details: dict[str, Any] = Field(default_factory=dict)

    @computed_field
    @property
    def passed(self) -> bool:
        return not any(i.severity == Severity.ERROR for i in self.issues)


class ValidationReport(BaseModel):
    title: str
    stages: list[StageResult] = Field(default_factory=list)

    @computed_field
    @property
    def passed(self) -> bool:
        return all(s.passed for s in self.stages)

    def add(self, stage: StageResult) -> StageResult:
        self.stages.append(stage)
        return stage

    def errors(self) -> list[Issue]:
        return [i for s in self.stages for i in s.issues if i.severity == Severity.ERROR]

    def to_markdown(self) -> str:
        lines = [f"# {self.title}", "", f"**Result:** {'PASSED' if self.passed else 'FAILED'}", ""]
        for s in self.stages:
            status = "skipped" if s.skipped else ("pass" if s.passed else "FAIL")
            lines.append(f"## {s.name} — {status}")
            lines.extend(f"- {i}" for i in s.issues)
            if not s.issues:
                lines.append("- no findings")
            lines.append("")
        return "\n".join(lines)

"""The AI's configuration design: vendor-neutral model + device-specific candidate configuration."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


class VerifyCheck(BaseModel):
    """Read-only command run after deployment and the strings its output must (not) contain."""

    model_config = ConfigDict(extra="ignore")

    command: str
    expect_contains: list[str] = Field(default_factory=list)
    expect_absent: list[str] = Field(default_factory=list)

    def evaluate(self, output: str) -> list[str]:
        problems = [f"'{s}' missing from '{self.command}'" for s in self.expect_contains if s not in output]
        problems += [f"'{s}' still present in '{self.command}'" for s in self.expect_absent if s in output]
        return problems


class DeviceConfig(BaseModel):
    model_config = ConfigDict(extra="ignore")

    device: str
    commands: list[str] = Field(default_factory=list)
    rollback: list[str] = Field(default_factory=list)
    verify: list[VerifyCheck] = Field(default_factory=list)

    @field_validator("commands", "rollback")
    @classmethod
    def _clean(cls, lines: list[str]) -> list[str]:
        out = []
        for raw in lines:
            for line in str(raw).splitlines():  # the LLM sometimes packs a block into one string
                if line.strip():
                    out.append(line.rstrip())
        return out


class ConfigDesign(BaseModel):
    model_config = ConfigDict(extra="ignore")

    approach: str
    reasoning: str = ""
    neutral_model: list[dict[str, Any]] = Field(default_factory=list)
    devices: list[DeviceConfig] = Field(default_factory=list)
    risks: list[str] = Field(default_factory=list)

    def device(self, name: str) -> DeviceConfig | None:
        return next((d for d in self.devices if d.device == name), None)

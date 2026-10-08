"""Platform registry: inventory `platform:` -> Platform implementation."""

from __future__ import annotations

from ibn.platforms.base import Platform
from ibn.platforms.cisco_ios import CiscoIOS

_REGISTRY: dict[str, Platform] = {}


def register(platform: Platform) -> None:
    _REGISTRY[platform.name] = platform


def get_platform(name: str) -> Platform:
    try:
        return _REGISTRY[name]
    except KeyError:
        raise KeyError(f"no platform module for {name!r} (available: {', '.join(_REGISTRY)})") from None


def supported() -> list[str]:
    return sorted(_REGISTRY)


register(CiscoIOS())

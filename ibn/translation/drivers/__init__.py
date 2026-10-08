"""Driver registry: platform string (inventory.yaml) -> VendorDriver."""

from __future__ import annotations

from ibn.translation.drivers.base import VendorDriver
from ibn.translation.drivers.cisco_ios import CiscoIOSDriver

_REGISTRY: dict[str, VendorDriver] = {}


def register(driver: VendorDriver) -> None:
    _REGISTRY[driver.platform] = driver


def get_driver(platform: str) -> VendorDriver:
    try:
        return _REGISTRY[platform]
    except KeyError:
        raise KeyError(f"no driver for platform {platform!r} (available: {', '.join(_REGISTRY)})") from None


register(CiscoIOSDriver())

"""Simple central registry for SentinelScan scanner modules."""

from sentinelscan.core.exceptions import ScannerAlreadyRegisteredError, ScannerNotFoundError
from sentinelscan.scanners.base import BaseScanner


class ScannerRegistry:
    """Synchronous, lightweight registry for storing and retrieving scanner instances."""

    def __init__(self, register_defaults: bool = True) -> None:
        self._scanners: dict[str, BaseScanner] = {}
        if register_defaults:
            self._register_defaults()

    def _register_defaults(self) -> None:
        """Instantiate and register standard SentinelScan security scanners."""
        from sentinelscan.scanners.iac_scanner import IacScanner
        from sentinelscan.scanners.sast_scanner import SastScanner
        from sentinelscan.scanners.sca_scanner import ScaScanner
        from sentinelscan.scanners.secret_scanner import SecretScanner

        self.register(SecretScanner())
        self.register(SastScanner())
        self.register(IacScanner())
        self.register(ScaScanner())

    def register(self, scanner: BaseScanner) -> None:
        """Register a scanner instance.

        Raises:
            ScannerAlreadyRegisteredError: If a scanner with the same name exists.
        """
        if scanner.name in self._scanners:
            raise ScannerAlreadyRegisteredError(
                f"Scanner with name '{scanner.name}' is already registered."
            )
        self._scanners[scanner.name] = scanner

    def get(self, name: str) -> BaseScanner:
        """Retrieve a registered scanner by name.

        Raises:
            ScannerNotFoundError: If no scanner with that name is registered.
        """
        if name not in self._scanners:
            raise ScannerNotFoundError(f"Scanner '{name}' is not registered.")
        return self._scanners[name]

    def list_all(self) -> list[BaseScanner]:
        """Return a list of all registered scanner instances."""
        return list(self._scanners.values())

    def clear(self) -> None:
        """Clear all registered scanners (primarily used in test teardowns)."""
        self._scanners.clear()

    def __len__(self) -> int:
        return len(self._scanners)

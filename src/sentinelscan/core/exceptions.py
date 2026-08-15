"""SentinelScan exception hierarchy for structured domain error handling."""


class SentinelScanError(Exception):
    """Base exception for all SentinelScan errors."""



class InvalidTargetError(SentinelScanError):
    """Raised when a provided scan target path is invalid or unreadable."""



class TargetNotFoundError(InvalidTargetError):
    """Raised when the target path does not exist on the filesystem."""



class ScannerError(SentinelScanError):
    """Base exception for scanner lifecycle errors."""



class ScannerAlreadyRegisteredError(ScannerError):
    """Raised when attempting to register a scanner with a duplicate name."""



class ScannerNotFoundError(ScannerError):
    """Raised when requesting a scanner that is not present in the registry."""



class ReportGenerationError(SentinelScanError):
    """Raised when report rendering or output writing fails."""


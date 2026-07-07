class NetScannerError(Exception):
    """Base error for expected NetScanner failures."""


class AuthorizationError(NetScannerError):
    """Raised when a real scan is requested without explicit authorization."""


class DependencyError(NetScannerError):
    """Raised when a required system or Python dependency is missing."""


class ScanExecutionError(NetScannerError):
    """Raised when Nmap fails during execution."""

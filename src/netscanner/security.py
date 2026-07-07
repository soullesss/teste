from __future__ import annotations

import os


def has_admin_privileges() -> bool:
    if hasattr(os, "geteuid"):
        return os.geteuid() == 0
    return False


def authorization_note() -> str:
    return (
        "Run real scans only against systems you own or have written permission "
        "to test. NetScanner requires --i-have-authorization for scan execution."
    )

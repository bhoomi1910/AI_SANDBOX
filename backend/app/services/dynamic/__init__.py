"""Dynamic sandbox analysis scaffold.

This module intentionally runs with a safe default:
- `dynamic_sandbox_enabled=false` means no sample execution occurs.
- when enabled, a controlled worker records bounded telemetry metadata only.
"""

from app.services.dynamic.service import start_dynamic_analysis

__all__ = ["start_dynamic_analysis"]


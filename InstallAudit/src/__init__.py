# Copyright (c) 2026 Paul Cossey. All rights reserved.
# SPDX-License-Identifier: BSD-3-Clause
"""
Modular InstallAudit Software Title Tester.
"""

from importlib.metadata import PackageNotFoundError, version as _dist_version

try:
    __version__ = _dist_version("InstallAudit")
except PackageNotFoundError:
    # Fallback version if distribution metadata is unavailable (e.g., running from source)
    __version__ = "0.0.0"
from .core.auto_update_tester import AutoUpdateTester, main

__all__ = ['AutoUpdateTester', 'main', '__version__']

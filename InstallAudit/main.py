#!/usr/bin/env python3
# Copyright (c) 2026 Paul Cossey. All rights reserved.
# SPDX-License-Identifier: BSD-3-Clause
"""
Main entry point for InstallAudit.

This script has been refactored from a monolithic structure into a modular
Python package while maintaining the same functionality and public API.
"""

import sys
import os

# Add the src directory to the Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from src import main, __version__  # noqa: E402

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] in ('--version', '-v'):
        print(f"InstallAudit v{__version__}")
        sys.exit(0)
    main()

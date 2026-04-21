# Copyright (c) 2026 Paul Cossey. All rights reserved.
# SPDX-License-Identifier: BSD-3-Clause
"""
Configuration Profile Generation Module.

This module provides functionality to automatically generate configuration profiles
based on application analysis, similar to iMazing Profile Editor's functionality.
"""

from .app_analyzer import AppAnalyzer
from .profile_generator import ProfileGenerator
from .profile_templates import ProfileTemplates

__all__ = ['AppAnalyzer', 'ProfileGenerator', 'ProfileTemplates']

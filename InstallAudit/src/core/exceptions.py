# Copyright (c) 2026 Paul Cossey. All rights reserved.
# SPDX-License-Identifier: BSD-3-Clause
"""
Custom Exception Hierarchy for InstallAudit.

This module defines specific exception types for better error handling
and debugging throughout the application.
"""


class InstallAuditError(Exception):
    """Base exception for all InstallAudit errors."""

    pass


class CatalogError(InstallAuditError):
    """Raised when catalog operations fail.

    Examples:
        - Catalog file not found
        - Invalid catalog format
        - Catalog update failures
        - Catalog item validation errors
    """

    pass


class InstallationError(InstallAuditError):
    """Raised when software installation fails.

    Examples:
        - Installation prerequisites not met
        - Munki installation failures
        - Post-installation verification failures
    """

    pass


class UninstallationError(InstallAuditError):
    """Raised when software uninstallation fails.

    Examples:
        - Uninstall script failures
        - Cleanup operation failures
        - Verification after uninstall failures
    """

    pass


class SecurityScanError(InstallAuditError):
    """Raised when security scanning operations fail.

    Examples:
        - VirusTotal API failures
        - ThreatLabs scanner errors
        - KnockKnock scanning failures
    """

    pass


class ProfileGenerationError(InstallAuditError):
    """Raised when configuration profile generation fails.

    Examples:
        - Invalid profile template data
        - Missing required profile fields
        - Profile file write failures
    """

    pass


class RecipeError(InstallAuditError):
    """Raised when AutoPkg recipe operations fail.

    Examples:
        - Recipe generation failures
        - Recipe update errors
        - Invalid recipe format
    """

    pass


class ManifestError(InstallAuditError):
    """Raised when Munki manifest operations fail.

    Examples:
        - Manifest file not found
        - Invalid manifest format
        - Manifest update failures
    """

    pass


class SystemCheckError(InstallAuditError):
    """Raised when system checks or comparisons fail.

    Examples:
        - Unable to capture system state
        - Comparison operation failures
        - Permission denied for system information
    """

    pass


class BinaryExtractionError(InstallAuditError):
    """Raised when binary extraction or analysis fails.

    Examples:
        - Binary extraction from package failures
        - Binary analysis errors
        - Unable to determine binary architecture
    """

    pass


class ConfigurationError(InstallAuditError):
    """Raised when configuration is invalid or missing.

    Examples:
        - Missing required configuration
        - Invalid configuration values
        - Configuration file parsing errors
    """

    pass

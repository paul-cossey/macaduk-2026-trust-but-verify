# Copyright (c) 2026 Paul Cossey. All rights reserved.
# SPDX-License-Identifier: BSD-3-Clause
"""
Configuration dictionaries and constants for InstallAudit.
"""

# Default log lookback period (in minutes)
# This controls how far back to search in unified logs
DEFAULT_LOG_LOOKBACK_MINUTES = 20

# Predicate strings for unified log queries
RANSOMWHERE_PREDICATE = "subsystem='com.objective-see.ransomwhere'"

# Security tool configurations
security_tools = {
    "lulu": {
        "command": [
            "log",
            "stream",
            "--level",
            "debug",
            "--predicate",
            "subsystem='com.objective-see.lulu'"
        ],
        "stream_command": [
            "log", "stream",
            "--level",
            "debug",
            "--predicate",
            "subsystem='com.objective-see.lulu'"
        ],
        "type": "both"
    },
    "blockblock": {
        "log_path": "/Library/Objective-See/BlockBlock/BlockBlock.log",
        "command": [
            "log", "show",
            "--predicate",
            (
                "subsystem == 'com.objective-see.blockblock'"
            ),
            "--style", "json",
            "--last", f"{DEFAULT_LOG_LOOKBACK_MINUTES}m"
        ],
        "stream_command": [
            "log", "stream",
            "--predicate",
            (
                "subsystem == 'com.objective-see.blockblock' "
                "AND eventMessage CONTAINS \"user says, 'allow'\""
            ),
            "--style", "json"
        ],
        "type": "both",
        "event_filters": {
            "ignore_paths": [
                "/System/Library/",
                "/Library/Apple/",
                "/private/var/db/softwareupdate/",
                "/System/Volumes/",
                "/Library/Application Support/Apple/"
            ],
            "ignore_processes": [
                "backgroundtaskmanagementd",
                "softwareupdated",
                "system_installd"
            ],
            "severity_threshold": "medium",
            "interesting_messages": [
                "installed a launch daemon",
                "installed a launch agent",
                "persistence mechanism",
                "new 'btm' event",
                "delivering alert to user"
            ]
        }
    },
    "reikey": {
        "command": [
            "/Applications/ReiKey.app/Contents/MacOS/ReiKey",
            "-scan",
            "-pretty",
            "-skipApple"
        ],
        "type": "scan"
    },
    "ransomwhere": {
        "command": [
            "log", "stream",
            "--level", "debug",
            "--predicate", RANSOMWHERE_PREDICATE
        ],
        "stream_command": [
            "log", "stream",
            "--level", "debug",
            "--predicate", RANSOMWHERE_PREDICATE
        ],
        "type": "stream"  # Stream only - captures full details in real-time
    },
    "oversight": {
        "command": [
            "log",
            "stream",
            "--level",
            "debug",
            "--predicate",
            "subsystem='com.objective-see.oversight'"
        ],
        "type": "stream"
    },
    "dhs": {
        "command": [
            "/Applications/DHS.app/Contents/MacOS/DHS",
            "-json"
        ],
        "output_path": "/Applications/dhsFindings.txt",
        "type": "scan"
    },
    "xprotect": {
        "command": [
            "log", "show",
            "--predicate",
            (
                "subsystem == 'com.apple.xprotect' "
                "OR subsystem == 'com.apple.XProtect' "
                "OR process == 'XProtect' "
                "OR eventMessage CONTAINS 'XProtect' "
                "OR eventMessage CONTAINS 'malware' "
                "OR eventMessage CONTAINS 'quarantine'"
            ),
            "--style", "json",
            "--last", f"{DEFAULT_LOG_LOOKBACK_MINUTES}m"
        ],
        "stream_command": [
            "log", "stream",
            "--predicate",
            (
                "subsystem == 'com.apple.xprotect' "
                "OR subsystem == 'com.apple.XProtect' "
                "OR process == 'XProtect' "
                "OR eventMessage CONTAINS 'XProtect' "
                "OR eventMessage CONTAINS 'malware' "
                "OR eventMessage CONTAINS 'quarantine'"
            ),
            "--style", "json"
        ],
        "type": "both"
    }
}

# Event formatting configuration
event_formatting = {
    "blockblock": {
        "severity_levels": {
            "high": ["launch daemon", "launch agent", "persistence"],
            "medium": ["file operation", "process creation"],
            "low": ["monitoring", "scan"]
        },
        "ignore_patterns": [
            r"/System/Library/.*",
            r"/Library/Apple/.*",
            r"/private/var/db/softwareupdate/.*"
        ]
    }
}

# Report configuration
report_config = {
    "sections": [
        "system_info",
        "installation_details",
        "test_results",
        "security_events",
        "system_changes",
        "code_signing",
        "uninstall_results"
    ],
    "security_tools": [
        "BLOCKBLOCK",
        "DHS",
        "REIKEY",
        "LULU",
        "RANSOMWHERE",
        "OVERSIGHT",
        "XPROTECT"
    ]
}


def update_log_lookback_period(minutes):
    """
    Update the log lookback period for all security tools.

    Args:
        minutes: Number of minutes to look back in logs
    """
    global DEFAULT_LOG_LOOKBACK_MINUTES
    DEFAULT_LOG_LOOKBACK_MINUTES = minutes

    # Update BlockBlock
    if "blockblock" in security_tools and "command" in security_tools["blockblock"]:
        cmd = security_tools["blockblock"]["command"]
        for i, item in enumerate(cmd):
            if item == "--last" and i + 1 < len(cmd):
                cmd[i + 1] = f"{minutes}m"

    # Note: RansomWhere v1.9.0+ uses streaming and doesn't have --last parameter
    # For older versions (<1.9.0), we would need to update if using log show instead of stream

    # Update XProtect
    if "xprotect" in security_tools and "command" in security_tools["xprotect"]:
        cmd = security_tools["xprotect"]["command"]
        for i, item in enumerate(cmd):
            if item == "--last" and i + 1 < len(cmd):
                cmd[i + 1] = f"{minutes}m"


def prompt_log_lookback_period():
    """
    Prompt the user to set the log lookback period.

    Returns:
        int: Number of minutes to look back
    """
    from .config_manager import get_config
    config = get_config()
    default_minutes = config.get_default_log_lookback_minutes()

    print("\n" + "=" * 60)
    print("Log Lookback Period Configuration")
    print("=" * 60)
    print(f"\nCurrent default: {default_minutes} minutes")
    print("\nThis setting controls how far back to search in unified logs")
    print("for security events (BlockBlock, RansomWhere, XProtect, etc.)")
    print("\nRecommended values:")
    print("  - 10-20 minutes: For quick tests")
    print("  - 30-60 minutes: For comprehensive tests")
    print("  - 120+ minutes: For troubleshooting or historical analysis")

    while True:
        try:
            user_input = input(f"\nEnter log lookback period in minutes (default: {default_minutes}): ").strip()

            if not user_input:
                # User pressed enter, use default
                return default_minutes

            minutes = int(user_input)

            if minutes < 1:
                print("❌ Please enter a positive number of minutes")
                continue

            if minutes > 720:  # 12 hours
                confirm = input(f"⚠️  {minutes} minutes is quite long. Continue? (y/n): ").strip().lower()
                if confirm != 'y':
                    continue

            return minutes

        except ValueError:
            print("❌ Please enter a valid number")
        except KeyboardInterrupt:
            print("\n\nUsing default value...")
            return DEFAULT_LOG_LOOKBACK_MINUTES


def configure_ransomwhere_for_version(version_string):
    """
    Configure RansomWhere command based on detected version.
    v1.9.0+ uses streaming with unified log (stream-only for full detail).
    v2.0+ uses Apple Endpoint Security framework with enhanced features.
    Pre-1.9.0 uses log show with historical lookback.

    Official documentation: https://objective-see.org/products/ransomwhere.html
    Recommended command: log stream --level debug --predicate="subsystem='com.objective-see.ransomwhere'"

    Args:
        version_string: Version string like "1.9.0" or "1.8.5"
    """
    if "ransomwhere" not in security_tools:
        return

    try:
        # Parse version
        if not version_string:
            # Default to new streaming method if version unknown
            return

        parts = version_string.split('.')
        version_tuple = tuple(int(p) for p in parts[:3] if p.isdigit())

        if version_tuple >= (1, 9, 0):
            # Use stream-only for v1.9.0+ to capture full multi-line alert details
            security_tools["ransomwhere"]["command"] = [
                "log", "stream",
                "--level", "debug",
                "--predicate", RANSOMWHERE_PREDICATE
            ]
            security_tools["ransomwhere"]["stream_command"] = [
                "log", "stream",
                "--level", "debug",
                "--predicate", RANSOMWHERE_PREDICATE
            ]
            security_tools["ransomwhere"]["type"] = "stream"
        else:
            # Use old log show command for pre-1.9.0
            security_tools["ransomwhere"]["command"] = [
                "log", "show",
                "--predicate", "process == 'RansomWhere'",
                "--style", "syslog",
                "--last", f"{DEFAULT_LOG_LOOKBACK_MINUTES}m"
            ]
            security_tools["ransomwhere"]["type"] = "historical"  # Not streaming

    except (ValueError, AttributeError, IndexError):
        # If version parsing fails, use default (new streaming method)
        pass

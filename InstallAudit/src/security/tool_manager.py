# Copyright (c) 2026 Paul Cossey. All rights reserved.
# SPDX-License-Identifier: BSD-3-Clause
"""
Security tool manager module for managing security tool states and verification.
"""

import subprocess
import os
import logging

# Set up logging
logger = logging.getLogger(__name__)


class SecurityToolManager:
    """Handles security tool state management and verification."""

    # Status constants
    STATUS_NOT_FOUND = "Not found"

    def _verify_security_tools(self):
        """Verify all security tools are available and responding"""
        tool_status = {}

        for tool_name, _config in self.security_tools.items():
            status = self._verify_tool_status(tool_name)
            tool_status[tool_name] = status

            # Only log warnings for unavailable tools, with special handling for DHS
            if tool_name == "dhs":
                # For DHS, only warn if it's not installed
                if status == "Not installed" or status == self.STATUS_NOT_FOUND:
                    logger.warning(f"⚠️ Security tool {tool_name} is not available: {status}")
            else:
                # For other tools, warn if they're not running or available
                if status not in ["Running", "Active", "Available"]:
                    logger.warning(f"⚠️ Security tool {tool_name} is not available: {status}")

        return tool_status

    def _verify_tool_status(self, tool_name):
        """Verify the status of a security tool with enhanced detection"""
        try:
            if tool_name not in self.security_tools:
                return "Not configured"

            tool_config = self.security_tools[tool_name]

            # Tool-specific paths and detection methods
            tool_paths = {
                "lulu": {
                    "paths": [
                        "/Applications/LuLu.app",
                        "/Applications/LuLu.app/Contents/MacOS/LuLu"
                    ],
                    "daemon": "com.objective-see.lulu",
                    "process": ["com.objective-see.lulu.extension", "LuLu"],
                    "extension": "com.objective-see.lulu.extension"
                },
                "blockblock": {
                    "paths": [
                        "/Library/Objective-See/BlockBlock/BlockBlock.app/Contents/MacOS/BlockBlock",
                        "/Applications/BlockBlock Helper.app/Contents/MacOS/BlockBlock Helper"
                    ],
                    "daemon": "com.objective-see.blockblock",
                    "process": ["BlockBlock", "BlockBlock Helper"],
                    "helper": "com.objective-see.blockblock.helper"
                },
                "ransomwhere": {
                    "paths": [
                        "/Library/Objective-See/RansomWhere/RansomWhere",
                        "/Applications/RansomWhere Helper.app",
                        "/Applications/RansomWhere Helper.app/Contents/MacOS/RansomWhere Helper",
                        "/Library/Objective-See/RansomWhere/RansomWhere.app"
                    ],
                    "daemon": "com.objective-see.ransomwhere",
                    "process": "RansomWhere"
                },
                "oversight": {
                    "paths": [
                        "/Applications/OverSight.app",
                        "/Applications/OverSight.app/Contents/MacOS/OverSight"
                    ],
                    "daemon": "com.objective-see.oversight",
                    "process": ["OverSight", "com.objective-see.oversight"]
                },
                "reikey": {
                    "paths": ["/Applications/ReiKey.app/Contents/MacOS/ReiKey"],
                    "process": "ReiKey"
                },
                "dhs": {
                    "paths": ["/Applications/DHS.app/Contents/MacOS/DHS"],
                    "process": "DHS"
                },
                "xprotect": {
                    "paths": [
                        "/System/Library/CoreServices/XProtect.bundle",
                        "/Library/Apple/System/Library/CoreServices/XProtect.bundle",
                        "/usr/libexec/XProtect"
                    ],
                    "daemon": "com.apple.xprotect.XProtectService",
                    "process": ["XProtect", "xprotectd"]
                }
            }

            # Check if tool is actively monitoring
            if tool_name in self.monitoring_processes:
                process_info = self.monitoring_processes[tool_name]
                if process_info.get("active") and process_info.get("process"):
                    return "Active"

            # Tool-specific verification
            if tool_name in tool_paths:
                tool_info = tool_paths[tool_name]

                # Check if binary exists
                binary_exists = any(os.path.exists(path) for path in tool_info["paths"])

                if binary_exists:
                    # Check if process is running
                    if "process" in tool_info:
                        processes = tool_info["process"] if isinstance(tool_info["process"], list) else [tool_info["process"]]
                        for proc in processes:
                            try:
                                process_check = subprocess.run(
                                    ["pgrep", "-f", proc],  # Added -f to match full process name
                                    capture_output=True,
                                    text=True
                                )
                                if process_check.returncode == 0:
                                    return "Running"
                            except subprocess.SubprocessError:
                                pass

                    # Check if daemon/extension is loaded
                    if "daemon" in tool_info:
                        try:
                            daemon_check = subprocess.run(
                                ["launchctl", "list", tool_info["daemon"]],
                                capture_output=True,
                                text=True
                            )
                            if daemon_check.returncode == 0:
                                return "Running"
                        except subprocess.SubprocessError:
                            pass

                    # Check system extension for LuLu
                    if "extension" in tool_info:
                        try:
                            extension_check = subprocess.run(
                                ["systemextensionsctl", "list"],
                                capture_output=True,
                                text=True
                            )
                            if tool_info["extension"] in extension_check.stdout:
                                return "Running"
                        except subprocess.SubprocessError:
                            pass

                    return "Available"
                return "Not installed"

            # For scan-type tools
            if tool_config["type"] == "scan":
                if os.path.exists(tool_config["command"][0]):
                    return "Available"
                return self.STATUS_NOT_FOUND

            return self.STATUS_NOT_FOUND

        except Exception as e:
            logger.error(f"Error verifying {tool_name} status: {e}")
            return f"Error: {str(e)}"

    def _manage_security_tool_states(self, action="save"):
        """Manage security tool states - save or restore.

        Args:
            action (str): Either 'save' to backup current state or
                'restore' to restore previous state
        """
        # Reset RansomWhere only (this is safer and more reliable)
        if action == "restore":
            try:
                ransomwhere_path = "/Library/Objective-See/RansomWhere/RansomWhere"
                if os.path.exists(ransomwhere_path):
                    subprocess.run([ransomwhere_path, "-reset"], check=True)
                    print("✅ Reset RansomWhere successfully")
            except Exception as e:
                logger.error(f"Error resetting RansomWhere: {e}")
                print(f"❌ Error resetting RansomWhere: {e}")

        # For save action, we don't need to do anything since we're not backing up states anymore
        if action == "save":
            print("✅ Security tool state management simplified - no backup needed")

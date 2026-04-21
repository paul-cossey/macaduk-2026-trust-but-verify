# Copyright (c) 2026 Paul Cossey. All rights reserved.
# SPDX-License-Identifier: BSD-3-Clause
"""
Process handling utilities for InstallAudit.
"""

import subprocess
import re
import logging

logger = logging.getLogger(__name__)


class ProcessUtils:
    """Handles process execution and output management."""

    def __init__(self):
        """Initialize ProcessUtils."""
        pass

    def _handle_process_output(self, process, _action_type=""):
        """Handle process output with reduced noise - wait for process to complete"""
        output_lines = []
        last_significant_line = None
        progress_pattern = re.compile(r'^[\s→]*([0-9.]+)(?:\s*percent complete)?$')
        last_percentage = -1

        # Read all output until process completes
        try:
            while True:
                output = process.stdout.readline()
                if output == '' and process.poll() is not None:
                    break
                if output:
                    line = output.strip()

                    # Skip empty lines
                    if not line:
                        continue

                    # Always collect the line for return value
                    output_lines.append(line)

                    # Check if this is a progress indicator line
                    progress_match = progress_pattern.match(line)
                    if progress_match:
                        try:
                            # Try to extract percentage
                            current = float(progress_match.group(1).rstrip('.'))
                            # Only show 0, 25, 50, 75, and 100 percent
                            if current in [0, 25, 50, 75, 100] and current > last_percentage:
                                print(f"   → {int(current)}% complete")
                                last_percentage = current
                        except ValueError:
                            continue
                        continue

                    # Skip redundant progress lines but still show them
                    if any(x in line for x in ['Downloading', 'Copying', 'Installing']):
                        if line != last_significant_line:
                            print(f"   → {line}")
                            last_significant_line = line
                        continue

                    # Include all other lines but filter display
                    # Skip lines that are just numbers, dots, and arrows for display
                    if not line.strip('→ .0123456789'):
                        continue

                    print(f"   → {line}")

            # Wait for process to complete
            process.wait()

        except Exception as e:
            logger.error(f"Error handling process output: {e}")
            # Make sure we still wait for the process
            try:
                process.wait()
            except (OSError, ValueError) as wait_error:
                logger.debug(f"Error waiting for process: {wait_error}")

        return output_lines

    def _parse_process_ancestors(self, ancestors_str):
        """Parse process ancestry information from es_process_t data"""
        ancestors = []
        if not ancestors_str:
            return ancestors

        # Split by lines and parse each ancestor
        lines = ancestors_str.strip().split('\n')
        for line in lines:
            if 'executable=' in line and 'pid=' in line:
                # Extract executable path and PID
                try:
                    exec_match = re.search(r'executable=([^,]+)', line)
                    pid_match = re.search(r'pid=(\d+)', line)

                    if exec_match and pid_match:
                        executable = exec_match.group(1).strip('"')
                        pid = int(pid_match.group(1))
                        ancestors.append({
                            'executable': executable,
                            'pid': pid,
                            'name': executable.split('/')[-1] if '/' in executable else executable
                        })
                except Exception as e:
                    logger.warning(f"Failed to parse ancestor line: {line}, error: {e}")

        return ancestors

    def _get_console_user(self):
        """Get the current console user"""
        try:
            result = subprocess.run(
                ["/usr/bin/stat", "-f", "%Su", "/dev/console"],
                capture_output=True,
                text=True,
                check=True
            )
            return result.stdout.strip()
        except subprocess.CalledProcessError:
            return None

    def _run_command(self, command, timeout=None):
        """Run a command and return the result"""
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False
            )
            return result
        except subprocess.TimeoutExpired:
            logger.error(f"Command timed out: {' '.join(command)}")
            return None
        except Exception as e:
            logger.error(f"Error running command {' '.join(command)}: {e}")
            return None

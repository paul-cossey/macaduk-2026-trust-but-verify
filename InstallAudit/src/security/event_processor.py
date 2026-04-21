# Copyright (c) 2026 Paul Cossey. All rights reserved.
# SPDX-License-Identifier: BSD-3-Clause
"""
Security event processor module for parsing and processing security events.
"""

import json
import os
import re
import subprocess
import logging
from typing import List, Dict
from ..core.config_manager import get_config

# Set up logging
logger = logging.getLogger(__name__)


class SecurityEventProcessor:
    """Handles parsing and processing of security events from various tools."""

    def __init__(self):
        """Initialize SecurityEventProcessor with caching for VirusTotal scans."""
        self._scanned_urls_cache = {}  # Cache for already scanned URLs {url: result}

    def _parse_signing_info(self, signing_info_str):
        """Parse signing info string into a dictionary"""
        try:
            # Remove curly braces and split by semicolon
            content = signing_info_str.strip('{}').strip()
            if not content:
                return {}

            info = {}
            for item in content.split(';'):
                if '=' in item:
                    key, value = item.split('=', 1)
                    key = key.strip()
                    # Clean up the value
                    value = value.strip().strip('"').strip()
                    # Remove any escaped quotes and newlines
                    value = value.replace('\\"', '"').replace('\\n', '').strip()
                    # Convert boolean strings
                    if value.lower() == 'yes':
                        value = True
                    elif value.lower() == 'no':
                        value = False
                    # Try to convert numbers
                    elif value.isdigit():
                        value = int(value)
                    info[key] = value
            return info
        except Exception as e:
            logger.error(f"Error parsing signing info: {e}")
            return {}

    def _clean_signing_info(self, signing_info):
        """Clean up signing info values"""
        cleaned = {}
        for key, value in signing_info.items():
            if isinstance(value, str):
                # First remove the newline and whitespace pattern
                value = value.replace('\\n', '').replace('\n', '')

                # Remove leading whitespace after newline removal
                value = ' '.join(line.strip() for line in value.split())

                # Handle any HTML entities
                value = value.replace('"', '"')

                # Remove escaped characters
                value = value.replace('\\"', '"').replace('\\/', '/')

                # Remove any remaining escape characters
                value = value.replace('\\', '')

                # Clean up any remaining quotes
                value = value.strip('"')

                # For signingID, keep the quotes
                if key == 'signingID':
                    value = f'"{value}"'

            cleaned[key] = value
        return cleaned

    def _parse_process_ancestors(self, ancestors_str):
        """Parse process ancestors string into a list of dictionaries"""
        try:
            # Remove parentheses and split by comma
            content = ancestors_str.strip('()').strip()
            if not content:
                return []

            ancestors = []
            # Split the content into individual ancestor blocks
            blocks = re.findall(r'\{([^}]+)\}', content)

            for block in blocks:
                ancestor = {}
                for item in block.split(';'):
                    if '=' in item:
                        key, value = item.split('=', 1)
                        key = key.strip()
                        # Clean up the value
                        value = value.strip().strip('"').strip()
                        # Remove any escaped quotes and newlines
                        value = value.replace('\\"', '"').replace('\\n', '').strip()
                        try:
                            # Try to convert to int if possible
                            value = int(value)
                        except ValueError:
                            pass
                        ancestor[key] = value
                if ancestor:  # Only add if we got some data
                    ancestors.append(ancestor)
            return ancestors
        except Exception as e:
            logger.error(f"Error parsing process ancestors: {e}")
            return []

    def collect_blockblock_unified_log_events(self, since="10m"):
        """
        Collect BlockBlock events from the unified log and add them to security_events.
        Only include events with valid path and timestamp, deduplicated.
        """
        print(
            f"\nCollecting BlockBlock events from unified log (last {since})..."
        )
        cmd = [
            "log", "show",
            "--predicate",
            (
                "subsystem == 'com.objective-see.blockblock' "
                "AND eventMessage CONTAINS \"user says, 'allow'\""
            ),
            "--style", "json",
            "--info", "--debug",
            "--last", since
        ]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=False)
            if result.returncode != 0:
                print("⚠️ Could not read BlockBlock events from unified log.")
                return

            # Parse and deduplicate events using helper
            self._parse_and_deduplicate_events(
                result.stdout,
                self._parse_blockblock_json_event_data,
                lambda event: (
                    event["event"]["details"].get("timestamp", ""),
                    event["event"]["details"].get("path", "")
                ),
                "BlockBlock"
            )

        except Exception as e:
            logger.error(f"Error collecting BlockBlock unified log events: {e}")

    def _parse_and_deduplicate_events(self, stdout_data, parse_func, key_func, tool_name):
        """
        Parse JSON events from unified log output and deduplicate based on key function.

        Args:
            stdout_data: Raw stdout from log command
            parse_func: Function to parse individual event data
            key_func: Function to extract deduplication key from parsed event
            tool_name: Name of tool for error messages
        """
        if not stdout_data.strip():
            return

        try:
            events_data = json.loads(stdout_data.strip())
            if not isinstance(events_data, list):
                print(f"⚠️ Unexpected JSON format from {tool_name} log command.")
                return

            seen = set()
            for event_data in events_data:
                event = parse_func(event_data)
                if event:
                    # Extract key for deduplication
                    key = key_func(event)
                    # Validate key has required values
                    if all(key):
                        if key not in seen:
                            self.report_data["security_events"].append(event)
                            seen.add(key)
        except json.JSONDecodeError as e:
            print(f"⚠️ Failed to parse {tool_name} JSON output: {e}")

    def _parse_blockblock_json_event_data(self, data):
        """
        Parse a BlockBlock log event from JSON data (not a JSON string)
        and extract event details.
        Handles both persistence events and paste protection events (v2.3.0+).
        Only returns events with a valid path/target and timestamp.
        """
        try:
            msg = data.get("eventMessage", "")

            # Check for paste protection event (v2.3.0+)
            if msg and ("paste" in msg.lower() or "clickfix" in msg.lower() or "terminal" in msg.lower()):
                return self._parse_paste_protection_event(data, msg)

            # Only process persistence events if it looks like a BlockBlock allow event
            if not (msg and "user says, 'allow'" in msg):
                return None

            # Extract process JSON
            process_info = {}
            process_match = re.search(r'process="process":(\{[^}]*\})', msg)
            if process_match:
                try:
                    process_info = json.loads(process_match.group(1))
                except Exception:
                    process_info = {}

            # Extract item file path
            path_match = re.search(r'item file path=([^,]+)', msg)
            item_file_path = path_match.group(1).strip() if path_match else ""
            # Extract event time (from timestamp=...)
            event_time_match = re.search(r'timestamp=([^,]+)', msg)
            event_time = event_time_match.group(1).strip() if event_time_match else ""
            # Only process if both are present
            if not item_file_path or not event_time:
                return None
            # Extract binary name
            binary_name = ""
            bin_name_match = re.search(r'item binary=name=([^,\s]+)', msg)
            if bin_name_match:
                binary_name = bin_name_match.group(1).strip()
            # Extract binary path
            binary_path = ""
            bin_path_match = re.search(r'object=([^,\n]+)', msg)
            if bin_path_match:
                binary_path = bin_path_match.group(1).strip()
            # Compose event
            return {
                "tool": "BLOCKBLOCK",
                "timestamp": data.get("timestamp", event_time),
                "event": {
                    "type": "user_action",
                    "details": {
                        "action": "allowed",
                        "path": item_file_path,
                        "binary_name": binary_name,
                        "binary_path": binary_path,
                        "process": process_info,
                        "timestamp": event_time
                    }
                }
            }
        except Exception:
            return None

    def _parse_paste_protection_event(self, data, msg):
        """
        Parse a BlockBlock paste protection event (v2.3.0+).
        These events alert on paste operations into Terminal to help thwart ClickFix attacks.

        Args:
            data: Raw event data
            msg: Event message string

        Returns:
            Parsed paste protection event or None
        """
        try:
            # Extract event time
            event_time = data.get("timestamp", "")
            if not event_time:
                return None

            # Extract target application (usually Terminal)
            target_app = "Unknown"
            app_match = re.search(r'(Terminal|iTerm|iTerm2)', msg, re.IGNORECASE)
            if app_match:
                target_app = app_match.group(1)

            # Extract paste operation details
            paste_content_preview = ""
            content_match = re.search(r'pasted?[:\s]+([^\n]+)', msg, re.IGNORECASE)
            if content_match:
                paste_content_preview = content_match.group(1).strip()[:100]  # Limit to 100 chars

            # Extract action (allow/block)
            action = "alerted"
            if "user says, 'allow'" in msg or "allowed" in msg.lower():
                action = "allowed"
            elif "blocked" in msg.lower():
                action = "blocked"

            # Extract responsible process if available
            process_info = {}
            process_match = re.search(r'process[:\s]+([^\n,]+)', msg)
            if process_match:
                process_info = {"name": process_match.group(1).strip()}

            return {
                "tool": "BLOCKBLOCK",
                "timestamp": event_time,
                "event": {
                    "type": "paste_protection",
                    "details": {
                        "action": action,
                        "target_app": target_app,
                        "paste_preview": paste_content_preview,
                        "process": process_info,
                        "timestamp": event_time,
                        "raw_message": msg
                    }
                }
            }
        except Exception as e:
            logger.debug(f"Error parsing paste protection event: {e}")
            return None

    def collect_lulu_unified_log_events(self, since="10m"):
        """
        Collect LuLu events from the unified log and add them to security_events.
        Only include user interaction events, deduplicated.

        LuLu v4.2.1+ Features:
        - Rule duration is now relative rather than fixed end time (#811, #813)
        - User-created rules can be exported/imported (#814)
        - Flows for exited processes are now denied (security improvement)
        - UI improvements for alert presentation (#812)

        Event log format remains compatible across versions.
        """
        print(
            f"\nCollecting LuLu events from unified log (last {since})..."
        )
        cmd = [
            "log", "show",
            "--predicate",
            'subsystem == "com.objective-see.lulu" AND eventMessage CONTAINS "(user) response:"',
            "--style", "json",
            "--info", "--debug",
            "--last", since
        ]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=False)
            if result.returncode != 0:
                print("⚠️ Could not read LuLu events from unified log.")
                return

            # Parse and deduplicate events using helper
            self._parse_and_deduplicate_events(
                result.stdout,
                self._parse_lulu_json_event_data,
                lambda event: (
                    event["event"]["details"].get("timestamp", ""),
                    event["event"]["details"].get("app_path", "")
                ),
                "LuLu"
            )

        except Exception as e:
            logger.error(f"Error collecting LuLu unified log events: {e}")

    def collect_xprotect_unified_log_events(self, since="10m"):
        """
        Collect XProtect events from the unified log and add them to security_events.
        XProtect events include malware detection, quarantine actions, and security scans.
        """
        logger.info(
            f"\nCollecting XProtect events from unified log (last {since})..."
        )

        try:
            cmd = [
                'log', 'show',
                '--predicate',
                (
                    'subsystem == "com.apple.xprotect" '
                    'OR subsystem == "com.apple.XProtect" '
                    'OR process == "XProtect" '
                    'OR eventMessage CONTAINS "XProtect" '
                    'OR eventMessage CONTAINS "malware" '
                    'OR eventMessage CONTAINS "quarantine"'
                ),
                '--style', 'json',
                '--last', since
            ]

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

            if result.returncode != 0:
                print("⚠️ Could not read XProtect events from unified log.")
                logger.warning(f"XProtect log collection failed: {result.stderr}")
                return

            # Parse each line as JSON
            for line in result.stdout.strip().split('\n'):
                line = line.strip()
                if line:
                    try:
                        event_data = json.loads(line)
                        event = self._parse_xprotect_json_event_data(event_data)
                        if event:
                            self.report_data["security_events"].append(event)
                            logger.debug(f"Added XProtect event: {event.get('event', {}).get('type', 'unknown')}")

                    except json.JSONDecodeError:
                        logger.debug(f"Failed to parse XProtect JSON line: {line[:100]}...")
                    except Exception as e:
                        logger.debug(f"Error processing XProtect event: {e}")

        except subprocess.TimeoutExpired:
            logger.warning("XProtect log collection timed out")
            print("⚠️ XProtect log collection timed out")
        except Exception as e:
            logger.error(f"Error collecting XProtect unified log events: {e}")

    def _parse_xprotect_json_event_data(self, data):
        """
        Parse an XProtect log event from JSON data and extract event details.
        Returns events related to malware detection, quarantine actions, and security scans.
        """
        try:
            msg = data.get("eventMessage", "")

            # Skip empty or irrelevant messages
            if not msg:
                return None

            # Extract timestamp
            event_time = data.get("timestamp", "")
            if not event_time:
                return None

            # Determine event type and extract details
            event_type, details = self._parse_xprotect_event_type(msg)

            # Compose event
            return {
                "tool": "XPROTECT",
                "timestamp": event_time,
                "event": {
                    "type": event_type,
                    "details": {
                        **details,
                        "timestamp": event_time,
                        "raw_message": msg
                    }
                }
            }
        except Exception as e:
            logger.debug(f"Error parsing XProtect event: {e}")
            return None

    def _parse_xprotect_event_type(self, msg: str) -> tuple:
        """
        Parse XProtect message to determine event type and extract details.

        Args:
            msg: Event message string

        Returns:
            Tuple of (event_type, details_dict)
        """
        details = {}

        # Malware detection events
        if "malware" in msg.lower() or "threat" in msg.lower():
            return self._parse_malware_event(msg, details)

        # Quarantine events
        if "quarantine" in msg.lower():
            return self._parse_quarantine_event(msg, details)

        # XProtect update events
        if "update" in msg.lower() and ("xprotect" in msg.lower() or "definition" in msg.lower()):
            return "update", details

        # XProtect scan events
        if "scan" in msg.lower() or "check" in msg.lower():
            return "scan", details

        # General XProtect activity
        return "activity", details

    def _parse_malware_event(self, msg: str, details: dict) -> tuple:
        """Parse malware detection event."""
        file_match = re.search(r'file[:\s]+([^\s]+)', msg, re.IGNORECASE)
        if file_match:
            details["file_path"] = file_match.group(1)

        threat_match = re.search(r'(threat|malware)[:\s]+([^\s,]+)', msg, re.IGNORECASE)
        if threat_match:
            details["threat_name"] = threat_match.group(2)

        return "malware_detection", details

    def _parse_quarantine_event(self, msg: str, details: dict) -> tuple:
        """Parse quarantine action event."""
        file_match = re.search(r'/[^\s]+', msg)
        if file_match:
            details["quarantined_file"] = file_match.group()

        return "quarantine_action", details

    def _parse_lulu_json_event_data(self, data):
        """
        Parse a LuLu log event from JSON data (not a JSON string)
        and extract event details.
        Only returns events with valid app path and timestamp.
        """
        try:
            msg = data.get("eventMessage", "")

            # Only process if it looks like a LuLu user response event
            if not (msg and "(user) response:" in msg):
                return None

            # Extract action (allow/block)
            action = "unknown"
            if '"allow"' in msg:
                action = "allowed"
            elif '"block"' in msg:
                action = "blocked"

            # Extract app path - format: "(user) response: "allow" for /Applications/Warp.app, that was trying to connect..."
            app_path = ""
            path_match = re.search(r'"(?:allow|block)" for ([^,]+)', msg)
            if path_match:
                app_path = path_match.group(1).strip()

            # Extract connection details - format: "trying to connect to 34.117.41.85:443"
            connection_info = ""
            conn_match = re.search(r'trying to connect to ([^,\s]+)', msg)
            if conn_match:
                connection_info = conn_match.group(1).strip()

            # Use timestamp from the log entry
            event_time = data.get("timestamp", "")

            # Only process if we have essential info
            if not app_path or not event_time:
                return None

            # Compose event
            return {
                "tool": "LULU",
                "timestamp": event_time,
                "event": {
                    "type": "user_action",
                    "details": {
                        "action": action,
                        "app_path": app_path,
                        "connection": connection_info,
                        "timestamp": event_time
                    }
                }
            }
        except Exception:
            return None

    def _extract_urls_from_lulu_events(self, security_events: List[Dict]) -> List[str]:
        """
        Extract URLs and IP addresses from LuLu events for VirusTotal scanning.

        Args:
            security_events: List of security events containing LuLu events

        Returns:
            List of unique URLs/IPs to scan
        """
        urls_to_scan = set()

        logger.debug(f"Checking {len(security_events)} security events for LuLu connections")

        for event in security_events:
            if event.get("tool") == "LULU":
                connection = self._extract_connection_from_lulu_event(event)

                if connection:
                    # Handle IPv6 and IPv4 addresses with ports properly
                    clean_address = self._extract_address_from_connection(connection)

                    logger.debug(f"Clean address extracted: '{clean_address}'")

                    # Skip common local/private IPs
                    if clean_address and self._is_scannable_address(clean_address):
                        logger.debug(f"Address is scannable, adding: '{clean_address}'")
                        urls_to_scan.add(clean_address)
                    else:
                        logger.debug(f"Address not scannable or empty: '{clean_address}'")

        logger.info(f"Extracted {len(urls_to_scan)} URLs from LuLu events: {list(urls_to_scan)}")
        return list(urls_to_scan)

    def _extract_connection_from_lulu_event(self, event: Dict) -> str:
        """
        Extract connection string from a LuLu event.

        Args:
            event: LuLu event dict

        Returns:
            Connection string or empty string
        """
        event_data = event.get("event", {})
        logger.debug(f"Found LULU event: event_data type={type(event_data)}")

        # If event is a string, extract connection using regex
        if isinstance(event_data, str):
            logger.debug(f"Parsing string event: {event_data[:100]}")
            # Extract connection details - format: "trying to connect to 208.103.161.1:443"
            conn_match = re.search(r'trying to connect to ([^,\s]+)', event_data)
            if conn_match:
                connection = conn_match.group(1).strip()
                logger.debug(f"Extracted connection from string: '{connection}'")
                return connection

        # If event is a dict, extract details
        elif isinstance(event_data, dict):
            event_details = event_data.get("details", {})
            connection = event_details.get("connection", "")
            logger.debug(f"Connection from dict: '{connection}'")
            return connection

        return ""

    def _extract_address_from_connection(self, connection: str) -> str:
        """
        Extract the address part from a connection string, handling both IPv4 and IPv6 formats.

        Args:
            connection: Connection string like "1.2.3.4:443" or "2600:1f18:4c12:9a01:d7c:d6ac:fb17:9bfc:443"

        Returns:
            Clean address without port
        """
        if not connection:
            return ""

        # Handle IPv6 addresses with brackets: [2001:db8::1]:443
        if connection.startswith('[') and ']:' in connection:
            return connection[1:connection.rfind(']:')]

        # Handle IPv4 addresses with port: 1.2.3.4:443
        if ':' in connection:
            # Count colons to distinguish IPv4 from IPv6
            colon_count = connection.count(':')

            # IPv4 has exactly one colon (address:port)
            if colon_count == 1:
                return connection.split(':')[0]

            # IPv6 has multiple colons - need to find the last one that's likely the port
            # IPv6 format: address:port (where address contains colons)
            # Try to parse as IPv6:port by finding the rightmost colon followed by digits
            import re
            port_match = re.search(r':(\d+)$', connection)
            if port_match:
                # Remove the :port part
                return connection[:port_match.start()]

            # If no port pattern found, assume it's a raw IPv6 address without port
            return connection

        # No colons, return as-is (domain name or IPv4 without port)
        return connection

    def _is_scannable_address(self, address: str) -> bool:
        """
        Check if an IP address or domain is worth scanning.

        Args:
            address: IP address or domain name

        Returns:
            True if the address should be scanned
        """
        import ipaddress

        # Skip empty addresses
        if not address or address.strip() == "":
            return False

        try:
            # Try to parse as IP address
            ip = ipaddress.ip_address(address)

            # Skip private IP ranges
            if ip.is_private or ip.is_loopback or ip.is_link_local:
                return False

            # Skip multicast and reserved ranges
            if ip.is_multicast or ip.is_reserved:
                return False

            return True

        except ValueError:
            # Not an IP address, assume it's a domain name
            # Skip obvious local domains
            local_domains = [
                'localhost', 'local', '.local',
                'test', '.test', 'internal', '.internal'
            ]

            address_lower = address.lower()
            for local_domain in local_domains:
                if local_domain in address_lower:
                    return False

            # If it looks like a domain name, scan it
            return '.' in address or len(address) > 4

    def scan_lulu_connections_with_virustotal(self, security_events: List[Dict]) -> List[Dict]:
        """
        Scan network connections detected by LuLu using VirusTotal.
        Uses caching to avoid scanning the same URL/IP multiple times.

        Args:
            security_events: List of security events containing LuLu events

        Returns:
            List of VirusTotal scan results
        """
        # Ensure cache exists (needed for CompositeTester with multiple inheritance)
        if not hasattr(self, '_scanned_urls_cache'):
            self._scanned_urls_cache = {}

        all_urls = self._extract_urls_from_lulu_events(security_events)

        if not all_urls:
            logger.info("No scannable URLs found in LuLu events")
            return []

        # Separate URLs into new and cached
        new_urls, cached_urls = self._separate_urls_by_cache(all_urls)

        if not new_urls:
            logger.info("All URLs already scanned - using cached results")
            return [self._scanned_urls_cache[url] for url in cached_urls]

        print(f"\n🔍 Scanning {len(new_urls)} new network connection(s) with VirusTotal...")

        # Scan new URLs
        scan_results = self._scan_new_urls(new_urls)

        # Add cached results to return list
        for url in cached_urls:
            scan_results.append(self._scanned_urls_cache[url])

        return scan_results

    def _separate_urls_by_cache(self, all_urls: List[str]) -> tuple:
        """
        Separate URLs into new and cached lists.

        Args:
            all_urls: List of all URLs to check

        Returns:
            Tuple of (new_urls, cached_urls)
        """
        unique_urls = list(set(all_urls))  # Remove duplicates from this batch
        new_urls = [url for url in unique_urls if url not in self._scanned_urls_cache]
        cached_urls = [url for url in unique_urls if url in self._scanned_urls_cache]

        logger.info(f"Found {len(unique_urls)} unique URLs/IPs ({len(new_urls)} new, {len(cached_urls)} cached)")

        if cached_urls:
            print(f"ℹ️  {len(cached_urls)} URL(s) already scanned (using cached results)")

        return new_urls, cached_urls

    def _scan_new_urls(self, new_urls: List[str]) -> List[Dict]:
        """
        Scan new URLs with VirusTotal and cache results.

        Args:
            new_urls: List of URLs to scan

        Returns:
            List of scan results
        """
        # Import VirusTotal analyzer
        try:
            from ..security.virustotal_analyzer import VirusTotalAnalyzer
            vt_analyzer = VirusTotalAnalyzer()
        except ImportError:
            logger.warning("VirusTotal analyzer not available")
            return []

        scan_results = []

        for url in new_urls:
            try:
                print(f"   🌐 Scanning: {url}")
                result = vt_analyzer.analyze_url(url)

                if result:
                    result['source'] = 'lulu_connection'
                    result['scanned_url'] = url

                    # Cache the result
                    self._scanned_urls_cache[url] = result
                    scan_results.append(result)

                    # Show basic result
                    self._print_scan_status(url, result.get('status', 'unknown'))

            except Exception as e:
                logger.error(f"Error scanning URL {url}: {e}")
                print(f"      ❌ Error scanning {url}: {e}")

        return scan_results

    def _print_scan_status(self, url: str, status: str):
        """Print scan result status."""
        if status == 'malicious':
            print(f"      ⚠️  FLAGGED AS MALICIOUS: {url}")
        elif status == 'suspicious':
            print(f"      ⚠️  FLAGGED AS SUSPICIOUS: {url}")
        elif status == 'clean':
            print(f"      ✅ Clean: {url}")
        else:
            print(f"      ℹ️  Status: {status}")

    def _check_code_signing(self, munki_item_name=None, output_directory=None):
        """Check code signing information for applications and generate configuration profiles"""
        print("\nCode Signing Verification & Configuration Profile Generation")
        print("=" * 60)
        print("Please drag and drop the applications to check code signing information")
        print("and automatically generate required configuration profiles.")

        # Import profile generation modules
        try:
            from ..profiles.app_analyzer import AppAnalyzer
            from ..profiles.profile_generator import ProfileGenerator

            # Check if self is already a ProfileGenerator (via CompositeTester inheritance)
            if isinstance(self, ProfileGenerator):
                # Use self as the generator, just update its properties
                generator = self
                if output_directory:
                    generator.output_directory = output_directory
                if munki_item_name:
                    generator.munki_item_name = munki_item_name
                analyzer = AppAnalyzer()
                print("✅ Configuration profile generation enabled (using inherited generator)")
            else:
                # Create new instances (when called from standalone SecurityEventProcessor)
                analyzer = AppAnalyzer()
                generator = ProfileGenerator(
                    output_directory=output_directory or os.getcwd(),
                    munki_item_name=munki_item_name
                )
                print("✅ Configuration profile generation enabled")
        except ImportError as e:
            logger.warning(f"Profile generation not available: {e}")
            analyzer = None
            generator = None
            print("⚠️  Configuration profile generation not available")

        application_analyses = []

        while True:
            try:
                print("\nDrag and drop an application here (or press Enter to skip):")
                app_path = input().strip()

                # Allow user to skip
                if not app_path:
                    break

                # Clean up the path - remove quotes and unescape shell-escaped characters
                # macOS terminal escapes special chars like |, &, (, ), etc. with backslashes
                import re
                app_path = app_path.strip('"').strip("'")  # Remove surrounding quotes
                app_path = re.sub(r'\\(.)', r'\1', app_path)  # Remove escape backslashes

                if not os.path.exists(app_path):
                    print(f"❌ Error: Application not found at {app_path}")
                    continue

                print(f"\nChecking code signing for: {app_path}")
                print("----------------------------------------------------------------")

                # Get Team and Bundle IDs
                codesign_cmd = ["/usr/bin/codesign", "-dv", app_path]
                ids_result = subprocess.run(
                    codesign_cmd,
                    capture_output=True,
                    text=True,
                    check=False
                )

                # Extract Team and Bundle IDs from stderr (codesign outputs to stderr)
                ids = []
                for line in ids_result.stderr.splitlines():
                    if line.startswith("Identifier="):
                        ids.append(line.replace("Identifier=", "BundleID: "))

                # Get detailed signing information
                deep_cmd = ["/usr/bin/codesign", "-d", "--deep", "--verbose=2", "-r-", app_path]
                deep_result = subprocess.run(
                    deep_cmd,
                    capture_output=True,
                    text=True,
                    check=False
                )

                print("\nFull App Information")
                print("----------------------------------------------------------------")
                print(deep_result.stderr.strip())
                print("----------------------------------------------------------------")
                print("\n".join(ids))
                print()

                # Add to report data
                result = {
                    "path": app_path,
                    "full_info": deep_result.stderr.strip(),
                    "identifiers": ids
                }
                if "code_signing_results" not in self.report_data:
                    self.report_data["code_signing_results"] = []
                self.report_data["code_signing_results"].append(result)

                # Perform configuration profile analysis if analyzer is available
                if analyzer and app_path.endswith('.app'):
                    print(f"\n🔍 Analyzing {os.path.basename(app_path)} for configuration profile requirements...")
                    analysis = analyzer.analyze_application(app_path)

                    if analysis:
                        application_analyses.append(analysis)

                        # Extract application icon if we have the necessary information
                        config = get_config()
                        if munki_item_name and output_directory and config.is_icon_extraction_enabled():
                            try:
                                from ..utils.file_helpers import FileHelpers
                                file_helper = FileHelpers()

                                print("\n📱 Extracting application icon...")
                                icon_path = file_helper.extract_app_icon(app_path, output_directory, munki_item_name)

                                if icon_path:
                                    # Add icon information to the analysis
                                    analysis['extracted_icon'] = {
                                        'icon_path': icon_path,
                                        'munki_name': munki_item_name
                                    }

                            except Exception as e:
                                logger.warning(f"Failed to extract icon: {e}")
                                print(f"   ⚠️  Icon extraction failed: {e}")
                        elif munki_item_name and output_directory and not config.is_icon_extraction_enabled():
                            print("\n📱 Icon extraction disabled in config - skipping")

                        # Display sub-applications if found
                        sub_applications = analysis.get('sub_applications', [])
                        if sub_applications:
                            print(f"\n🔍 Found {len(sub_applications)} sub-application(s):")
                            for sub_app in sub_applications:
                                sub_name = sub_app.get('app_name', 'Unknown')
                                sub_required = sub_app.get('required_profiles', {})

                                # Check if sub-app needs profiles
                                sub_needs_profiles = any([
                                    sub_required.get('pppc'),
                                    sub_required.get('notifications'),
                                    sub_required.get('system_extensions'),
                                    sub_required.get('kernel_extensions'),
                                    sub_required.get('content_filter'),
                                    sub_required.get('screen_recording'),
                                    sub_required.get('managed_login_items')
                                ])

                                if sub_needs_profiles:
                                    print(f"   📱 {sub_name} - Configuration profiles required")
                                else:
                                    print(f"   📱 {sub_name} - No configuration profiles needed")

                        # Display detected requirements for main app
                        required = analysis.get('required_profiles', {})
                        detected_any = False

                        print(f"\n📋 Main Application ({os.path.basename(app_path)}) Requirements:")

                        if required.get('pppc'):
                            print(f"   📋 PPPC Requirements: {len(required['pppc'])} detected")
                            detected_any = True

                        if required.get('notifications'):
                            print("   🔔 Notifications: Required")
                            detected_any = True

                        if required.get('system_extensions'):
                            detected_any = True

                        if required.get('kernel_extensions'):
                            print(f"   ⚙️  Kernel Extensions: {len(required['kernel_extensions'])} detected")
                            detected_any = True

                        if required.get('content_filter'):
                            print("   🌐 Content Filter: Required")
                            detected_any = True

                        if required.get('screen_recording'):
                            print("   📺 Screen Recording: Required")
                            detected_any = True

                        if required.get('managed_login_items'):
                            print(f"   🚀 Managed Login Items: {len(required['managed_login_items'])} detected")
                            detected_any = True

                        if not detected_any:
                            print("   ℹ️  No configuration profile requirements detected")

                        # Display manual review warnings if any
                        manual_warnings = analysis.get('manual_review_warnings', [])
                        if manual_warnings:
                            print(f"\n⚠️  Manual Review Recommendations for {os.path.basename(app_path)}:")
                            for warning in manual_warnings:
                                print(f"   ⚠️  {warning['message']}")

            except Exception as e:
                logger.error(f"Error checking code signing: {e}")
                print(f"❌ Error checking code signing: {e}")

        # Generate configuration profiles if we have analyses
        if analyzer and generator and application_analyses:
            print(f"\n📝 Generating configuration profiles for {len(application_analyses)} applications...")
            try:
                generated_profiles = generator.generate_profiles_from_analysis(application_analyses)

                if generated_profiles:
                    # Save profiles to disk
                    saved_files = generator.save_profiles(generated_profiles)

                    print(f"\n✅ Generated {len(generated_profiles)} configuration profiles:")
                    for profile in generated_profiles:
                        print(f"   - {profile['type']}: {profile['filename']}")

                        # Display apps covered by this profile
                        if profile.get('apps'):
                            apps_list = ', '.join(profile['apps'])
                            print(f"     Apps: {apps_list}")

                        # Display warnings for non-manageable permissions
                        if profile.get('non_manageable_warnings'):
                            warnings = profile['non_manageable_warnings']
                            if warnings.get('bluetooth'):
                                print(f"     ⚠️  Bluetooth access detected but not manageable via PPPC: {', '.join(warnings['bluetooth'])}")
                            if warnings['camera']:
                                print(f"     ⚠️  Camera access detected but not manageable via PPPC (deny-only): {', '.join(warnings['camera'])}")
                            if warnings['microphone']:
                                print(f"     ⚠️  Microphone access detected but not manageable via PPPC (deny-only): {', '.join(warnings['microphone'])}")
                            if warnings['location']:
                                print(f"     ⚠️  Location access detected but not manageable via PPPC: {', '.join(warnings['location'])}")

                    # Add profile generation results to report data
                    if "configuration_profiles" not in self.report_data:
                        self.report_data["configuration_profiles"] = {}

                    # Collect all manual review warnings from analyses
                    all_manual_warnings = []
                    for analysis in application_analyses:
                        manual_warnings = analysis.get('manual_review_warnings', [])
                        all_manual_warnings.extend(manual_warnings)

                    self.report_data["configuration_profiles"]["generated_profiles"] = generated_profiles
                    self.report_data["configuration_profiles"]["saved_files"] = saved_files
                    self.report_data["configuration_profiles"]["profile_summary"] = generator.generate_profile_summary(generated_profiles)
                    self.report_data["configuration_profiles"]["statistics"] = generator.get_profile_statistics(generated_profiles)
                    self.report_data["configuration_profiles"]["manual_review_warnings"] = all_manual_warnings

                    print(f"\n📁 Configuration profiles saved to: {generator.output_directory}")
                else:
                    print("\nℹ️  No configuration profiles were required for the analyzed applications")

                    # Still collect and report manual review warnings even if no profiles generated
                    if "configuration_profiles" not in self.report_data:
                        self.report_data["configuration_profiles"] = {}

                    # Collect all manual review warnings from analyses
                    all_manual_warnings = []
                    for analysis in application_analyses:
                        manual_warnings = analysis.get('manual_review_warnings', [])
                        all_manual_warnings.extend(manual_warnings)

                    if all_manual_warnings:
                        self.report_data["configuration_profiles"]["manual_review_warnings"] = all_manual_warnings
                        print(f"\n⚠️  Manual review recommendations available for {len(all_manual_warnings)} item(s) - see report for details")

            except Exception as e:
                logger.error(f"Error generating configuration profiles: {e}")
                print(f"❌ Error generating configuration profiles: {e}")

        # Process application analyses for report data (regardless of profile generation)
        if application_analyses:
            self.report_data["application_analyses"] = application_analyses

            # Extract Rosetta information for the report
            rosetta_info = {}
            for analysis in application_analyses:
                app_path = analysis.get('app_path', 'Unknown')
                rosetta_data = analysis.get('rosetta_info', {})
                if rosetta_data:  # Only add if there's Rosetta data
                    rosetta_info[app_path] = rosetta_data

            if rosetta_info:
                self.report_data["rosetta_info"] = rosetta_info
                print(f"\n🔍 Rosetta compatibility analysis completed for {len(rosetta_info)} application(s)")

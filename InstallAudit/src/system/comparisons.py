# Copyright (c) 2026 Paul Cossey. All rights reserved.
# SPDX-License-Identifier: BSD-3-Clause
"""
System comparison methods for InstallAudit.
"""

import subprocess
import logging
from datetime import datetime

logger = logging.getLogger(__name__)


class SystemComparator:
    """Handles system state comparisons and change detection."""

    # Constants for duplicated string literals
    FIELD_NAME = 'Name:'
    FIELD_DEVELOPER_NAME = 'Developer Name:'
    FIELD_TYPE = 'Type:'
    FIELD_IDENTIFIER = 'Identifier:'
    FIELD_TEAM_IDENTIFIER = 'Team Identifier:'
    FIELD_EXECUTABLE_PATH = 'Executable Path:'
    NULL_VALUE = '(null)'
    UNKNOWN_DEVELOPER = 'Unknown Developer'
    PLIST_EXTENSION = '.plist'

    def __init__(self, initial_sysext=None, initial_btm=None, initial_notifications=None, report_data=None):
        """Initialize SystemComparator with initial state data."""
        self.initial_sysext = initial_sysext
        self.initial_btm = initial_btm
        self.initial_notifications = initial_notifications
        self.report_data = report_data or {}

    def _compare_system_checks(self):
        """Compare current system state with initial state"""
        try:
            print("\n\nComparing system states")
            print("=" * 60)

            changes = {
                "system_extensions": [],
                "login_items": [],
                "notifications": []
            }

            # Check system extensions
            new_extensions = self._compare_system_extensions()
            if new_extensions:
                changes["system_extensions"] = new_extensions

            # Check managed login items
            print("Checking managed login items changes...")
            btm_changes = self._compare_btm_database()
            file_changes = self._compare_launch_items()

            # Combine all login item changes
            all_changes = []
            all_changes.extend(btm_changes)
            all_changes.extend(file_changes)

            if all_changes:
                changes["login_items"] = all_changes
                print(f"   Found {len(all_changes)} login item changes")
            else:
                print("   No login items changes detected")

            # Check notifications database changes
            notification_changes, stats = self._compare_notifications_database()
            if notification_changes:
                changes["notifications"] = notification_changes
                print("\nNotification Changes Summary:")
                print(f"  New permissions: {stats['new_permissions']}")
                print(f"  Status changes: {stats['status_changes']}")
                print(f"  Apps with new notifications: {stats['new_activity']}")
            else:
                print("No Notification changes found")

            # Always save system changes to report data
            self.report_data["system_changes"] = changes

            return changes

        except Exception as e:
            logger.error(f"Error comparing system states: {e}")
            print(f"❌ Error comparing system states: {e}")
            return None

    def _compare_system_extensions(self):
        """Check system extensions and return list of new extensions"""
        print("Checking system extensions changes...")
        current_sysext = subprocess.run(
            ["systemextensionsctl", "list"],
            capture_output=True,
            text=True
        ).stdout.strip()

        initial_sysext = getattr(self, 'initial_sysext', '')
        if current_sysext != initial_sysext:
            initial_lines = set(initial_sysext.splitlines()) if initial_sysext else set()
            current_lines = set(current_sysext.splitlines())
            new_extensions = current_lines - initial_lines
            if new_extensions:
                return list(new_extensions)
        return []

    def _parse_btm_items(self, btm_output):
        """Parse BTM output into structured items with full details using correct BTM format"""
        items = {}
        if not btm_output:
            return items

        lines = btm_output.split('\n')
        current_item = None
        current_item_data = {}

        for _i, line in enumerate(lines):
            line_stripped = line.strip()

            # Look for item numbers like "#1:", "#2:", etc.
            if line_stripped.startswith('#') and line_stripped.endswith(':') and len(line_stripped) < 10:
                # Save previous item if it exists
                if current_item is not None and current_item_data:
                    items[current_item] = current_item_data.copy()

                # Start new item
                current_item = line_stripped
                current_item_data = {
                    'item_number': line_stripped,
                    'uuid': '',
                    'name': '',
                    'developer_name': '',
                    'team_identifier': '',
                    'type': '',
                    'flags': '',
                    'disposition': '',
                    'identifier': '',
                    'url': '',
                    'executable_path': '',
                    'generation': '',
                    'parent_identifier': '',
                    'is_managed': False,
                    'is_legacy': False,
                    'raw_lines': [line],
                    'details': []
                }

            elif current_item is not None and line_stripped:
                current_item_data['raw_lines'].append(line)

                # Parse specific fields based on actual BTM format
                if 'UUID:' in line:
                    current_item_data['uuid'] = line.split('UUID:')[1].strip()
                elif self.FIELD_NAME in line and self.FIELD_DEVELOPER_NAME not in line:
                    current_item_data['name'] = line.split(self.FIELD_NAME)[1].strip()
                elif self.FIELD_DEVELOPER_NAME in line:
                    current_item_data['developer_name'] = line.split(self.FIELD_DEVELOPER_NAME)[1].strip()
                elif self.FIELD_TEAM_IDENTIFIER in line:
                    current_item_data['team_identifier'] = line.split(self.FIELD_TEAM_IDENTIFIER)[1].strip()
                elif self.FIELD_TYPE in line:
                    current_item_data['type'] = line.split(self.FIELD_TYPE)[1].strip()
                elif 'Flags:' in line:
                    current_item_data['flags'] = line.split('Flags:')[1].strip()
                    # Check if managed and legacy flags are present
                    if 'managed' in line.lower():
                        current_item_data['is_managed'] = True
                    if 'legacy' in line.lower():
                        current_item_data['is_legacy'] = True
                elif 'Disposition:' in line:
                    current_item_data['disposition'] = line.split('Disposition:')[1].strip()
                elif line.strip().startswith(self.FIELD_IDENTIFIER):  # Use strip() to handle leading spaces
                    current_item_data['identifier'] = line.split(self.FIELD_IDENTIFIER)[1].strip()
                elif 'URL:' in line:
                    current_item_data['url'] = line.split('URL:')[1].strip()
                elif self.FIELD_EXECUTABLE_PATH in line:
                    current_item_data['executable_path'] = line.split(self.FIELD_EXECUTABLE_PATH)[1].strip()
                elif 'Generation:' in line:
                    current_item_data['generation'] = line.split('Generation:')[1].strip()
                elif 'Parent Identifier:' in line:
                    current_item_data['parent_identifier'] = line.split('Parent Identifier:')[1].strip()

                # Collect interesting details for reporting
                if any(keyword in line for keyword in [self.FIELD_NAME, self.FIELD_TYPE, self.FIELD_IDENTIFIER, 'URL:', self.FIELD_EXECUTABLE_PATH, self.FIELD_DEVELOPER_NAME, self.FIELD_TEAM_IDENTIFIER]):
                    current_item_data['details'].append(line.strip())

        # Don't forget the last item
        if current_item is not None and current_item_data:
            items[current_item] = current_item_data

        return items

    def _compare_btm_database(self):
        """Check BTM database and return list of BTM changes"""
        current_btm = subprocess.run(
            ["sfltool", "dumpbtm"],
            capture_output=True,
            text=True
        ).stdout.strip()

        # Store current BTM for profile generation
        self.current_btm = current_btm

        initial_btm = getattr(self, 'initial_btm', '')
        initial_btm_items = self._parse_btm_items(initial_btm)
        current_btm_items = self._parse_btm_items(current_btm)

        # Find new items by comparing identifiers for ALL BTM items (managed and non-managed)
        initial_all_identifiers = {
            data['identifier'] for data in initial_btm_items.values()
            if data.get('identifier') and data['identifier'] not in [self.NULL_VALUE, self.UNKNOWN_DEVELOPER]
        }
        current_all_identifiers = {
            data['identifier'] for data in current_btm_items.values()
            if data.get('identifier') and data['identifier'] not in [self.NULL_VALUE, self.UNKNOWN_DEVELOPER]
        }
        new_identifiers = current_all_identifiers - initial_all_identifiers

        # Create detailed reports for ALL new BTM items (managed and non-managed)
        btm_changes = []
        for _item_key, item_data in current_btm_items.items():
            if (item_data.get('identifier') in new_identifiers
                    and item_data.get('identifier')
                    and item_data['identifier'] not in [self.NULL_VALUE, self.UNKNOWN_DEVELOPER]
                    and not item_data['identifier'].startswith('com.apple.')
                    and not item_data['identifier'].startswith('16.com.apple.')
                    and not item_data['identifier'].startswith('8.com.apple.')
                    and not item_data['identifier'].startswith('2.com.apple.')):

                # Create a detailed description
                details = []
                if item_data.get('identifier'):
                    details.append(f"Identifier: {item_data['identifier']}")
                if item_data.get('name') and item_data['name'] != self.NULL_VALUE:
                    details.append(f"Name: {item_data['name']}")
                if item_data.get('type'):
                    details.append(f"Type: {item_data['type']}")
                if item_data.get('team_identifier'):
                    details.append(f"Team Identifier: {item_data['team_identifier']}")
                if item_data.get('url') and item_data['url'] != self.NULL_VALUE:
                    details.append(f"URL: {item_data['url']}")
                if item_data.get('executable_path') and item_data['executable_path'] != self.NULL_VALUE:
                    details.append(f"Executable Path: {item_data['executable_path']}")
                if item_data.get('developer_name') and item_data['developer_name'] != self.NULL_VALUE:
                    details.append(f"Developer: {item_data['developer_name']}")
                if item_data.get('flags'):
                    details.append(f"Flags: {item_data['flags']}")

                # Determine the type based on managed status
                is_managed = item_data.get('is_managed', False)
                item_type = 'managed_login_item' if is_managed else 'login_item'
                summary_prefix = 'New Managed Login Item' if is_managed else 'New Login Item'

                btm_change = {
                    'type': item_type,
                    'identifier': item_data['identifier'],
                    'name': item_data.get('name', ''),
                    'team_identifier': item_data.get('team_identifier', ''),
                    'executable_path': item_data.get('executable_path', ''),
                    'url': item_data.get('url', ''),
                    'summary': f"{summary_prefix}: {item_data['identifier']}",
                    'details': details,
                    'raw_btm_section': '\n'.join(item_data['raw_lines']),
                    'is_managed': is_managed
                }
                btm_changes.append(btm_change)

        return btm_changes

    def _get_launch_items(self):
        """Get current launch daemon and agent files"""
        items = set()
        try:
            # Check LaunchDaemons
            daemon_result = subprocess.run(["ls", "/Library/LaunchDaemons/"],
                                           capture_output=True, text=True)
            if daemon_result.returncode == 0:
                for item in daemon_result.stdout.strip().split('\n'):
                    if item.endswith(self.PLIST_EXTENSION):
                        items.add(f"LaunchDaemon: {item}")

            # Check LaunchAgents (system-wide)
            agent_result = subprocess.run(["ls", "/Library/LaunchAgents/"],
                                          capture_output=True, text=True)
            if agent_result.returncode == 0:
                for item in agent_result.stdout.strip().split('\n'):
                    if item.endswith(self.PLIST_EXTENSION):
                        items.add(f"LaunchAgent: {item}")

        except Exception:
            pass
        return items

    def _compare_launch_items(self):
        """Check actual LaunchDaemons and LaunchAgents files and return file changes"""
        initial_launch_items = getattr(self, 'initial_launch_items', set())
        current_launch_items = self._get_launch_items()

        # Store current launch items for profile generation
        self.current_launch_items = current_launch_items

        new_launch_items = current_launch_items - initial_launch_items

        if new_launch_items:
            return [f"New file: {item}" for item in sorted(new_launch_items)]
        return []

    def _compare_notifications_database(self):
        """Check notifications database changes and return changes and stats"""
        print("Checking notifications database changes...")
        current_notifications = self._check_notifications_db()

        # Create dictionaries for easier comparison
        initial_notifications = getattr(self, 'initial_notifications', [])
        initial_notifs = {n['bundle_id']: n for n in initial_notifications} if initial_notifications else {}
        current_notifs = {n['bundle_id']: n for n in current_notifications}

        # Compare notifications
        notification_changes = []

        # Track statistics for summary
        stats = {
            "new_permissions": 0,
            "status_changes": 0,
            "new_activity": 0
        }

        # Get all bundle IDs from both initial and current states
        all_bundle_ids = set(initial_notifs.keys()) | set(current_notifs.keys())

        # Process each bundle ID
        for bundle_id in all_bundle_ids:
            current_notif = current_notifs.get(bundle_id)
            initial_notif = initial_notifs.get(bundle_id)

            if current_notif and not initial_notif:
                # New notification entry
                notification_changes.append({
                    "type": "new",
                    "bundle_id": bundle_id,
                    "name": current_notif.get('name', ''),
                    "status": current_notif['status'],
                    "details": (
                        f"New notification permission for {bundle_id}: "
                        f"{current_notif['status']}"
                    ),
                    "is_helper": current_notif.get('is_helper', False),
                    "path": current_notif.get('path', ''),
                    "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                })
                stats["new_permissions"] += 1
            elif current_notif and initial_notif:
                # Check for status changes
                if current_notif['status'] != initial_notif['status']:
                    notification_changes.append({
                        "type": "modified",
                        "bundle_id": bundle_id,
                        "name": current_notif.get('name', ''),
                        "old_status": initial_notif['status'],
                        "new_status": current_notif['status'],
                        "details": f"Permission changed for {bundle_id}: {initial_notif['status']} → {current_notif['status']}",
                        "is_helper": current_notif.get('is_helper', False),
                        "path": current_notif.get('path', ''),
                        "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    })
                    stats["status_changes"] += 1

                # Check for notification count changes
                current_count = current_notif.get('notification_count', 0) or 0
                initial_count = initial_notif.get('notification_count', 0) or 0

                if current_count > initial_count:
                    new_notifications = current_count - initial_count
                    notification_changes.append({
                        "type": "activity",
                        "bundle_id": bundle_id,
                        "name": current_notif.get('name', ''),
                        "old_count": initial_count,
                        "new_count": current_count,
                        "new_notifications": new_notifications,
                        "last_notification": current_notif['last_notification'],
                        "details": f"New notifications for {bundle_id}: {new_notifications} new notifications",
                        "is_helper": current_notif.get('is_helper', False),
                        "path": current_notif.get('path', ''),
                        "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    })
                    stats["new_activity"] += 1

        return notification_changes, stats

    def _compare_versions(self, version1, version2):
        """Compare two version strings"""
        def normalize(v):
            return [int(x) for x in v.split(".")]

        v1 = normalize(version1)
        v2 = normalize(version2)

        for i in range(max(len(v1), len(v2))):
            n1 = v1[i] if i < len(v1) else 0
            n2 = v2[i] if i < len(v2) else 0
            if n1 < n2:
                return -1
            elif n1 > n2:
                return 1
        return 0

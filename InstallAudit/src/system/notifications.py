# Copyright (c) 2026 Paul Cossey. All rights reserved.
# SPDX-License-Identifier: BSD-3-Clause
"""
Notification-related methods for InstallAudit.
"""

import os
import glob
import sqlite3
import subprocess
import logging
from datetime import datetime

logger = logging.getLogger(__name__)


class NotificationChecker:
    """Handles notification database checks and monitoring."""

    def __init__(self):
        """Initialize NotificationChecker."""
        pass

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

    def _get_notification_db_path(self):
        """Get the path to the notifications database for the current user"""
        try:
            current_user = self._get_console_user()
            if not current_user:
                logger.warning("Could not determine console user")
                return None

            # Check all possible locations for the notifications database
            possible_paths = [
                # Check user-specific locations
                (
                    f"/Users/{current_user}/Library/Application Support/"
                    "com.apple.notificationcenter/db2/db"
                ),
                f"/Users/{current_user}/Library/Application Support/"
                "NotificationCenter/db2/db",
                # Check Group Containers
                f"/Users/{current_user}/Library/Group Containers/"
                "group.com.apple.usernoted/db2/db",
                # Check system folders
                "/private/var/folders/*/0/com.apple.notificationcenter/db2/db"
            ]

            # For system folders, we need to expand the wildcard
            for base_path in glob.glob(
                "/private/var/folders/*/0/com.apple.notificationcenter/db2"
            ):
                if os.path.exists(base_path):
                    db_path = os.path.join(base_path, "db")
                    if os.path.exists(db_path):
                        logger.debug(
                            f"Found notifications database at: {db_path}"
                        )
                        return db_path

            # Check other specific paths
            NOTIFICATION_FOLDER_PREFIX = "/private/var/folders"
            for path in possible_paths:
                if not path.startswith(NOTIFICATION_FOLDER_PREFIX):
                    # Skip folder paths we already checked
                    if os.path.exists(path):
                        logger.debug("Found notifications DB at: %s", path)
                        return path

            logger.warning("No valid notification database found")
            return None

        except Exception as e:
            logger.error(f"Error getting notification database path: {e}")
            return None

    def _get_notification_data(self, bundle_id, db_path):
        """Get detailed notification data for an application."""
        try:
            if not db_path:
                logging.debug(f"No database path provided for {bundle_id}")
                return 0, "Never", "Inactive"

            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()

            # First get the app_id from the app table
            query = "SELECT app_id FROM app WHERE identifier = ?"
            cursor.execute(query, (bundle_id,))
            app_row = cursor.fetchone()

            if not app_row:
                logging.debug(f"No app_id found for bundle {bundle_id}")
                conn.close()
                return 0, "Never", "Inactive"

            app_id = app_row[0]

            # Query the record table with enhanced metrics
            query = """
            SELECT
                COUNT(DISTINCT rec_id) as count,
                MAX(CASE
                    WHEN delivered_date > 0 THEN delivered_date
                    WHEN request_date > 0 THEN request_date
                    ELSE NULL
                END) as last_date,
                SUM(CASE WHEN presented = 1 THEN 1 ELSE 0 END)
                    as presented_count,
                COUNT(
                    CASE WHEN delivered_date IS NOT NULL THEN 1 END
                ) as delivered_count
            FROM record
            WHERE app_id = ?
            """

            cursor.execute(query, (app_id,))
            result = cursor.fetchone()

            if result:
                count, last_date, presented_count, delivered_count = result

                # Handle null values from SQL queries
                count = count or 0
                presented_count = presented_count or 0
                delivered_count = delivered_count or 0

                # Handle timestamp conversion
                if last_date:
                    try:
                        # Convert Cocoa timestamp (seconds since 2001)
                        cocoa_timestamp = last_date + 978307200
                        dt = datetime.fromtimestamp(cocoa_timestamp)
                        last_sent = dt.strftime('%Y-%m-%d %H:%M:%S')
                    except (ValueError, OSError):
                        try:
                            # Try as Unix timestamp
                            dt = datetime.fromtimestamp(last_date)
                            last_sent = dt.strftime('%Y-%m-%d %H:%M:%S')
                        except (ValueError, OSError):
                            last_sent = "Invalid Date"
                else:
                    last_sent = "Never"

                # Check additional tables for status
                cursor.execute(
                    "SELECT list FROM delivered WHERE app_id = ?",
                    (app_id,)
                )
                has_delivered = cursor.fetchone() is not None

                cursor.execute(
                    "SELECT list FROM displayed WHERE app_id = ?",
                    (app_id,)
                )
                has_displayed = cursor.fetchone() is not None

                # Determine detailed status
                if presented_count > 0 or has_displayed:
                    status = "Active"
                elif delivered_count > 0 or has_delivered:
                    status = "Pending"
                else:
                    status = "Inactive"

            else:
                count = 0
                last_sent = "Never"
                status = "Inactive"

            conn.close()
            return count, last_sent, status

        except Exception as e:
            # Check if this is an authorization error (common in newer macOS versions)
            error_msg = str(e).lower()
            if "authorization denied" in error_msg or "permission denied" in error_msg:
                # Don't log authorization errors as they're expected in macOS 26+
                pass
            else:
                # Log other unexpected errors
                logging.error(f"Error querying notifications for {bundle_id}: {e}")

            if 'conn' in locals():
                conn.close()
            return 0, "Never", "Authorization Denied" if "authorization denied" in error_msg else "Error"

    def _check_notifications_db(self):
        """Get current notification database entries with enhanced details"""
        try:
            current_user = self._get_console_user()
            if not current_user:
                logger.warning("⚠️ Could not determine console user")
                return []

            db_path = self._get_notification_db_path()
            if not db_path:
                logger.warning("⚠️ No valid notification database found")
                return []

            print(f"Checking notifications database for user {current_user}")

            # Get list of installed applications
            apps = self._get_installed_apps()
            notifications = []

            for bundle_id, app_info in apps.items():
                count, last_sent, status = self._get_notification_data(
                    bundle_id, db_path
                )
                notifications.append({
                    'bundle_id': bundle_id,
                    'name': app_info['name'],
                    'path': app_info['path'],
                    'is_helper': app_info['is_helper'],
                    'is_system': app_info['is_system'],
                    'notification_count': count,
                    'last_notification': last_sent,
                    'status': status
                })

            # Add debug output
            print(f"\nFound {len(notifications)} notification entries")

            # Log status distribution
            status_counts = {}
            for entry in notifications:
                status = entry['status']
                status_counts[status] = status_counts.get(status, 0) + 1

            print("\nNotification permission status distribution:")
            for status, count in status_counts.items():
                print(f"Status: {status} - {count} entries")

            # Check if we have a lot of authorization denied errors (common in macOS 26+)
            auth_denied_count = status_counts.get("Authorization Denied", 0)
            if auth_denied_count > 50:  # Arbitrary threshold
                print(f"\n⚠️  Note: {auth_denied_count} authorization denied errors detected.")
                print("   This is normal behavior on macOS 26+ due to enhanced security restrictions.")
                print("   Notification database comparison may be limited but functionality will continue.")

            return notifications

        except Exception as e:
            logger.error(f"Error checking notifications database: {e}")
            print(f"Note: Error checking notifications database: {e}")
            return []

    def _get_installed_apps(self):
        """Get list of installed applications with their bundle IDs"""
        apps = {}
        app_dirs = [
            "/Applications",
            "/System/Applications",
            os.path.expanduser("~/Applications"),
            "/Library/Application Support",
            os.path.expanduser("~/Library/Application Support"),
            "/System/Library/CoreServices",
            "/System/Library/CoreServices/Applications"
        ]

        try:
            for app_dir in app_dirs:
                if not os.path.exists(app_dir):
                    continue

                for ext in [".app", ".appex"]:
                    # First check the main directories
                    cmd = [
                        "find",
                        app_dir,
                        "-name",
                        f"*{ext}",
                        "-maxdepth",
                        "5"
                    ]
                    result = subprocess.run(
                        cmd,
                        capture_output=True,
                        text=True
                    )

                    for app_path in result.stdout.splitlines():
                        if app_path:
                            # Get bundle ID for the app
                            bundle_cmd = [
                                "mdls",
                                "-name",
                                "kMDItemCFBundleIdentifier",
                                "-raw",
                                app_path
                            ]
                            bundle_result = subprocess.run(
                                bundle_cmd,
                                capture_output=True,
                                text=True
                            )
                            bundle_id = bundle_result.stdout.strip()

                            if bundle_id and bundle_id != "(null)":
                                base_name = os.path.basename(app_path)
                                app_name = base_name.replace(ext, "")
                                is_helper = any(
                                    x in app_path.lower()
                                    for x in ["helper", "agent", "daemon"]
                                )
                                is_system = app_path.startswith("/System")

                                # Only update if we don't have this bundle_id
                                # or if this is a non-helper version
                                if bundle_id not in apps or (
                                    not is_helper
                                    and apps[bundle_id].get("is_helper", False)
                                ):
                                    apps[bundle_id] = {
                                        "name": app_name,
                                        "path": app_path,
                                        "is_helper": is_helper,
                                        "is_system": is_system
                                    }

            return apps

        except Exception as e:
            logger.error(f"Error getting installed apps: {e}")
            return {}

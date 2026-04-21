# Copyright (c) 2026 Paul Cossey. All rights reserved.
# SPDX-License-Identifier: BSD-3-Clause
"""
File and path utilities for InstallAudit.
"""

import os
import logging
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


class FileHelpers:
    """Handles file and path utilities."""

    # Constants for duplicated string literals
    ICNS_EXTENSION = '.icns'

    def __init__(self):
        """Initialize FileHelpers."""
        pass

    @staticmethod
    def create_directory_with_permissions(directory_path, permissions=0o777):
        """
        Create directory with proper permissions and ensure user ownership.

        Args:
            directory_path: Path to directory to create
            permissions: Unix permissions (default: 777 - full access for all users, allows deletion without password)
        """
        try:
            # Convert to Path object
            path = Path(directory_path)

            # Create directory if it doesn't exist
            path.mkdir(parents=True, exist_ok=True)

            # Set permissions on the created directory
            os.chmod(path, permissions)

            # Get current user info for ownership
            current_uid = os.getuid()
            current_gid = os.getgid()

            # Set ownership to current user (important when running with sudo)
            os.chown(path, current_uid, current_gid)

            # Also fix permissions for parent directories that were created
            # Walk up the path and fix permissions for any newly created parents
            current = path
            while current.exists() and current != current.parent:
                try:
                    # Only modify if we have write access to the parent
                    if os.access(current.parent, os.W_OK):
                        os.chmod(current, permissions)
                        os.chown(current, current_uid, current_gid)
                except OSError as e:
                    # Don't fail if we can't modify parent directories
                    logger.debug(f"Could not set permissions on {current}: {e}")
                current = current.parent
                if current == Path('/'):  # Stop at root
                    break

            logger.debug(f"Created directory with permissions {oct(permissions)}: {path}")
            return True

        except Exception as e:
            logger.error(f"Failed to create directory {directory_path} with proper permissions: {e}")
            return False

    @staticmethod
    def set_file_permissions(file_path, permissions=0o777):
        """
        Set proper permissions on a file.

        Args:
            file_path: Path to file
            permissions: Unix permissions (default: 777 - full access for all users, allows deletion without password)
        """
        try:
            # Set file permissions
            os.chmod(file_path, permissions)

            # Set ownership to current user
            current_uid = os.getuid()
            current_gid = os.getgid()
            os.chown(file_path, current_uid, current_gid)

            logger.debug(f"Set file permissions {oct(permissions)}: {file_path}")
            return True

        except Exception as e:
            logger.error(f"Failed to set permissions on {file_path}: {e}")
            return False

    def _clean_event_data(self, event_data):
        """
        Clean up event data by removing escape characters and formatting paths.
        """
        if isinstance(event_data, str):
            # Remove escaped characters and clean up paths
            cleaned = event_data.replace('\\n', '\n')
            cleaned = cleaned.replace('\\"', '"')
            cleaned = cleaned.replace('\\/', '/')
            return cleaned.strip()
        elif isinstance(event_data, dict):
            cleaned_dict = {}
            for key, value in event_data.items():
                if isinstance(value, (str, dict, list)):
                    cleaned_dict[key] = self._clean_event_data(value)
                else:
                    cleaned_dict[key] = value
            return cleaned_dict
        elif isinstance(event_data, list):
            return [self._clean_event_data(item) for item in event_data]
        return event_data

    def _clean_path(self, path):
        """
        Clean up path strings by removing extra quotes and escape characters.
        """
        if not path:
            return ""

        # First, handle HTML entities
        cleaned = path.replace('"', '"')

        # Remove escaped quotes and slashes
        cleaned = cleaned.replace('\\"', '"').replace('\\/', '/')

        # Remove any remaining escape characters
        cleaned = cleaned.replace('\\', '')

        # Remove any duplicate quotes
        cleaned = cleaned.strip('"')

        # Add back a single set of quotes
        return f'"{cleaned}"'

    def _calculate_disk_impact(self):
        """Calculate disk space impact in bytes (free space on /)"""
        try:
            statvfs = os.statvfs('/')
            free_bytes = statvfs.f_frsize * statvfs.f_bavail
            return free_bytes
        except Exception as e:
            logger.error(f"Error calculating disk impact: {e}")
            return -1

    def get_save_location(self, default_path: str = None) -> str:
        """
        Prompt user for save location with drag-and-drop support.

        Args:
            default_path: Default path to use if user presses Enter

        Returns:
            Cleaned and validated save path
        """
        # Set default to configured save location if not provided
        if default_path is None:
            from ..core.config_manager import get_config
            config = get_config()
            default_path = os.path.expanduser(config.get_default_save_location())

        retry_message = "Please try again or press Enter for default."

        print("\nWhere would you like to save the report and configuration profiles?")
        print("You can drag and drop a folder here, or press Enter for default.")
        print(f"Default: {default_path}")

        while True:
            try:
                save_path = input("Save location: ").strip()

                # Use default if user just pressed Enter
                if not save_path:
                    save_path = default_path
                    break

                # Clean up drag-and-drop paths - remove quotes and unescape shell-escaped characters
                # macOS terminal escapes special chars like |, &, (, ), etc. with backslashes
                import re
                save_path = save_path.strip('"').strip("'")  # Remove surrounding quotes
                save_path = re.sub(r'\\(.)', r'\1', save_path)  # Remove escape backslashes

                # Validate the path exists
                if not os.path.exists(save_path):
                    print(f"❌ Error: Path does not exist: {save_path}")
                    print(retry_message)
                    continue

                # Validate it's a directory
                if not os.path.isdir(save_path):
                    print(f"❌ Error: Path is not a directory: {save_path}")
                    print(retry_message)
                    continue

                # Validate we can write to it
                if not os.access(save_path, os.W_OK):
                    print(f"❌ Error: Cannot write to directory: {save_path}")
                    print(retry_message)
                    continue

                break

            except KeyboardInterrupt:
                print("\nUsing default save location.")
                save_path = default_path
                break
            except Exception as e:
                print(f"❌ Error: {e}")
                print(retry_message)
                continue

        # Ensure the path exists and is absolute
        save_path = os.path.abspath(os.path.expanduser(save_path))
        print(f"✅ Save location: {save_path}")
        return save_path

    def extract_app_icon(self, app_path: str, save_location: str, munki_item_name: str) -> Optional[str]:
        """
        Extract the application's icon file and save it to the specified location.

        Args:
            app_path: Path to the .app bundle
            save_location: Base directory where to create the munki item folder
            munki_item_name: Name of the Munki item (used for folder and file naming)

        Returns:
            Path to the extracted icon file, or None if extraction failed
        """
        try:
            import plistlib
            import shutil

            # Create munki item folder in the save location
            clean_munki_name = munki_item_name.replace(' ', '_').replace('.app', '').replace('/', '_').replace('\\', '_')
            munki_folder = os.path.join(save_location, clean_munki_name)

            # Create the munki folder if it doesn't exist
            os.makedirs(munki_folder, exist_ok=True)

            # Read the Info.plist to find the icon file name
            info_plist_path = os.path.join(app_path, 'Contents', 'Info.plist')

            if not os.path.exists(info_plist_path):
                logger.warning(f"Info.plist not found at {info_plist_path}")
                return None

            with open(info_plist_path, 'rb') as f:
                info_plist = plistlib.load(f)

            # Look for icon file name in Info.plist
            icon_file = None
            for key in ['CFBundleIconFile', 'CFBundleIcons', 'CFBundleIconFiles']:
                if key in info_plist:
                    if key == 'CFBundleIconFile':
                        icon_file = info_plist[key]
                        break
                    elif key == 'CFBundleIcons':
                        # Modern icon format - try to get primary icon
                        icons_dict = info_plist[key]
                        if 'CFBundlePrimaryIcon' in icons_dict:
                            primary_icon = icons_dict['CFBundlePrimaryIcon']
                            if 'CFBundleIconFiles' in primary_icon:
                                icon_files = primary_icon['CFBundleIconFiles']
                                if icon_files:
                                    icon_file = icon_files[0]  # Use first icon file
                                    break
                    elif key == 'CFBundleIconFiles':
                        icon_files = info_plist[key]
                        if icon_files:
                            icon_file = icon_files[0]  # Use first icon file
                            break

            if not icon_file:
                logger.warning(f"No icon file specified in Info.plist for {app_path}")
                return None

            # Ensure the icon file has .icns extension
            if not icon_file.endswith(self.ICNS_EXTENSION):
                icon_file += self.ICNS_EXTENSION

            # Look for the icon file in the Resources directory
            resources_path = os.path.join(app_path, 'Contents', 'Resources')
            icon_source_path = os.path.join(resources_path, icon_file)

            if not os.path.exists(icon_source_path):
                # Try without .icns extension in case it was double-added
                alt_icon_file = icon_file.replace(self.ICNS_EXTENSION, '')
                alt_icon_source_path = os.path.join(resources_path, alt_icon_file + self.ICNS_EXTENSION)
                if os.path.exists(alt_icon_source_path):
                    icon_source_path = alt_icon_source_path
                else:
                    logger.warning(f"Icon file not found at {icon_source_path}")
                    return None

            # Create destination filename using munki item name
            dest_filename = f"{clean_munki_name}{self.ICNS_EXTENSION}"
            dest_path = os.path.join(munki_folder, dest_filename)

            # Copy the icon file
            shutil.copy2(icon_source_path, dest_path)

            logger.info(f"✅ Extracted icon: {icon_source_path} -> {dest_path}")
            print(f"   📁 Icon extracted: {dest_filename}")

            return dest_path

        except Exception as e:
            logger.error(f"Error extracting icon from {app_path}: {e}")
            print(f"   ⚠️  Could not extract icon: {e}")
            return None

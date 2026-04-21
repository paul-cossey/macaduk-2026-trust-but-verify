# Copyright (c) 2026 Paul Cossey. All rights reserved.
# SPDX-License-Identifier: BSD-3-Clause
"""
Manifest management methods for InstallAudit.

Supports both local-only and standard Munki manifest layouts:

- **Local-only** manifests typically contain ``managed_installs`` and
  ``managed_uninstalls`` arrays directly.
- **Standard Munki** manifests may initially contain only a ``catalogs``
  array (the server-side default).  This module will add the
  ``managed_installs`` / ``managed_uninstalls`` keys as needed.

Manifest filenames on disk may or may not include a ``.plist`` extension and
may contain special characters (spaces, serial-number formats, etc.).
"""

import os
import plistlib
import logging

logger = logging.getLogger(__name__)

# Standard location where Munki stores manifests
MANIFESTS_DIR = "/Library/Managed Installs/manifests"
PLIST_EXT = ".plist"


class ManifestManager:
    """Handles Munki manifest file operations."""

    # ------------------------------------------------------------------
    # Manifest discovery helpers
    # ------------------------------------------------------------------

    @staticmethod
    def get_available_manifests():
        """Return a sorted list of valid manifest filenames found on disk.

        Scans ``/Library/Managed Installs/manifests/`` for files that can be
        parsed as Apple property-list files.  Directories are skipped.

        Returns:
            list[str]: Sorted manifest filenames (as they appear on disk).
        """
        if not os.path.isdir(MANIFESTS_DIR):
            logger.warning(f"Manifests directory not found: {MANIFESTS_DIR}")
            return []

        manifests = []
        for entry in os.listdir(MANIFESTS_DIR):
            full_path = os.path.join(MANIFESTS_DIR, entry)
            if not os.path.isfile(full_path):
                continue
            try:
                with open(full_path, 'rb') as fh:
                    plistlib.load(fh)
                manifests.append(entry)
            except Exception:
                # Not a valid plist — skip silently
                continue

        return sorted(manifests)

    @staticmethod
    def resolve_manifest_path(manifest_name):
        """Resolve a manifest name to its actual path on disk.

        Handles the common case where the manifest file may or may not
        have a ``.plist`` extension and may contain special characters.

        Resolution order:
            1. ``<dir>/<name>.plist``  (name with extension appended)
            2. ``<dir>/<name>``        (name used verbatim)

        Args:
            manifest_name: The manifest name (from config or user input).
                           May or may not include ``.plist``.

        Returns:
            str: Absolute path to the manifest file.  If neither candidate
                 exists on disk the ``.plist`` variant is returned as a
                 sensible default (it will be created on first write).

        Raises:
            ValueError: If *manifest_name* would resolve outside
                        ``MANIFESTS_DIR`` (e.g. absolute path or ``../``).
        """
        # Sanitize: strip to basename to prevent path traversal
        safe_name = os.path.basename(manifest_name)
        if not safe_name:
            raise ValueError(f"Invalid manifest name: {manifest_name!r}")

        # If the caller already provided the .plist extension, try that
        # first, then fall back to exactly what was given.
        if safe_name.endswith(PLIST_EXT):
            with_ext = os.path.join(MANIFESTS_DIR, safe_name)
            without_ext = os.path.join(MANIFESTS_DIR, safe_name[:-len(PLIST_EXT)])
            if os.path.exists(with_ext):
                return with_ext
            if os.path.exists(without_ext):
                return without_ext
            return with_ext  # default to the explicit name

        # Name does NOT end with .plist — try both variants
        with_ext = os.path.join(MANIFESTS_DIR, f"{safe_name}{PLIST_EXT}")
        without_ext = os.path.join(MANIFESTS_DIR, safe_name)

        if os.path.exists(with_ext):
            return with_ext
        if os.path.exists(without_ext):
            return without_ext

        # Neither exists yet — default to the .plist variant
        return with_ext

    # ------------------------------------------------------------------
    # Interactive manifest selection
    # ------------------------------------------------------------------

    def select_manifest_interactive(self):
        """Prompt the user to choose a manifest from those on disk.

        Displays a numbered menu of available manifests and allows the
        user to select one by number.  If the configured default manifest
        is found in the list it is pre-selected (shown with a ``*``).

        Returns:
            str | None: Absolute path to the chosen manifest, or ``None``
                        if the user cancels or no manifests are available.
        """
        manifests = self.get_available_manifests()
        if not manifests:
            print("No manifests found in " + MANIFESTS_DIR)
            return None

        # Determine the configured default so we can highlight it
        default_idx = self._find_default_manifest_index(manifests)

        self._print_manifest_menu(manifests, default_idx)
        return self._prompt_manifest_selection(manifests, default_idx)

    def _find_default_manifest_index(self, manifests):
        """Return the index of the configured default manifest, or ``None``."""
        try:
            from ..core.config_manager import get_config
            config = get_config()
            default_name = config.get_munki_manifest_name()
        except (ImportError, AttributeError):
            return None

        for idx, name in enumerate(manifests):
            bare = name[:-len(PLIST_EXT)] if name.endswith(PLIST_EXT) else name
            if name == default_name or bare == default_name:
                return idx
        return None

    @staticmethod
    def _print_manifest_menu(manifests, default_idx):
        """Print the numbered manifest menu."""
        print("Available manifests:\n")
        for idx, name in enumerate(manifests):
            marker = " *" if idx == default_idx else ""
            print(f"  {idx + 1}. {name}{marker}")
        if default_idx is not None:
            print("\n  (* = configured default)")
        print()

    def _prompt_manifest_selection(self, manifests, default_idx):
        """Read user input and return the selected manifest path."""
        prompt = "Select manifest"
        if default_idx is not None:
            prompt += f" [{default_idx + 1}]"
        prompt += ": "

        try:
            choice = input(prompt).strip()
        except (KeyboardInterrupt, EOFError):
            return None

        if not choice:
            return self._select_default_manifest(manifests, default_idx)

        try:
            idx = int(choice) - 1
            if 0 <= idx < len(manifests):
                selected = manifests[idx]
                path = os.path.join(MANIFESTS_DIR, selected)
                print(f"Selected manifest: {selected}")
                return path
        except ValueError:
            pass

        print("Invalid selection")
        return None

    @staticmethod
    def _select_default_manifest(manifests, default_idx):
        """Return the default manifest path when the user presses Enter."""
        if default_idx is not None:
            selected = manifests[default_idx]
            path = os.path.join(MANIFESTS_DIR, selected)
            print(f"Using default manifest: {selected}")
            return path
        if len(manifests) == 1:
            selected = manifests[0]
            path = os.path.join(MANIFESTS_DIR, selected)
            print(f"Using only available manifest: {selected}")
            return path
        print("No default manifest configured — please enter a number")
        return None

    # ------------------------------------------------------------------
    # Manifest update / cleanup
    # ------------------------------------------------------------------

    def _update_manifest(self, item_name, action="install"):
        """Update the manifest to add *item_name* for install or uninstall.

        Works with both local-only manifests (which already have
        ``managed_installs``/``managed_uninstalls``) and standard Munki
        manifests (which may only have a ``catalogs`` key initially).
        Missing keys are created automatically.
        """
        try:
            print(f"\nUpdating manifest at: {self.manifest_path}")
            manifest_data = self._read_or_create_manifest()
            self._ensure_manifest_keys(manifest_data)
            self._apply_manifest_action(manifest_data, item_name, action)

            with open(self.manifest_path, 'wb') as f:
                plistlib.dump(manifest_data, f)
            print("✅ Successfully updated manifest")

            return True
        except Exception as e:
            logger.error(f"Error updating manifest: {e}")
            print(f"❌ Error updating manifest: {e}")
            return False

    def _read_or_create_manifest(self):
        """Read existing manifest from disk or return empty dict."""
        if os.path.exists(self.manifest_path):
            with open(self.manifest_path, 'rb') as f:
                data = plistlib.load(f)
            print("- Successfully read existing manifest")
            return data
        print("- Creating new manifest")
        return {}

    @staticmethod
    def _ensure_manifest_keys(manifest_data):
        """Ensure managed_installs and managed_uninstalls keys exist."""
        if 'managed_installs' not in manifest_data:
            manifest_data['managed_installs'] = []
        if 'managed_uninstalls' not in manifest_data:
            manifest_data['managed_uninstalls'] = []

    @staticmethod
    def _apply_manifest_action(manifest_data, item_name, action):
        """Add *item_name* to the appropriate manifest list."""
        if action == "install":
            print(f"- Adding {item_name} to managed_installs")
            if item_name not in manifest_data['managed_installs']:
                manifest_data['managed_installs'].append(item_name)
                if item_name in manifest_data['managed_uninstalls']:
                    manifest_data['managed_uninstalls'].remove(item_name)
        else:  # uninstall
            print(f"- Adding {item_name} to managed_uninstalls")
            if item_name not in manifest_data['managed_uninstalls']:
                manifest_data['managed_uninstalls'].append(item_name)
                if item_name in manifest_data['managed_installs']:
                    manifest_data['managed_installs'].remove(item_name)

    def _cleanup_manifest_item(self, item_name):
        """Remove *item_name* from both managed arrays.

        Called after loop checks pass so the manifest is left in a clean
        default state (empty ``managed_installs`` / ``managed_uninstalls``).
        """
        try:
            print(f"\nCleaning up manifest: removing {item_name}")
            manifest_data = self._read_or_create_manifest()
            self._ensure_manifest_keys(manifest_data)

            changed = False
            if item_name in manifest_data['managed_installs']:
                manifest_data['managed_installs'].remove(item_name)
                print(f"- Removed {item_name} from managed_installs")
                changed = True
            if item_name in manifest_data['managed_uninstalls']:
                manifest_data['managed_uninstalls'].remove(item_name)
                print(f"- Removed {item_name} from managed_uninstalls")
                changed = True

            if changed:
                with open(self.manifest_path, 'wb') as f:
                    plistlib.dump(manifest_data, f)
                print("✅ Manifest restored to default state")
            else:
                print("ℹ️  Item not found in manifest — already clean")

            return True
        except Exception as e:
            logger.error(f"Error cleaning up manifest: {e}")
            print(f"❌ Error cleaning up manifest: {e}")
            return False

    def _restore_manifest(self):
        """Restore original manifest"""
        try:
            if hasattr(self, 'original_manifest'):
                with open(self.manifest_path, 'wb') as f:
                    plistlib.dump(self.original_manifest, f)
                logger.info("Original manifest restored")
                return True
            return False
        except Exception as e:
            logger.error(f"Error restoring manifest: {e}")
            return False

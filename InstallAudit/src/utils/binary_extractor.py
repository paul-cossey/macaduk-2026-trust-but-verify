#!/usr/bin/env python3
"""
Binary Extractor Utility

Extracts and identifies Mach-O binaries from DMG and PKG files for security analysis.
Copyright (c) 2026 Paul Cossey. All rights reserved.
SPDX-License-Identifier: BSD-3-Clause
"""

import logging
import os
import shutil
import subprocess
import tempfile
from typing import List, Dict, Any, Optional

from .dmg_mounter import mount_dmg, unmount_dmg

logger = logging.getLogger(__name__)


class BinaryExtractor:
    """
    Extract Mach-O binaries from packages and disk images.

    Features:
    - Mount and scan DMG files
    - Extract and scan PKG files
    - Identify Mach-O binaries using `file` command
    - Handle nested packages and applications
    - Clean up temporary files
    """

    def __init__(self):
        """Initialize binary extractor."""
        self.temp_dirs = []

    def __del__(self):
        """Clean up temporary directories on deletion."""
        self.cleanup()

    def cleanup(self):
        """Remove all temporary directories created during extraction."""
        for temp_dir in self.temp_dirs:
            if os.path.exists(temp_dir):
                try:
                    shutil.rmtree(temp_dir)
                    logger.debug(f"Cleaned up temporary directory: {temp_dir}")
                except Exception as e:
                    logger.warning(f"Failed to clean up {temp_dir}: {e}")
        self.temp_dirs.clear()

    def extract_binaries(self, file_path: str) -> List[Dict[str, Any]]:
        """
        Extract all Mach-O binaries from a DMG, PKG, or archive file.

        Args:
            file_path: Path to DMG, PKG, ZIP, TAR, or other archive file

        Returns:
            List of dicts containing binary information:
            {
                'path': str,           # Absolute path to binary
                'name': str,           # Binary filename
                'size': int,           # File size in bytes
                'type': str,           # Binary type (Mach-O 64-bit executable, etc.)
                'source_app': str,     # Application bundle it came from (if applicable)
                'relative_path': str   # Path relative to app bundle or package root
            }
        """
        if not os.path.exists(file_path):
            logger.error(f"File not found: {file_path}")
            return []

        file_ext = os.path.splitext(file_path)[1].lower()
        file_name = os.path.basename(file_path).lower()

        # Check for compound extensions like .tar.gz
        if file_name.endswith('.tar.gz') or file_name.endswith('.tar.bz2') or file_name.endswith('.tar.xz'):
            return self._extract_from_archive(file_path)
        elif file_ext == '.dmg':
            return self._extract_from_dmg(file_path)
        elif file_ext == '.pkg':
            return self._extract_from_pkg(file_path)
        elif file_ext in ['.zip', '.tar', '.bz2', '.xz', '.gz']:
            return self._extract_from_archive(file_path)
        elif file_ext == '.app':
            # Direct app bundle
            return self._scan_app_bundle(file_path)
        else:
            logger.warning(f"Unsupported file type: {file_ext}")
            return []

    def _extract_from_dmg(self, dmg_path: str) -> List[Dict[str, Any]]:
        """
        Extract binaries from a DMG file.

        Args:
            dmg_path: Path to DMG file

        Returns:
            List of binary information dicts
        """
        binaries = []
        mount_point = None

        try:
            dmg_name = os.path.basename(dmg_path)
            logger.info(f"Mounting DMG: {dmg_name}")
            mount_point = mount_dmg(dmg_path)

            if not mount_point:
                logger.error(f"Failed to mount DMG: {dmg_name}")
                return []

            logger.info(f"DMG mounted at: {mount_point}")

            # Create temporary directory to copy binaries before unmounting
            temp_dir = tempfile.mkdtemp(prefix='dmg_binaries_')
            self.temp_dirs.append(temp_dir)

            # Scan for applications
            for item in os.listdir(mount_point):
                item_path = os.path.join(mount_point, item)

                # Check for .app bundles
                if item.endswith('.app') and os.path.isdir(item_path):
                    binaries.extend(self._scan_app_bundle(item_path, copy_to_temp=temp_dir, source_package=dmg_name))

                # Check for nested PKG files
                elif item.endswith('.pkg') and os.path.isfile(item_path):
                    binaries.extend(self._extract_from_pkg(item_path))

                # Check for direct binaries (less common)
                elif os.path.isfile(item_path):
                    if self._is_macho_binary(item_path):
                        binaries.append(self._get_binary_info(item_path, item_path, source_app=dmg_name, copy_to_temp=temp_dir))

        except subprocess.TimeoutExpired:
            logger.error("DMG mount operation timed out")
        except Exception as e:
            logger.error(f"Error extracting from DMG: {e}")
        finally:
            # Unmount DMG
            if mount_point:
                unmount_dmg(mount_point)

        return binaries

    def _extract_from_pkg(self, pkg_path: str) -> List[Dict[str, Any]]:
        """
        Extract binaries from a PKG file.

        Args:
            pkg_path: Path to PKG file

        Returns:
            List of binary information dicts
        """
        binaries = []

        try:
            # Create temporary directory path (but don't create the directory yet - pkgutil will do that)
            temp_base = tempfile.mkdtemp(prefix='pkg_base_')
            self.temp_dirs.append(temp_base)
            temp_dir = os.path.join(temp_base, 'expanded')

            pkg_name = os.path.basename(pkg_path)
            logger.info(f"Extracting PKG: {pkg_name}")

            # Expand the package fully (including decompressing pbzx-format Payloads)
            # --expand-full automatically handles pbzx, gzip, xz, and other formats
            result = subprocess.run(
                ['pkgutil', '--expand-full', pkg_path, temp_dir],
                capture_output=True,
                text=True,
                timeout=120
            )

            if result.returncode != 0:
                logger.error(f"Failed to expand PKG: {result.stderr}")
                return []

            # Log the structure of the expanded package for debugging
            logger.debug("Expanded package structure:")
            for root, _dirs, files in os.walk(temp_dir):
                rel_root = os.path.relpath(root, temp_dir)
                logger.debug(f"  {rel_root}/")
                for f in files[:10]:  # Limit to first 10 files per directory
                    file_path = os.path.join(root, f)
                    size = os.path.getsize(file_path) if os.path.exists(file_path) else 0
                    logger.debug(f"    {f} ({size} bytes)")
                if len(files) > 10:
                    logger.debug(f"    ... and {len(files) - 10} more files")

            # First, scan the expanded package directory for app bundles
            # With --expand-full, the Payload is already decompressed into a Payload/ directory
            # containing the actual application files, so we just need to scan for .app bundles
            for root, dirs, _files in os.walk(temp_dir):
                for dir_name in dirs:
                    if dir_name.endswith('.app'):
                        app_path = os.path.join(root, dir_name)
                        logger.debug(f"Found .app bundle in expanded package: {dir_name}")
                        binaries.extend(self._scan_app_bundle(app_path, source_package=pkg_name))

            # Also scan for any loose binaries in non-.app directories
            for root, _dirs, files in os.walk(temp_dir):
                # Skip .app bundle contents (already scanned above)
                if '.app/' in root or root.endswith('.app'):
                    continue

                for file in files:
                    file_path = os.path.join(root, file)
                    if os.path.isfile(file_path) and not os.path.islink(file_path):
                        if self._is_macho_binary(file_path):
                            binary_info = self._get_binary_info(file_path, temp_dir, source_app=pkg_name)
                            binaries.append(binary_info)

        except subprocess.TimeoutExpired:
            logger.error("PKG extraction timed out")
        except Exception as e:
            logger.error(f"Error extracting from PKG: {e}")

        return binaries

    def _extract_from_archive(self, archive_path: str) -> List[Dict[str, Any]]:
        """
        Extract binaries from various archive formats (ZIP, TAR, etc.).

        Args:
            archive_path: Path to archive file

        Returns:
            List of binary information dicts
        """
        binaries = []

        try:
            # Create temporary directory for extraction
            temp_dir = tempfile.mkdtemp(prefix='archive_extract_')
            self.temp_dirs.append(temp_dir)

            archive_name = os.path.basename(archive_path)
            file_ext = os.path.splitext(archive_path)[1].lower()
            file_name = archive_name.lower()

            logger.info(f"Extracting archive: {archive_name}")

            # Determine extraction method based on file type
            if file_ext == '.zip':
                # Use unzip command
                result = subprocess.run(
                    ['unzip', '-q', archive_path, '-d', temp_dir],
                    capture_output=True,
                    text=True,
                    timeout=120
                )
            elif file_name.endswith('.tar.gz') or file_name.endswith('.tgz'):
                # Tar gzip
                result = subprocess.run(
                    ['tar', '-xzf', archive_path, '-C', temp_dir],
                    capture_output=True,
                    text=True,
                    timeout=120
                )
            elif file_name.endswith('.tar.bz2') or file_ext == '.tbz':
                # Tar bzip2
                result = subprocess.run(
                    ['tar', '-xjf', archive_path, '-C', temp_dir],
                    capture_output=True,
                    text=True,
                    timeout=120
                )
            elif file_name.endswith('.tar.xz'):
                # Tar xz
                result = subprocess.run(
                    ['tar', '-xJf', archive_path, '-C', temp_dir],
                    capture_output=True,
                    text=True,
                    timeout=120
                )
            elif file_ext == '.tar':
                # Plain tar
                result = subprocess.run(
                    ['tar', '-xf', archive_path, '-C', temp_dir],
                    capture_output=True,
                    text=True,
                    timeout=120
                )
            else:
                logger.warning(f"Unsupported archive format: {file_ext}")
                return []

            if result.returncode != 0:
                logger.error(f"Failed to extract archive: {result.stderr}")
                return []

            # Scan extracted contents for app bundles and binaries
            binaries.extend(self._scan_directory(temp_dir, source_app=archive_name))

        except subprocess.TimeoutExpired:
            logger.error("Archive extraction timed out")
        except Exception as e:
            logger.error(f"Error extracting from archive: {e}")

        return binaries

    def _scan_app_bundle(self, app_path: str, copy_to_temp: Optional[str] = None, source_package: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Scan an application bundle for Mach-O binaries.

        Args:
            app_path: Path to .app bundle
            copy_to_temp: Optional temp directory to copy binaries to
            source_package: Optional package name (DMG/PKG) to use as source

        Returns:
            List of binary information dicts
        """
        binaries = []
        # Use source_package if provided, otherwise use app name
        source_name = source_package if source_package else os.path.basename(app_path)
        app_bundle_name = os.path.basename(app_path)

        # Dynamically discover all folders within Contents directory
        # This ensures we don't miss binaries in unexpected locations
        contents_path = os.path.join(app_path, 'Contents')

        if not os.path.exists(contents_path):
            logger.warning(f"App bundle {app_bundle_name} has no Contents directory")
            # Still scan the app bundle root in case it's an unusual structure
            binaries.extend(self._scan_directory(app_path, source_app=source_name, app_bundle=app_bundle_name, copy_to_temp=copy_to_temp))
            return binaries

        # Get all subdirectories within Contents
        search_paths = []
        try:
            for item in os.listdir(contents_path):
                item_path = os.path.join(contents_path, item)
                if os.path.isdir(item_path) and not os.path.islink(item_path):
                    search_paths.append(item_path)

            if search_paths:
                dir_names = [os.path.basename(p) for p in search_paths]
                logger.info(f"Scanning {len(search_paths)} directories in {app_bundle_name}/Contents: {', '.join(dir_names)}")
            else:
                logger.debug(f"No subdirectories found in {app_bundle_name}/Contents, scanning entire Contents")
                # If no subdirectories, scan Contents itself
                search_paths = [contents_path]
        except Exception as e:
            logger.warning(f"Error listing Contents directory for {app_bundle_name}: {e}")
            # Fallback to scanning entire Contents directory
            search_paths = [contents_path]

        # Scan each discovered directory for binaries
        for search_path in search_paths:
            logger.debug(f"Scanning directory: {os.path.relpath(search_path, app_path)}")
            binaries.extend(self._scan_directory(search_path, source_app=source_name, app_bundle=app_bundle_name, copy_to_temp=copy_to_temp))

        return binaries

    def _scan_directory(self, directory: str, source_app: Optional[str] = None, app_bundle: Optional[str] = None, copy_to_temp: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Recursively scan a directory for Mach-O binaries.

        .framework bundles are treated as directories (like .app bundles) and are walked into
        automatically to find the actual binaries within. This extracts real executables from
        framework bundle structures like QtMultimedia.framework/Versions/A/QtMultimedia.

        Args:
            directory: Directory to scan
            source_app: Name of the source application (if applicable)
            app_bundle: Name of the app bundle (if applicable)
            copy_to_temp: Optional temp directory to copy binaries to

        Returns:
            List of binary information dicts
        """
        binaries = []
        files_checked = 0
        files_skipped_symlink = 0

        try:
            for root, _dirs, files in os.walk(directory):
                for file in files:
                    file_path = os.path.join(root, file)
                    files_checked += 1

                    # Skip symbolic links
                    if os.path.islink(file_path):
                        files_skipped_symlink += 1
                        logger.debug(f"Skipping symlink: {file}")
                        continue

                    # Check if it's a Mach-O binary
                    if self._is_macho_binary(file_path):
                        logger.debug(f"Found Mach-O binary: {file} in {os.path.basename(root)}")
                        binary_info = self._get_binary_info(file_path, directory, source_app, app_bundle, copy_to_temp)
                        binaries.append(binary_info)

            if files_checked > 0:
                logger.debug(f"Scanned {files_checked} files in {os.path.basename(directory)}, found {len(binaries)} Mach-O binaries (skipped {files_skipped_symlink} symlinks)")

        except Exception as e:
            logger.error(f"Error scanning directory {directory}: {e}")

        return binaries

    def _is_macho_binary(self, file_path: str) -> bool:
        """
        Check if a file is a Mach-O binary.

        Args:
            file_path: Path to file

        Returns:
            True if file is a Mach-O binary
        """
        try:
            # Skip files that are clearly not binaries based on extension
            # But be cautious - some binaries have no extension
            basename = os.path.basename(file_path)
            skip_extensions = ['.txt', '.plist', '.strings', '.nib', '.xib', '.png', '.jpg', '.jpeg',
                               '.gif', '.icns', '.pdf', '.rtf', '.html', '.css', '.js', '.json',
                               '.xml', '.md', '.log', '.h', '.m', '.swift', '.c', '.cpp']
            if any(basename.lower().endswith(ext) for ext in skip_extensions):
                return False

            result = subprocess.run(
                ['file', '-b', file_path],
                capture_output=True,
                text=True,
                timeout=5
            )

            output = result.stdout.lower()
            is_macho = 'mach-o' in output

            # Log when we find a potential binary that's not being detected
            if not is_macho and os.access(file_path, os.X_OK) and os.path.getsize(file_path) > 1024:
                # File is executable, larger than 1KB, but not detected as Mach-O
                logger.debug(f"Executable file not detected as Mach-O: {basename} (type: {result.stdout.strip()})")

            return is_macho

        except Exception as e:
            logger.debug(f"Error checking file type for {file_path}: {e}")
            return False

    def _get_binary_filetype(self, file_path: str) -> Optional[str]:
        """
        Get the Mach-O filetype using otool.

        Args:
            file_path: Path to binary file

        Returns:
            Filetype string (e.g., 'EXECUTE', 'DYLIB', 'BUNDLE') or None if unable to determine
        """
        try:
            # Skip if path is a directory
            if not os.path.isfile(file_path):
                logger.debug(f"Skipping otool for non-file: {file_path}")
                return None

            result = subprocess.run(
                ['otool', '-hv', file_path],
                capture_output=True,
                text=True,
                timeout=5
            )

            # Parse output for filetype
            # Example line: "MH_MAGIC_64   X86_64        ALL  0x00     EXECUTE    57       7344   NOUNDEFS..."
            for line in result.stdout.splitlines():
                if 'filetype' in line.lower():
                    # Skip header line
                    continue
                # Look for lines with architecture info
                parts = line.split()
                if len(parts) >= 5 and parts[0].startswith('MH_MAGIC'):
                    # Filetype is typically the 5th column after magic, cputype, cpusubtype, caps
                    filetype = parts[4]
                    logger.debug(f"Detected filetype for {os.path.basename(file_path)}: {filetype}")
                    return filetype

            # If we didn't find filetype in expected format, log it
            logger.debug(f"Could not parse filetype from otool output for {os.path.basename(file_path)}")
            return None

        except subprocess.TimeoutExpired:
            logger.debug(f"otool timeout for {file_path}")
            return None
        except Exception as e:
            # otool might fail on non-Mach-O files or if file is corrupted
            logger.debug(f"Error getting filetype with otool for {file_path}: {e}")
            return None

    def _get_binary_info(self, binary_path: str, base_path: str, source_app: Optional[str] = None, app_bundle: Optional[str] = None, copy_to_temp: Optional[str] = None) -> Dict[str, Any]:
        """
        Get detailed information about a binary.

        Args:
            binary_path: Path to binary
            base_path: Base path for calculating relative path
            source_app: Name of source application
            app_bundle: Name of app bundle (if different from source)
            copy_to_temp: Optional temp directory to copy binary to (for mounted volumes)

        Returns:
            Dict with binary information
        """
        try:
            # Calculate relative path before any copying
            try:
                relative_path = os.path.relpath(binary_path, base_path)
            except ValueError:
                relative_path = os.path.basename(binary_path)

            # If copy_to_temp specified, copy binary to temp location
            actual_path = binary_path
            if copy_to_temp:
                # Create subdirectory structure in temp
                rel_dir = os.path.dirname(relative_path)
                temp_subdir = os.path.join(copy_to_temp, rel_dir)
                os.makedirs(temp_subdir, exist_ok=True)

                # Copy binary
                temp_binary_path = os.path.join(copy_to_temp, relative_path)
                shutil.copy2(binary_path, temp_binary_path)
                actual_path = temp_binary_path
                logger.debug(f"Copied {os.path.basename(binary_path)} to temp")

            # Get file type details
            result = subprocess.run(
                ['file', '-b', actual_path],
                capture_output=True,
                text=True,
                timeout=5
            )
            file_type = result.stdout.strip()

            # Get file size
            file_size = os.path.getsize(actual_path)

            # Get Mach-O filetype (EXECUTE, DYLIB, BUNDLE, etc.) using otool
            filetype = self._get_binary_filetype(actual_path)

            logger.debug(f"Binary info for {os.path.basename(binary_path)}: source_app={source_app}, app_bundle={app_bundle}, filetype={filetype}")

            return {
                'path': actual_path,
                'name': os.path.basename(binary_path),
                'size': file_size,
                'type': file_type,
                'filetype': filetype,
                'source_app': source_app or 'Unknown',
                'app_bundle': app_bundle,
                'relative_path': relative_path
            }

        except Exception as e:
            logger.warning(f"Error getting binary info for {binary_path}: {e}")
            return {
                'path': binary_path,
                'name': os.path.basename(binary_path),
                'size': 0,
                'type': 'Unknown',
                'filetype': None,
                'source_app': source_app or 'Unknown',
                'app_bundle': app_bundle,
                'relative_path': os.path.basename(binary_path)
            }

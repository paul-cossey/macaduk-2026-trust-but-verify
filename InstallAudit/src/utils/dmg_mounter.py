"""
DMG Mounter Utility

Mounts and unmounts disk images using the same approach as AutoPkg's DmgMounter.
Handles DMGs with Software License Agreements (SLAs/EULAs) and mixed plist output.

Based on: https://github.com/autopkg/autopkg/blob/master/Code/autopkglib/DmgMounter.py
Copyright 2010 Per Olofsson (original AutoPkg DmgMounter, Apache-2.0)
Copyright (c) 2026 Paul Cossey. All rights reserved.
SPDX-License-Identifier: Apache-2.0
"""

import logging
import os
import plistlib
import subprocess

logger = logging.getLogger(__name__)

HDIUTIL = "/usr/bin/hdiutil"


def _get_first_plist(text_string):
    """Extract the first plist from a string that may contain non-plist text.

    hdiutil output can include SLA/EULA text before the actual plist data,
    which causes plistlib.loads() to fail on the raw output.

    Args:
        text_string: Raw text output from hdiutil

    Returns:
        Tuple of (plist_string, remaining_string)
    """
    plist_header = "<?xml version"
    plist_footer = "</plist>"
    plist_start_index = text_string.find(plist_header)
    if plist_start_index == -1:
        return ("", text_string)
    plist_end_index = text_string.find(
        plist_footer, plist_start_index + len(plist_header)
    )
    if plist_end_index == -1:
        return ("", text_string)
    plist_end_index = plist_end_index + len(plist_footer)
    return (
        text_string[plist_start_index:plist_end_index],
        text_string[plist_end_index:],
    )


def _dmg_has_sla(dmg_path):
    """Check if a DMG has a Software License Agreement.

    DMGs with SLAs require 'Y' on stdin to accept before mounting.

    Args:
        dmg_path: Path to the DMG file

    Returns:
        True if DMG has an SLA, False otherwise
    """
    try:
        proc = subprocess.Popen(
            [HDIUTIL, "imageinfo", dmg_path, "-plist"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        stdout, stderr = proc.communicate(timeout=30)
        if stderr:
            # APFS disk images can generate extraneous output to stderr
            logger.debug(f"hdiutil imageinfo stderr for {dmg_path}: {stderr}")

        pliststr, _ = _get_first_plist(stdout)
        if pliststr:
            plist = plistlib.loads(pliststr.encode())
            properties = plist.get("Properties")
            if properties:
                return properties.get("Software License Agreement", False)
    except subprocess.TimeoutExpired:
        logger.warning(f"hdiutil imageinfo timed out for {dmg_path}")
    except Exception as e:
        logger.warning(f"Error checking DMG SLA for {dmg_path}: {e}")

    return False


def mount_dmg(dmg_path, timeout=120):
    """Mount a DMG file using the AutoPkg approach.

    Handles DMGs with SLAs by checking first and only sending 'Y' if needed.
    Uses -mountrandom to avoid mount point conflicts.
    Extracts plist from potentially mixed output.

    Args:
        dmg_path: Path to the DMG file
        timeout: Timeout in seconds for the mount operation

    Returns:
        Mount point path string on success, None on failure
    """
    # Only send Y on stdin if DMG has a Software License Agreement
    stdin = ""
    if _dmg_has_sla(dmg_path):
        stdin = "Y\n"

    try:
        proc = subprocess.Popen(
            (
                HDIUTIL,
                "attach",
                "-plist",
                "-mountrandom", "/private/tmp",
                "-nobrowse",
                "-readonly",
                dmg_path,
            ),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.PIPE,
            text=True,
        )
        stdout, stderr = proc.communicate(input=stdin, timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
        logger.error(f"DMG mount timed out for {dmg_path}")
        return None
    except OSError as err:
        logger.error(f"hdiutil execution failed: {err}")
        return None

    if proc.returncode != 0:
        logger.error(f"Mounting {dmg_path} failed: {stderr}")
        return None

    # Extract plist from output (may contain SLA text before plist)
    pliststr, _ = _get_first_plist(stdout)
    if not pliststr:
        logger.error(f"Mounting {dmg_path} failed: no plist in hdiutil output")
        return None

    try:
        output = plistlib.loads(pliststr.encode())
    except Exception:
        logger.error(f"Mounting {dmg_path} failed: unexpected output from hdiutil")
        return None

    # Find mount point
    for part in output.get("system-entities", []):
        if "mount-point" in part:
            mount_point = part["mount-point"]
            logger.info(f"Mounted {dmg_path} at {mount_point}")
            return mount_point

    logger.error(f"Mounting {dmg_path} failed: no mount point in hdiutil output")
    return None


def unmount_dmg(mount_point, timeout=30):
    """Unmount a previously mounted DMG.

    Args:
        mount_point: The mount point path to detach
        timeout: Timeout in seconds for the detach operation

    Returns:
        True if unmount succeeded, False otherwise
    """
    # If mount point no longer exists, DMG was already detached
    if not os.path.exists(mount_point):
        logger.info(f"Mount point {mount_point} already removed - DMG already detached")
        return True

    try:
        proc = subprocess.Popen(
            (HDIUTIL, "detach", mount_point),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        _, stderr = proc.communicate(timeout=timeout)
        if proc.returncode != 0:
            logger.warning(f"Unmounting {mount_point} failed: {stderr}, retrying with -force")
            return _force_detach(mount_point)
        logger.info(f"Unmounted {mount_point}")
        return True
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
        logger.warning(f"Unmount timed out for {mount_point}, attempting force detach")
        return _force_detach(mount_point)
    except OSError as err:
        logger.warning(f"Failed to unmount {mount_point}: {err}")
        return False


def _force_detach(mount_point):
    """Force detach a mount point as a fallback.

    Args:
        mount_point: The mount point path to force detach

    Returns:
        True if force detach succeeded, False otherwise
    """
    try:
        result = subprocess.run(
            [HDIUTIL, "detach", mount_point, "-force"],
            capture_output=True, text=True, timeout=15
        )
        if result.returncode == 0:
            logger.info(f"Force detached {mount_point}")
            return True
        logger.warning(f"Force detach failed for {mount_point}: {result.stderr}")
        return False
    except Exception as e:
        logger.warning(f"Force detach also failed for {mount_point}: {e}")
        return False

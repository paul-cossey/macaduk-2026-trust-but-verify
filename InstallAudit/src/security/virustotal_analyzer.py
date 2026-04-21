#!/usr/bin/env python3
# Copyright (c) 2026 Paul Cossey. All rights reserved.
# SPDX-License-Identifier: BSD-3-Clause
#
# Based on VirusTotalReporter by Nathaniel Strauss (MIT License)
# https://github.com/autopkg/nstrauss-recipes/tree/master/VirusTotalReporter
# See THIRD_PARTY_LICENSES for details.

"""
VirusTotal Integration for InstallAudit

Based on the VirusTotalReporter AutoPkg processor by Nathaniel Strauss.
Adapted for integration with the InstallAudit testing workflow.
"""

import hashlib
import json
import logging
import os
import ssl
import subprocess
import time
from typing import Dict, Any, Optional, Tuple
from urllib.error import URLError
from urllib.parse import urlencode
from urllib.request import HTTPErrorProcessor, HTTPSHandler, Request, build_opener

from ..core.config_manager import get_config

try:
    import certifi
except ImportError:
    certifi = None

logger = logging.getLogger(__name__)


class NoExceptionHTTPErrorProcessor(HTTPErrorProcessor):
    """Custom HTTP error processor that doesn't raise exceptions for HTTP errors."""
    def http_response(self, request, response):
        return response

    https_response = http_response


class VirusTotalAnalyzer:
    """
    VirusTotal integration for analyzing downloaded files for malware.

    Features:
    - Analyzes files by SHA-256 hash lookup
    - Submits new files for analysis (up to 650MB)
    - Files over 650MB require manual VirusTotal verification
    - Provides detailed reporting for integration into test reports
    """

    def __init__(self, api_key: Optional[str] = None, submit_new: bool = True,
                 timeout: int = 300):
        """
        Initialize VirusTotal analyzer.

        Args:
            api_key: VirusTotal API key (falls back to config file)
            submit_new: Whether to submit new files for analysis
            timeout: Timeout in seconds for new submissions
        """
        config = get_config()
        self.api_key = api_key or config.get_virustotal_key()
        self.submit_new = submit_new
        self.timeout = timeout
        self.curl_path = self._find_curl()

    def _find_curl(self) -> str:
        """Find curl binary path."""
        # Check common locations
        for path in ['/usr/bin/curl', '/opt/homebrew/bin/curl', '/usr/local/bin/curl']:
            if os.path.exists(path) and os.access(path, os.X_OK):
                return path

        # Try which command
        try:
            result = subprocess.run(['which', 'curl'], capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                return result.stdout.strip()
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError):
            pass

        raise RuntimeError("Unable to locate curl binary")

    def _default_ssl_context(self):
        """Create SSL context with certifi if available."""
        if certifi:
            context = ssl.create_default_context(cafile=certifi.where())
        else:
            context = ssl.create_default_context()

        # Enforce TLS 1.2 or higher for security
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        return context

    def _virustotal_api_v3(self, endpoint: str, form_data: dict = None,
                           api_timeout: int = 30) -> Tuple[dict, int]:
        """Make API request to VirusTotal v3 API."""
        url = f"https://www.virustotal.com/api/v3{endpoint}"
        if form_data:
            form_data = urlencode(form_data).encode("utf-8")

        https_handler = HTTPSHandler(context=self._default_ssl_context())
        opener = build_opener(https_handler, NoExceptionHTTPErrorProcessor())
        request = Request(url, headers={"x-apikey": self.api_key}, data=form_data)

        try:
            response = opener.open(request, timeout=api_timeout)
            return self._load_api_json(response.read()), response.status
        except URLError as err:
            logger.error(f"Failed to reach VirusTotal server: {err.reason}")
            raise
        except Exception as err:
            logger.error(f"VirusTotal API error: {err}")
            raise

    def _load_api_json(self, data: bytes) -> dict:
        """Parse VirusTotal API JSON response."""
        valid_keys = ["data", "error"]
        try:
            json_data = json.loads(data)
            # Ensure we always return a dict
            if isinstance(json_data, dict):
                key = next((k for k in valid_keys if k in json_data), None)
                if key:
                    result = json_data[key]
                    # If the result is a string (error message), wrap it in a dict
                    if isinstance(result, str):
                        return {"message": result}
                    return result if isinstance(result, dict) else json_data
                else:
                    return json_data
            else:
                # If json_data is not a dict, wrap it
                return {"message": str(json_data)}
        except (KeyError, json.JSONDecodeError) as err:
            logger.error(f"Couldn't parse VirusTotal API data: {err}")
            # Return error in dict format
            return {"message": f"JSON parse error: {err}", "data": data.decode('utf-8', errors='replace')}

    def _get_sha256(self, file_path: str) -> str:
        """Calculate SHA-256 hash of file."""
        # Defensive type checking
        if not isinstance(file_path, (str, bytes, os.PathLike)):
            raise TypeError(f"file_path must be str, bytes, or PathLike, not {type(file_path)}: {file_path}")

        hash_sha256 = hashlib.sha256()
        with open(file_path, "rb") as file:
            for chunk in iter(lambda: file.read(4096), b""):
                hash_sha256.update(chunk)
        return hash_sha256.hexdigest()

    def _safe_basename(self, file_path) -> str:
        """Safely extract basename from file_path, handling unexpected types."""
        try:
            if isinstance(file_path, (str, bytes, os.PathLike)):
                return os.path.basename(file_path)
            else:
                return str(file_path)
        except Exception:
            return "unknown_file"

    def _curl_new_file(self, input_path: str) -> dict:
        """Submit new file using curl with multipart form data."""
        logger.info("Getting upload URL from VirusTotal")

        # Get upload URL
        upload_url_data, _ = self._virustotal_api_v3("/files/upload_url")

        # Extract the actual URL from the response
        if isinstance(upload_url_data, dict):
            if "data" in upload_url_data:
                upload_url = upload_url_data["data"]
            elif "message" in upload_url_data:
                upload_url = upload_url_data["message"]
            else:
                upload_url = upload_url_data
        else:
            upload_url = upload_url_data

        # Use curl to upload file
        cmd = [
            self.curl_path,
            "--request", "POST",
            "--url", upload_url,
            "--header", "accept: application/json",
            "--header", "content-type: multipart/form-data",
            "--header", f"x-apikey: {self.api_key}",
            "--form", f"file=@{input_path}",
        ]

        logger.info("Uploading file to VirusTotal (this may take several minutes for large files)")
        try:
            result = subprocess.run(cmd, capture_output=True, check=True, text=True, timeout=300)
            return self._load_api_json(result.stdout.encode())
        except subprocess.CalledProcessError as err:
            logger.error(f"File upload failed: {err.stderr}")
            raise
        except subprocess.TimeoutExpired:
            logger.error("File upload timed out")
            raise

    def _submit_new(self, resource: str, identifier: str, analysis_type: str) -> dict:
        """Submit new file or URL for analysis and wait for completion."""
        logger.info(f"Submitting new {analysis_type} for analysis: {identifier}")

        try:
            if analysis_type == "file":
                submission = self._curl_new_file(resource)
            elif analysis_type == "url":
                submission, _ = self._virustotal_api_v3("/urls", {"url": resource})
            else:
                raise ValueError(f"Unknown analysis type: {analysis_type}")
        except Exception as e:
            logger.error(f"Failed to submit {analysis_type}: {e}")
            raise

        # Get analysis URL
        analysis_url = submission["links"]["self"]

        # Wait for analysis to complete
        timer = 0
        while timer < self.timeout:
            time.sleep(30)
            timer += 30
            logger.info(f"Waiting for {analysis_type} analysis to complete: {timer} seconds")

            try:
                analysis_status, status_code = self._virustotal_api_v3(
                    analysis_url.split("v3")[1]
                )

                if (status_code == 200
                        and analysis_status.get("attributes", {}).get("status") == "completed"):
                    logger.info("Analysis complete")
                    break
            except Exception as err:
                logger.warning(f"Error checking analysis status: {err}")
                continue
        else:
            raise TimeoutError(f"Analysis timed out after {self.timeout} seconds")

        # Get final report
        endpoint = f"/{analysis_type}s/{identifier}"
        report, _ = self._virustotal_api_v3(endpoint)
        return report

    def analyze_file(self, file_path: str) -> Dict[str, Any]:
        """
        Analyze a file for malware using VirusTotal.

        Args:
            file_path: Path to the file to analyze

        Returns:
            Dict containing analysis results and metadata
        """
        # Basic validation
        logger.info(f"analyze_file called with file_path: {file_path} (type: {type(file_path)})")

        # Check if file_path is actually a string
        if not isinstance(file_path, (str, bytes, os.PathLike)):
            logger.error(f"file_path is not a valid path type: {type(file_path)} - {file_path}")
            return {
                "error": f"Invalid file_path type: {type(file_path)} - expected str, bytes, or PathLike",
                "status": "error"
            }

        if not os.path.exists(file_path):
            return {
                "error": f"File not found: {file_path}",
                "status": "error"
            }

        # Get file information
        try:
            file_size_mb = round(os.path.getsize(file_path) / (1024 * 1024.0), 2)
            file_sha256 = self._get_sha256(file_path)
            logger.info(f"File size: {file_size_mb} MB, SHA-256: {file_sha256}")
        except Exception as e:
            logger.error(f"Error getting file information: {e}")
            return {
                "error": f"Error getting file information: {e}",
                "status": "error"
            }

        logger.info(f"Analyzing file: {self._safe_basename(file_path)} ({file_size_mb} MB)")
        logger.info(f"SHA-256: {file_sha256}")

        try:
            # Try to get existing report
            logger.info("Checking VirusTotal database for existing analysis")
            report, status_code = self._virustotal_api_v3(f"/files/{file_sha256}")

            if status_code == 200:
                logger.info("Found existing analysis in VirusTotal database")
                return self._process_report(report, file_path, file_size_mb)            # File not found in database
            if status_code == 404:
                if not self.submit_new:
                    return {
                        "status": "not_found",
                        "message": "File not found in VirusTotal database and submission disabled",
                        "file_name": self._safe_basename(file_path),
                        "file_size_mb": file_size_mb,
                        "sha256": file_sha256,
                        "requires_manual_check": True
                    }

                # Check file size limit for direct submission
                if file_size_mb > 650:
                    logger.warning(f"File size ({file_size_mb} MB) exceeds 650 MB limit")

                    return {
                        "status": "too_large",
                        "message": f"File too large ({file_size_mb} MB) for VirusTotal submission (max 650 MB)",
                        "file_name": self._safe_basename(file_path),
                        "file_size_mb": file_size_mb,
                        "sha256": file_sha256,
                        "requires_manual_check": True
                    }

                # Submit new file
                logger.info("Submitting new file for analysis (this may take several minutes)")
                report = self._submit_new(file_path, file_sha256, "file")
                return self._process_report(report, file_path, file_size_mb)

            # Other error
            return {
                "status": "api_error",
                "message": f"VirusTotal API error: {status_code}",
                "file_name": self._safe_basename(file_path),
                "file_size_mb": file_size_mb,
                "sha256": file_sha256
            }

        except Exception as err:
            logger.error(f"VirusTotal analysis failed: {err}")

            # Safe filename extraction
            try:
                file_name = self._safe_basename(file_path)
            except Exception:
                file_name = "unknown_file"

            # Safe file size and SHA256 extraction
            try:
                file_size = file_size_mb if 'file_size_mb' in locals() else 0.0
            except Exception:
                file_size = 0.0

            try:
                sha256 = file_sha256 if 'file_sha256' in locals() else "unknown"
            except Exception:
                sha256 = "unknown"

            return {
                "status": "error",
                "message": str(err),
                "file_name": file_name,
                "file_size_mb": file_size,
                "sha256": sha256
            }

    def analyze_url(self, url: str) -> Dict[str, Any]:
        """
        Analyze a URL for malware using VirusTotal.

        Args:
            url: URL to analyze

        Returns:
            Dict containing analysis results and metadata
        """
        logger.info(f"Analyzing URL: {url}")

        if not url or not isinstance(url, str):
            return {
                "error": "Invalid URL provided",
                "status": "error"
            }

        try:
            import base64

            # Ensure URL has protocol
            if not url.startswith(('http://', 'https://')):
                # Try to determine if it's an IP address or domain
                if ':' in url and url.count(':') <= 1:  # Likely IP:port
                    url = f"http://{url}"
                else:
                    url = f"https://{url}"

            # Create URL identifier for VirusTotal (base64 encoded URL without padding)
            url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip('=')

            logger.info(f"Checking existing analysis for URL: {url}")

            # First, check if URL already exists in VirusTotal database
            try:
                report, status_code = self._virustotal_api_v3(f"/urls/{url_id}")
            except Exception as e:
                logger.debug(f"Error checking existing URL analysis: {e}")
                status_code = 404

            # If URL found, process existing report
            if status_code == 200:
                logger.info("Found existing URL analysis in VirusTotal database")
                return self._process_url_report(report, url)

            # URL not found in database
            if status_code == 404:
                if not self.submit_new:
                    return {
                        "status": "not_found",
                        "message": "URL not found in VirusTotal database and submission disabled",
                        "url": url,
                        "requires_manual_check": True
                    }

                logger.info(f"URL not found in database, submitting for analysis: {url}")
                try:
                    report = self._submit_new(url, url_id, "url")
                    return self._process_url_report(report, url)
                except Exception as e:
                    logger.error(f"Failed to submit URL for analysis: {e}")
                    return {
                        "status": "submission_failed",
                        "message": f"Failed to submit URL for analysis: {str(e)}",
                        "url": url,
                        "requires_manual_check": True
                    }

            # Other status code
            return {
                "status": "api_error",
                "message": f"VirusTotal API returned status code: {status_code}",
                "url": url,
                "requires_manual_check": True
            }

        except Exception as err:
            logger.error(f"Error analyzing URL {url}: {err}")
            return {
                "status": "error",
                "message": str(err),
                "url": url
            }

    def _process_url_report(self, report: dict, url: str) -> Dict[str, Any]:
        """Process VirusTotal URL report into standardized format."""
        attributes = report.get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})

        harmless = stats.get("harmless", 0)
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        undetected = stats.get("undetected", 0)

        total_detected = malicious + suspicious
        total_scanned = harmless + malicious + suspicious + undetected

        # Determine status
        if malicious > 0:
            status = "malicious"
        elif suspicious > 0:
            status = "suspicious"
        elif total_detected == 0:
            status = "clean"
        else:
            status = "unknown"

        return {
            "status": status,
            "url": url,
            "analysis_type": "url",
            "scan_results": {
                "harmless": harmless,
                "malicious": malicious,
                "suspicious": suspicious,
                "undetected": undetected,
                "total_detected": total_detected,
                "total_scanned": total_scanned,
                "detection_ratio": f"{total_detected}/{total_scanned}"
            },
            "permalink": f"https://www.virustotal.com/gui/url/{report.get('id')}",
            "scan_date": attributes.get("last_analysis_date"),
            "first_submission_date": attributes.get("first_submission_date"),
            "final_url": attributes.get("url", url),  # VirusTotal may follow redirects
            "title": attributes.get("title", ""),
            "categories": attributes.get("categories", {})
        }

    def _process_report(self, report: dict, file_path: str, file_size_mb: float,
                        analysis_type: str = "file") -> Dict[str, Any]:
        """Process VirusTotal report into standardized format."""
        attributes = report.get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})

        harmless = stats.get("harmless", 0)
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        undetected = stats.get("undetected", 0)

        total_detected = malicious + suspicious
        total_scanned = harmless + malicious + suspicious + undetected

        # Determine status
        if malicious > 0:
            status = "malicious"
        elif suspicious > 0:
            status = "suspicious"
        elif total_detected == 0:
            status = "clean"
        else:
            status = "unknown"

        return {
            "status": status,
            "file_name": self._safe_basename(file_path),
            "file_size_mb": file_size_mb,
            "analysis_type": analysis_type,
            "scan_results": {
                "harmless": harmless,
                "malicious": malicious,
                "suspicious": suspicious,
                "undetected": undetected,
                "total_detected": total_detected,
                "total_scanned": total_scanned,
                "detection_ratio": f"{total_detected}/{total_scanned}"
            },
            "permalink": f"https://www.virustotal.com/gui/{analysis_type}/{report.get('id')}",
            "sha256": report.get("id") if analysis_type == "file" else None,
            "scan_date": attributes.get("last_analysis_date"),
            "first_submission_date": attributes.get("first_submission_date"),
        }

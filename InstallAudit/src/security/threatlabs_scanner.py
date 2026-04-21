#!/usr/bin/env python3
"""
ThreatLabs Scanner

Submits Mach-O binaries to ThreatLabs for security analysis.
Copyright (c) 2026 Paul Cossey. All rights reserved.
SPDX-License-Identifier: BSD-3-Clause
"""

import hashlib
import json
import logging
import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Any, Optional
from urllib.error import URLError, HTTPError
from urllib.request import Request, urlopen

from ..core.config_manager import get_config

logger = logging.getLogger(__name__)


class ThreatLabsScanner:
    """
    ThreatLabs binary scanning integration.

    Features:
    - Submit Mach-O binaries for analysis
    - Poll for analysis results
    - Comprehensive threat reporting
    - API key management
    """

    # API endpoints
    BASE_URL = "https://api.scry.threatlabs.protect.jamfcloud.com"
    UPLOAD_ENDPOINT = "/api/v1/submissions/upload"
    STATUS_ENDPOINT = "/api/v1/submissions/{submission_id}/status"
    RESULTS_ENDPOINT = "/api/v1/submissions/{submission_id}/results"
    HASH_EXISTS_ENDPOINT = "/api/v1/hashes/{hash_type}/{hash_value}/exists"

    # File size limit from API
    MAX_FILE_SIZE_MB = 50

    # Debug log file path
    DEBUG_LOG_PATH = '/tmp/threatlabs_debug.log'

    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize ThreatLabs scanner.

        Args:
            api_key: ThreatLabs API key (falls back to config file)
        """
        config = get_config()
        self.api_key = api_key or config.get_threatlabs_key()
        self.submission_results = {}

        if not self.api_key:
            logger.warning("No ThreatLabs API key provided - scanning will be skipped")

    def is_available(self) -> bool:
        """Check if ThreatLabs scanning is available (API key configured)."""
        return bool(self.api_key)

    def scan_binaries(self, binaries: List[Dict[str, Any]], max_submissions: int = 100) -> Dict[str, Any]:
        """
        Scan multiple binaries with ThreatLabs.

        Args:
            binaries: List of binary info dicts from BinaryExtractor
            max_submissions: Maximum number of binaries to submit per batch (to avoid rate limits)

        Returns:
            Dict containing scan results
        """
        if not self.is_available():
            logger.warning("ThreatLabs API key not configured - skipping scan")
            return {
                'total_binaries': len(binaries),
                'submitted': 0,
                'skipped': 0,
                'results': [],
                'errors': ['ThreatLabs API key not configured']
            }

        results = {
            'total_binaries': len(binaries),
            'submitted': 0,
            'skipped': 0,
            'results': [],
            'errors': []
        }

        # Initialize debug log file
        with open(self.DEBUG_LOG_PATH, 'w') as f:
            f.write("=== ThreatLabs Scan Debug Log ===\n")
            f.write(f"Scanning {len(binaries)} binaries in batches of {max_submissions}\n\n")

        # Process all binaries in batches
        total_binaries = len(binaries)
        for batch_start in range(0, total_binaries, max_submissions):
            batch_end = min(batch_start + max_submissions, total_binaries)
            batch = binaries[batch_start:batch_end]
            batch_num = (batch_start // max_submissions) + 1
            total_batches = (total_binaries + max_submissions - 1) // max_submissions

            logger.info(f"Processing batch {batch_num}/{total_batches}: {len(batch)} binaries")

            # Submit binaries in parallel using ThreadPoolExecutor
            with ThreadPoolExecutor(max_workers=5) as executor:
                # Submit all tasks for this batch
                future_to_binary = {executor.submit(self._scan_binary, binary): binary for binary in batch}

                # Process completed tasks as they finish
                for future in as_completed(future_to_binary):
                    binary = future_to_binary[future]
                    try:
                        result = future.result()
                        if result:
                            results['results'].append(result)
                            results['submitted'] += 1
                        else:
                            results['errors'].append(f"Failed to scan {binary['name']}")
                    except Exception as e:
                        error_msg = f"Error scanning {binary['name']}: {e}"
                        logger.error(error_msg)
                        results['errors'].append(error_msg)

        return results

    def _scan_binary(self, binary: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Scan a single binary with ThreatLabs.

        Args:
            binary: Binary info dict

        Returns:
            Dict with scan result or None on failure
        """
        binary_path = binary['path']
        binary_name = binary['name']

        if not os.path.exists(binary_path):
            logger.error(f"Binary not found: {binary_path}")
            return None

        try:
            # Check file size (max 50MB)
            file_size_bytes = os.path.getsize(binary_path)
            file_size_mb = file_size_bytes / (1024 * 1024)

            if file_size_mb > self.MAX_FILE_SIZE_MB:
                logger.warning(f"Binary too large: {binary_name} ({file_size_mb:.2f} MB)")
                return {
                    'name': binary_name,
                    'path': binary['relative_path'],
                    'source_app': binary.get('source_app', 'Unknown'),
                    'app_bundle': binary.get('app_bundle'),
                    'status': 'too_large',
                    'threat_level': 'unknown',
                    'file_size_mb': f"{file_size_mb:.2f}",
                    'message': f'File exceeds {self.MAX_FILE_SIZE_MB}MB limit'
                }

            # Calculate SHA-256
            sha256 = self._get_sha256(binary_path)
            print(f"\n🔍 Checking binary: {binary_name}")
            print(f"   SHA-256: {sha256}")
            logger.info(f"Checking {binary_name} (SHA-256: {sha256})")

            # Check if hash already exists in ThreatLabs
            print("   Checking if hash exists in ThreatLabs...")
            existing_result = self._check_hash_exists(sha256)
            if existing_result:
                print("   ✅ Hash found in ThreatLabs - using cached analysis")
                logger.info(f"Hash found in ThreatLabs - using existing analysis for {binary_name}")
                # Extract submission_id from cached result
                # Hash lookup returns submission_ids as an array - use the first one if available
                cached_submission_id = None
                if existing_result.get('submission_ids') and len(existing_result['submission_ids']) > 0:
                    cached_submission_id = existing_result['submission_ids'][0]
                    print(f"   📝 Using submission_id: {cached_submission_id}")
                else:
                    print("   No submission_ids in response")
                    # Write response to debug for investigation
                    with open(self.DEBUG_LOG_PATH, 'a') as f:
                        f.write("\n=== Hash lookup with no submission_ids ===\n")
                        f.write(f"Binary: {binary_name}\n")
                        f.write(f"SHA-256: {sha256}\n")
                        f.write(json.dumps(existing_result, indent=2))
                        f.write("\n=== End ===\n\n")
                return self._parse_analysis_result(existing_result, binary, sha256, cached_submission_id, is_hash_lookup=True)

            # Hash not found, submit binary
            print("   ℹ️  Hash not found - submitting binary for analysis...")
            logger.info(f"Hash not found - submitting {binary_name}")
            submission_id = self._submit_binary(binary_path, binary_name)

            if submission_id == "UNSUPPORTED_FORMAT":
                # ThreatLabs doesn't support this file type (usually frameworks/shared libraries)
                logger.info(f"File type not supported by ThreatLabs API: {binary_name}")
                return {
                    'name': binary_name,
                    'path': binary['relative_path'],
                    'source_app': binary.get('source_app', 'Unknown'),
                    'app_bundle': binary.get('app_bundle'),
                    'sha256': sha256,
                    'status': 'unsupported_format',
                    'threat_level': 'unsupported',
                    'file_type': binary.get('type', 'Unknown'),
                    'message': 'File type not supported by ThreatLabs API (likely a framework or shared library)'
                }

            if not submission_id:
                logger.error(f"Failed to submit {binary_name}")
                return {
                    'name': binary_name,
                    'path': binary['relative_path'],
                    'source_app': binary.get('source_app', 'Unknown'),
                    'app_bundle': binary.get('app_bundle'),
                    'sha256': sha256,
                    'status': 'submission_failed',
                    'threat_level': 'unknown',
                    'message': 'Failed to upload to ThreatLabs'
                }

            logger.info(f"Submitted {binary_name} - ID: {submission_id}")

            # Poll for results (with timeout)
            analysis_result = self._get_analysis_result(submission_id, max_wait=120)

            if not analysis_result:
                logger.warning(f"Analysis timed out for {binary_name}")
                return {
                    'name': binary_name,
                    'path': binary['relative_path'],
                    'source_app': binary.get('source_app', 'Unknown'),
                    'app_bundle': binary.get('app_bundle'),
                    'sha256': sha256,
                    'submission_id': submission_id,
                    'status': 'pending',
                    'threat_level': 'unknown',
                    'detections': []
                }

            # Parse analysis result
            return self._parse_analysis_result(analysis_result, binary, sha256, submission_id)

        except Exception as e:
            logger.error(f"Error scanning {binary_name}: {e}")
            return None

    def _check_hash_exists(self, sha256: str) -> Optional[Dict[str, Any]]:
        """
        Check if a hash already exists in ThreatLabs and retrieve results.

        Args:
            sha256: SHA-256 hash of the file

        Returns:
            Analysis result dict if hash exists, None otherwise
        """
        try:
            # Check if hash exists
            check_url = f"{self.BASE_URL}{self.HASH_EXISTS_ENDPOINT.format(hash_type='sha256', hash_value=sha256)}"
            check_request = Request(check_url)
            check_request.add_header('Authorization', f'Bearer {self.api_key}')

            with urlopen(check_request, timeout=60) as response:
                result = json.loads(response.read().decode('utf-8'))

                # Write to debug file
                with open(self.DEBUG_LOG_PATH, 'a') as f:
                    f.write(f"\n=== Hash lookup response for {sha256[:16]}... ===\n")
                    f.write(json.dumps(result, indent=2))
                    f.write("\n=== End hash lookup response ===\n\n")

                # Check if hash exists - API returns "exists": true/false
                if result.get('exists') is True:
                    logger.debug(f"Hash exists in ThreatLabs: {sha256[:16]}...")
                    return result

                # Hash not found
                return None

        except URLError as e:
            # 404 typically means hash doesn't exist
            if hasattr(e, 'code') and e.code == 404:
                print("   ℹ️  Hash not in database (404)")
                logger.debug(f"Hash not found in ThreatLabs: {sha256[:16]}...")
                return None
            print(f"   ⚠️  Error checking hash: {e}")
            logger.warning(f"Error checking hash: {e}")
            return None
        except Exception as e:
            logger.warning(f"Error checking hash: {e}")
            return None

    def _submit_binary(self, binary_path: str, binary_name: str) -> Optional[str]:
        """
        Submit a binary to ThreatLabs.

        Args:
            binary_path: Path to binary file
            binary_name: Name of binary

        Returns:
            Submission ID string, or special codes:
            - None: Network/other errors
            - "UNSUPPORTED_FORMAT": HTTP 415 - ThreatLabs doesn't accept this file type
        """
        try:
            # Read binary file
            with open(binary_path, 'rb') as f:
                file_data = f.read()

            # Prepare multipart form data
            boundary = '----ThreatLabsBoundary' + str(int(time.time()))

            # Build multipart body
            body_parts = []

            # Add file field
            body_parts.append(f'--{boundary}'.encode())
            body_parts.append(f'Content-Disposition: form-data; name="file"; filename="{binary_name}"'.encode())
            body_parts.append(b'Content-Type: application/octet-stream')
            body_parts.append(b'')
            body_parts.append(file_data)

            # End boundary
            body_parts.append(f'--{boundary}--'.encode())
            body_parts.append(b'')

            body = b'\r\n'.join(body_parts)

            # Create request
            url = f"{self.BASE_URL}{self.UPLOAD_ENDPOINT}"
            request = Request(url, data=body, method='POST')
            request.add_header('Authorization', f'Bearer {self.api_key}')
            request.add_header('Content-Type', f'multipart/form-data; boundary={boundary}')
            request.add_header('Content-Length', str(len(body)))

            # Submit request (5 minute timeout for large files)
            with urlopen(request, timeout=300) as response:
                response_data = json.loads(response.read().decode('utf-8'))

                # Extract submission ID from response
                submission_id = response_data.get('submission_id')
                return submission_id

        except HTTPError as e:
            if e.code == 415:
                # HTTP 415: Unsupported Media Type
                # ThreatLabs only accepts certain file types (executables, not shared libraries)
                logger.info(f"ThreatLabs doesn't support this file type: {binary_name} (HTTP 415)")
                return "UNSUPPORTED_FORMAT"
            else:
                logger.error(f"HTTP error {e.code} submitting binary: {e}")
                return None
        except URLError as e:
            logger.error(f"Network error submitting binary: {e}")
            return None
        except Exception as e:
            logger.error(f"Error submitting binary: {e}")
            return None

    def _get_analysis_result(self, submission_id: str, max_wait: int = 120) -> Optional[Dict[str, Any]]:
        """
        Poll for analysis results.

        Args:
            submission_id: Submission ID from upload
            max_wait: Maximum time to wait in seconds

        Returns:
            Analysis result dict or None on timeout/failure
        """
        start_time = time.time()
        poll_interval = 5  # Poll every 5 seconds

        while time.time() - start_time < max_wait:
            try:
                # First check status (lightweight endpoint)
                status_url = f"{self.BASE_URL}{self.STATUS_ENDPOINT.format(submission_id=submission_id)}"
                status_request = Request(status_url)
                status_request.add_header('Authorization', f'Bearer {self.api_key}')

                with urlopen(status_request, timeout=60) as response:
                    status_result = json.loads(response.read().decode('utf-8'))

                    # Response format: {"submission_id": "...", "status": "queued|processing|completed", "updated_at": "..."}
                    status = status_result.get('status', '').lower()

                    if status == 'completed':
                        # Get full results
                        results_url = f"{self.BASE_URL}{self.RESULTS_ENDPOINT.format(submission_id=submission_id)}"
                        results_request = Request(results_url)
                        results_request.add_header('Authorization', f'Bearer {self.api_key}')

                        with urlopen(results_request, timeout=60) as results_response:
                            results_data = json.loads(results_response.read().decode('utf-8'))
                            # Write to debug file
                            with open(self.DEBUG_LOG_PATH, 'a') as f:
                                f.write(f"\n=== Submission results for {submission_id} ===\n")
                                f.write(json.dumps(results_data, indent=2))
                                f.write("\n=== End submission results ===\n\n")
                            return results_data

                    elif status in ['failed', 'error']:
                        logger.error(f"Analysis failed for submission {submission_id}")
                        return None

                    # Still processing (queued or processing), wait and retry
                    time.sleep(poll_interval)

            except URLError as e:
                logger.warning(f"Network error polling results: {e}")
                time.sleep(poll_interval)
            except Exception as e:
                logger.error(f"Error polling results: {e}")
                return None

        logger.warning(f"Analysis timeout for submission {submission_id}")
        return None

    def _parse_analysis_result(self, result: Dict[str, Any], binary: Dict[str, Any],
                               sha256: str, submission_id: str, is_hash_lookup: bool = False) -> Dict[str, Any]:
        """
        Parse ThreatLabs analysis result into standardized format.

        Args:
            result: Raw API response from /results or /hashes endpoint
            binary: Original binary info dict
            sha256: File SHA-256 hash
            submission_id: Submission ID (if available)
            is_hash_lookup: True if result is from hash lookup, False if from submission

        Returns:
            Standardized result dict
        """
        # Handle both hash lookup and submission result formats
        if is_hash_lookup:
            # Hash lookup response format
            threat_detected = result.get('blocked', False) or bool(result.get('threat_name'))
            # Determine threat level
            if result.get('blocked'):
                threat_level = 'malicious'
            elif result.get('yara_matches'):
                threat_level = 'suspicious'
            else:
                threat_level = 'clean'
            detection_method = 'hash_lookup'
        else:
            # Submission result format
            threat_detected = result.get('threat_detected', False)
            threat_level = result.get('threat_level', 'unknown')
            detection_method = result.get('detection_method', '')

        # Map threat_level to our categories
        if threat_level == 'no_detections' or not threat_detected:
            status_level = 'clean'
        elif threat_level in ['low', 'medium']:
            status_level = 'suspicious'
        elif threat_level in ['high', 'critical']:
            status_level = 'malicious'
        else:
            status_level = 'unknown'

        parsed = {
            'name': binary['name'],
            'path': binary['relative_path'],
            'source_app': binary.get('source_app', 'Unknown'),
            'app_bundle': binary.get('app_bundle'),
            'sha256': sha256,
            'submission_id': submission_id if submission_id else None,
            'status': 'completed',
            'threat_level': status_level,
            'threat_detected': threat_detected,
            'detection_method': detection_method,
            'detections': [],
            'analysis_duration': result.get('analysis_duration'),
            'protect_version': result.get('protect_version'),
        }

        # Add developer info if available (from hash lookup or submission)
        if result.get('developer_name'):
            parsed['developer_name'] = result['developer_name']
            print(f"   Found developer_name: {result['developer_name']}")
        if result.get('signing_id'):
            parsed['signing_id'] = result['signing_id']
            print(f"   Found signing_id: {result['signing_id']}")

        # Add threat info if available (from hash lookup)
        if result.get('threat_name'):
            parsed['threat_name'] = result['threat_name']
            print(f"   Found threat_name: {result['threat_name']}")
        if result.get('blocked') is not None:
            parsed['blocked'] = result['blocked']
            print(f"   Found blocked: {result['blocked']}")
        if result.get('blocking_reason'):
            parsed['blocking_reason'] = result['blocking_reason']
            print(f"   Found blocking_reason: {result['blocking_reason']}")

        # Parse yara_matches from hash lookup
        if is_hash_lookup and result.get('yara_matches'):
            for match in result['yara_matches']:
                parsed['detections'].append({
                    'type': 'yara',
                    'severity': threat_level,
                    'description': f"YARA rule: {match.get('rule', 'unknown')}",
                    'indicator': match.get('rule', ''),
                    'metadata': match.get('metadata', {})
                })

        # Parse analysis_results for detections (from submission)
        analysis_results = result.get('analysis_results', {})
        if analysis_results and isinstance(analysis_results, dict):
            # Extract any detection details from analysis_results
            for key, value in analysis_results.items():
                if isinstance(value, list):
                    for item in value:
                        if isinstance(item, dict):
                            parsed['detections'].append({
                                'type': key,
                                'severity': threat_level,
                                'description': item.get('description', ''),
                                'indicator': item.get('indicator', '')
                            })

        # Add LLM analysis if available
        if result.get('llm_analysis'):
            parsed['llm_analysis'] = result['llm_analysis']

        return parsed

    def _get_sha256(self, file_path: str) -> str:
        """
        Calculate SHA-256 hash of a file.

        Args:
            file_path: Path to file

        Returns:
            SHA-256 hash as hex string
        """
        sha256_hash = hashlib.sha256()

        with open(file_path, 'rb') as f:
            for byte_block in iter(lambda: f.read(4096), b''):
                sha256_hash.update(byte_block)

        return sha256_hash.hexdigest()

    def get_summary(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate summary statistics from scan results.

        Args:
            scan_results: Results from scan_binaries()

        Returns:
            Summary dict with statistics
        """
        summary = {
            'total_binaries': scan_results.get('total_binaries', 0),
            'submitted': scan_results.get('submitted', 0),
            'skipped': scan_results.get('skipped', 0),
            'clean': 0,
            'suspicious': 0,
            'malicious': 0,
            'unknown': 0,
            'pending': 0,
            'too_large': 0,
            'unsupported': 0
        }

        for result in scan_results.get('results', []):
            status = result.get('status', '')
            threat_level = result.get('threat_level', 'unknown').lower()

            # Check for special statuses first
            if status == 'too_large':
                summary['too_large'] += 1
            elif status == 'unsupported_format' or threat_level == 'unsupported':
                summary['unsupported'] += 1
            elif threat_level in ['clean', 'safe', 'benign']:
                summary['clean'] += 1
            elif threat_level in ['suspicious', 'warning']:
                summary['suspicious'] += 1
            elif threat_level in ['malicious', 'danger', 'threat']:
                summary['malicious'] += 1
            elif threat_level == 'pending':
                summary['pending'] += 1
            else:
                summary['unknown'] += 1

        return summary

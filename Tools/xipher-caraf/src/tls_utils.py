#!/usr/bin/env python3

# Copyright 2026 Comcast Cable Communications Management, LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
TLS Verification and Secure Request Utilities
==============================================
Provides explicit HTTPS verification with certificate pinning support for GitHub API.

Features:
- Explicit verify=True enforcement on all requests
- Cache-aware certificate SHA256 fingerprint validation
- Trust-On-First-Use (TOFU) pin tracking
- Environment variable pinning support (XIPHER_GITHUB_CERT_SHA256_PINS)
"""

import os
import ssl
import socket
import hashlib
import threading
import time
from urllib.parse import urlparse
from typing import Optional, Dict, Any

import requests


class GitHubTLSVerifier:
    """Validate GitHub API server certificates using pinning/TOFU checks."""

    TARGET_HOSTS = {"api.github.com"}

    def __init__(
        self,
        pinned_fingerprints: Optional[set] = None,
        enforce_tofu: bool = True,
        cache_ttl_seconds: int = 300,
    ):
        """
        Initialize TLS verifier.
        
        Args:
            pinned_fingerprints: Set of allowed cert SHA256 fingerprints (hex)
            enforce_tofu: Enable Trust-On-First-Use pin caching
            cache_ttl_seconds: Fingerprint cache lifetime
        """
        self.pinned_fingerprints = pinned_fingerprints or set()
        self.enforce_tofu = enforce_tofu
        self.cache_ttl_seconds = cache_ttl_seconds
        self._cache: Dict[str, Dict[str, Any]] = {}
        self._tofu_pins: Dict[str, str] = {}
        self._lock = threading.Lock()

    @staticmethod
    def _normalize_fingerprint(value: str) -> str:
        """Normalize fingerprint to lowercase hex without colons."""
        return value.strip().lower().replace(":", "")

    @classmethod
    def from_env(cls) -> 'GitHubTLSVerifier':
        """
        Build verifier from environment variable XIPHER_GITHUB_CERT_SHA256_PINS.
        
        Format: comma-separated hex fingerprints (colons optional).
        """
        raw = os.getenv("XIPHER_GITHUB_CERT_SHA256_PINS", "")
        pins = {
            cls._normalize_fingerprint(part)
            for part in raw.split(",")
            if part.strip()
        }
        return cls(pinned_fingerprints=pins, enforce_tofu=True)

    @staticmethod
    def _get_server_cert_sha256(hostname: str, port: int = 443) -> str:
        """Fetch server certificate and return SHA256 fingerprint."""
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as tls_sock:
                cert_der = tls_sock.getpeercert(binary_form=True)
        return hashlib.sha256(cert_der).hexdigest()

    def _get_current_fingerprint(self, host: str) -> str:
        """Get current server certificate fingerprint with cache."""
        now = time.time()
        with self._lock:
            cached = self._cache.get(host)
            if cached and now - cached["ts"] < self.cache_ttl_seconds:
                return cached["fp"]

        fingerprint = self._get_server_cert_sha256(host)
        with self._lock:
            self._cache[host] = {"fp": fingerprint, "ts": now}
        return fingerprint

    def validate_url(self, url: str):
        """
        Validate TLS identity for target GitHub hosts.
        
        Raises:
            requests.exceptions.SSLError: If pinning or TOFU check fails
        """
        host = (urlparse(url).hostname or "").lower()
        if host not in self.TARGET_HOSTS:
            return

        current_fp = self._get_current_fingerprint(host)
        with self._lock:
            if self.pinned_fingerprints:
                if current_fp not in self.pinned_fingerprints:
                    raise requests.exceptions.SSLError(
                        f"TLS pinning failed for {host}: fingerprint mismatch"
                    )
                return

            if self.enforce_tofu:
                known = self._tofu_pins.get(host)
                if known is None:
                    self._tofu_pins[host] = current_fp
                elif known != current_fp:
                    raise requests.exceptions.SSLError(
                        f"TLS TOFU pin changed for {host}: refusing connection"
                    )


# Global default verifier initialized from environment
_DEFAULT_TLS_VERIFIER = GitHubTLSVerifier.from_env()


def secure_request(
    method: str, 
    url: str, 
    tls_verifier: Optional[GitHubTLSVerifier] = None, 
    **kwargs
) -> requests.Response:
    """
    Send HTTPS requests with explicit TLS verification and GitHub pinning checks.
    
    Args:
        method: HTTP method (GET, POST, etc.)
        url: Request URL (must use https://)
        tls_verifier: Custom TLS verifier (uses default if None)
        **kwargs: Additional requests.request() arguments
    
    Returns:
        requests.Response object
    
    Raises:
        ValueError: If verify parameter is not True
        requests.exceptions.SSLError: If TLS pinning/TOFU check fails
    """
    verify = kwargs.pop("verify", True)
    if verify is not True:
        raise ValueError("Insecure TLS override is not allowed; verify must be True.")

    verifier = tls_verifier or _DEFAULT_TLS_VERIFIER
    verifier.validate_url(url)
    return requests.request(method=method, url=url, verify=True, **kwargs)


__all__ = [
    'GitHubTLSVerifier',
    'secure_request',
]

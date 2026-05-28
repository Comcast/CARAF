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
GitHub Authentication Module
============================
Provides authentication helpers for GitHub API access.

Supports:
- Personal Access Token (PAT) authentication
- GitHub App authentication (App ID + Private Key)

Usage:
    from src.auth import GitHubAuthManager, GitHubTokenManager, get_auth_from_user
    
    # PAT authentication
    auth = GitHubAuthManager(pat_token="your_token")
    
    # GitHub App authentication
    token_manager = GitHubTokenManager(app_id="12345", private_key="...")
    auth = GitHubAuthManager(token_manager=token_manager, installation_id=123)
"""

import os
import time
import threading
from getpass import getpass
from datetime import datetime, timedelta, timezone
from typing import Tuple, Optional

import requests
import jwt

from src.tls_utils import secure_request


def _request_with_retries(
    method: str,
    url: str,
    retries: int = 3,
    backoff_seconds: float = 1.0,
    **kwargs,
) -> requests.Response:
    """Perform a secure HTTP request with retries for transient network/server errors."""
    last_exc: Optional[Exception] = None

    for attempt in range(1, retries + 1):
        try:
            response = secure_request(method, url, **kwargs)

            # Retry transient server-side conditions.
            if response.status_code in (429, 500, 502, 503, 504) and attempt < retries:
                time.sleep(backoff_seconds * (2 ** (attempt - 1)))
                continue

            return response
        except (
            requests.exceptions.Timeout,
            requests.exceptions.ConnectionError,
            requests.exceptions.SSLError,
        ) as exc:
            last_exc = exc
            if attempt >= retries:
                raise
            time.sleep(backoff_seconds * (2 ** (attempt - 1)))

    if last_exc:
        raise last_exc
    raise RuntimeError("Request failed unexpectedly without response")


def generate_jwt(app_id: str, private_key: str) -> str:
    """
    Generate JWT for GitHub App authentication.
    
    Args:
        app_id: GitHub App ID
        private_key: Private key PEM content
    
    Returns:
        JWT token string
    """
    payload = {
        "iat": int(time.time()),
        "exp": int(time.time()) + (10 * 60),
        "iss": str(app_id),
    }
    return jwt.encode(payload, private_key, algorithm="RS256")


def list_installations(jwt_token: str, org: str) -> int:
    """
    List GitHub App installations and get installation ID for org.
    
    Args:
        jwt_token: JWT token for authentication
        org: Organization name
    
    Returns:
        Installation ID for the organization
    
    Raises:
        RuntimeError: If listing fails or org not found in installations
    """
    url = "https://api.github.com/app/installations"
    headers = {
        "Authorization": f"Bearer {jwt_token}",
        "Accept": "application/vnd.github.v3+json",
    }
    
    try:
        per_page = 100
        page = 1
        normalized_target_org = org.strip().lower()

        while True:
            response = _request_with_retries(
                "GET",
                url,
                headers=headers,
                params={"per_page": per_page, "page": page},
                timeout=(10, 30),
                retries=4,
                backoff_seconds=1.0,
            )
            response.raise_for_status()

            installations = response.json()
            for installation in installations:
                account_login = installation.get("account", {}).get("login", "")
                if account_login.lower() == normalized_target_org:
                    return installation["id"]

            # If fewer than per_page results are returned, this is the last page.
            if len(installations) < per_page:
                break

            page += 1

        raise ValueError(f"Organization '{org}' not found in GitHub App installations")
    except requests.exceptions.RequestException as e:
        raise RuntimeError(f"Failed to list GitHub App installations (auth may be invalid): {e}") from e
    except Exception as e:
        raise RuntimeError(f"Unexpected error listing installations: {e}") from e


class GitHubAuthManager:
    """
    Thread-safe GitHub authentication manager.
    
    Supports both PAT and GitHub App authentication methods.
    
    Usage:
        # PAT authentication
        auth = GitHubAuthManager(pat_token="your_token")
        headers = auth.get_headers()
        
        # GitHub App authentication
        token_manager = GitHubTokenManager(app_id, private_key)
        installation_id = list_installations(jwt_token, org)
        auth = GitHubAuthManager(token_manager=token_manager, installation_id=installation_id)
    """
    
    def __init__(
        self, 
        pat_token: Optional[str] = None, 
        app_id: Optional[str] = None, 
        private_key: Optional[str] = None,
        token_manager: Optional['GitHubTokenManager'] = None, 
        installation_id: Optional[int] = None
    ):
        """
        Initialize authentication manager.
        
        Args:
            pat_token: Personal Access Token (for PAT auth)
            app_id: GitHub App ID (for App auth)
            private_key: GitHub App private key (for App auth)
            token_manager: GitHubTokenManager instance (for App auth)
            installation_id: GitHub App installation ID (for App auth)
        """
        self.lock = threading.Lock()
        self.auth_headers = {"Accept": "application/vnd.github.v3+json"}
        
        self.is_pat = bool(pat_token)
        self.app_id = app_id
        self.token_manager = token_manager
        self.installation_id = installation_id

        if self.is_pat:
            self.update_header(pat_token, is_pat=True)
        elif token_manager and installation_id:
            initial_token = self.token_manager.get_access_token(self.installation_id)
            if initial_token:
                self.update_header(initial_token, is_pat=False)

    def update_header(self, token: str, is_pat: bool = False):
        """Update authorization header with new token."""
        with self.lock:
            if is_pat:
                self.auth_headers["Authorization"] = f"token {token}"
            else:
                self.auth_headers["Authorization"] = f"Bearer {token}"

    def get_headers(self) -> dict:
        """Get a copy of current authentication headers."""
        with self.lock:
            return self.auth_headers.copy()


class GitHubTokenManager:
    """
    GitHub App token manager with automatic refresh.
    
    Handles JWT generation and installation access token retrieval
    with automatic caching and refresh before expiration.
    """
    
    def __init__(self, app_id: str, private_key: str):
        """
        Initialize token manager.
        
        Args:
            app_id: GitHub App ID
            private_key: GitHub App private key PEM content
        """
        self.app_id = app_id
        # Keep key material in mutable bytes so it can be wiped on cleanup.
        self._private_key_bytes = bytearray(private_key.encode("utf-8"))
        self.tokens = {}
        self.token_expiries = {}

    def _get_private_key(self) -> str:
        """Build private key string from in-memory bytes."""
        return self._private_key_bytes.decode("utf-8")

    def _wipe_private_key(self):
        """Best-effort wipe of private key bytes held by this object."""
        if hasattr(self, "_private_key_bytes") and self._private_key_bytes:
            self._private_key_bytes[:] = b"\x00" * len(self._private_key_bytes)

    def close(self):
        """Release sensitive memory and token caches."""
        self._wipe_private_key()
        self.tokens.clear()
        self.token_expiries.clear()

    def __del__(self):
        self._wipe_private_key()

    def __getstate__(self):
        """Prevent serializing sensitive key bytes."""
        state = self.__dict__.copy()
        state["_private_key_bytes"] = None
        return state

    def _generate_jwt(self) -> str:
        """Generate a new JWT token.
        
        Returns:
            JWT token string
        
        Raises:
            RuntimeError: If JWT generation fails (bad key, encoding errors)
        """
        try:
            now_utc = datetime.now(timezone.utc)
            payload = {
                'iat': int(now_utc.timestamp()),
                'exp': int((now_utc + timedelta(minutes=10)).timestamp()),
                'iss': str(self.app_id)
            }
            jwt_token = jwt.encode(payload, self._get_private_key(), algorithm='RS256')
            return jwt_token.decode("utf-8") if isinstance(jwt_token, bytes) else jwt_token
        except ValueError as e:
            raise RuntimeError(f"JWT generation failed: private key is invalid: {e}") from e
        except Exception as e:
            raise RuntimeError(f"JWT generation failed: {e}") from e

    def get_access_token(self, installation_id: int) -> str:
        """
        Get access token for an installation, using cache if valid.
        
        Args:
            installation_id: GitHub App installation ID
        
        Returns:
            Access token string
        
        Raises:
            RuntimeError: If token retrieval fails (credentials invalid/revoked, network error)
        """
        key = str(installation_id)
        now_utc = datetime.now(timezone.utc)
        min_utc = datetime.min.replace(tzinfo=timezone.utc)
        
        # Return cached token if still valid
        if key in self.tokens and self.token_expiries.get(key, min_utc) > now_utc + timedelta(minutes=5):
            return self.tokens[key]
        
        try:
            jwt_token = self._generate_jwt()
                
            url = f"https://api.github.com/app/installations/{installation_id}/access_tokens"
            headers = {
                "Authorization": f"Bearer {jwt_token}", 
                "Accept": "application/vnd.github.v3+json"
            }
            response = _request_with_retries(
                "POST",
                url,
                headers=headers,
                timeout=(10, 30),
                retries=4,
                backoff_seconds=1.0,
            )
            response.raise_for_status()
            
            token_data = response.json()
            self.tokens[key] = token_data['token']
            self.token_expiries[key] = datetime.now(timezone.utc) + timedelta(hours=1)
            return self.tokens[key]
        except requests.exceptions.RequestException as e:
            raise RuntimeError(f"Failed to get access token for installation {installation_id} (credentials may be invalid or revoked): {e}") from e
        except Exception as e:
            raise RuntimeError(f"Unexpected error retrieving access token: {e}") from e


class RateLimiter:
    """
    Thread-safe rate limiter for GitHub API calls.
    
    Implements sliding window rate limiting to stay within
    GitHub API limits (5000/hour for PAT, 15000/hour for Apps).
    """
    
    def __init__(self, max_calls: int = 5000, period: int = 3600, thread_count: int = 5):
        """
        Initialize rate limiter.
        
        Args:
            max_calls: Maximum calls allowed per period
            period: Time period in seconds (default: 1 hour)
            thread_count: Number of concurrent threads
        """
        self.max_calls = max_calls
        self.period = period
        self.lock = threading.Lock()
        self.calls = []
        self.buffer_factor = 0.85
        self.max_safe_calls = int(self.max_calls * self.buffer_factor)

    def wait_for_request(self):
        """Wait until a request can be made within rate limits."""
        while True:
            with self.lock:
                now = time.time()
                self.calls = [t for t in self.calls if now - t < self.period]
                
                if len(self.calls) < self.max_safe_calls:
                    self.calls.append(now)
                    return
                
                oldest_call = self.calls[0]
                sleep_time = min(self.period - (now - oldest_call) + 0.1, 60)
            
            print(f"[RateLimiter] Sleeping {sleep_time:.2f}s ({len(self.calls)} active calls)")
            time.sleep(sleep_time)


def get_auth_from_user() -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """
    Interactively get authentication credentials from user.
    
    Returns:
        Tuple of (pat_token, app_id, private_key)
        - For PAT: (token, None, None)
        - For App: (None, app_id, private_key)
        - On error: (None, None, None)
    """
    print("\n" + "="*60)
    print("XIPHER CARAF SCANNER - AUTHENTICATION")
    print("="*60)
    print("\nSelect authentication method:")
    print("1. Personal Access Token (PAT)")
    print("2. GitHub App (App ID + Private Key)")
    
    choice = input("\nEnter choice (1 or 2): ").strip()
    
    if choice in ("1", "1.", "pat", "PAT"):
        pat_token = getpass("Enter GitHub PAT token: ").strip()
        if not pat_token:
            print("[ERROR] PAT token cannot be empty.")
            return None, None, None
        return pat_token, None, None
    
    elif choice in ("2", "2.", "app", "APP"):
        app_id = input("Enter GitHub App ID: ").strip()
        print("Enter path to private key PEM file (or paste key directly):")
        key_input = input().strip()
        
        cwd_path = os.path.realpath(os.getcwd())
        resolved_key = os.path.realpath(os.path.expanduser(key_input))

        if key_input and resolved_key.startswith(cwd_path + os.sep) and os.path.isfile(resolved_key):
            if not resolved_key.lower().endswith(".pem"):
                print("[ERROR] Private key file must have a .pem extension.")
                return None, None, None
            with open(resolved_key, 'r', encoding='utf-8') as f:
                private_key = f.read()
        else:
            print("Paste your private key (end with a blank line):")
            lines = []
            while True:
                line = input()
                if line == "":
                    break
                lines.append(line)
            private_key = "\n".join(lines)
        
        return None, app_id, private_key
    
    else:
        print(f"[ERROR] Invalid choice '{choice}'. Please enter 1 or 2.")
        return None, None, None


# Export all public symbols
__all__ = [
    'generate_jwt',
    'list_installations',
    'GitHubAuthManager',
    'GitHubTokenManager',
    'RateLimiter',
    'get_auth_from_user',
    'secure_request'
]

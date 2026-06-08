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
Xipher CARAF Scanner (Certificate Analysis and Risk Assessment Framework)
==========================================================================
A standalone certificate compliance scanner with modular checks:

  1. Expiry Check - Certificate expiration status
  2. Public Key (PQC) Check - Post-Quantum Cryptography key compliance
  3. Hash Algorithm (PQC) Check - PQC-compliant hash algorithms
  4. Issuer (CA) Check - Against compliant CA/ICA/Root cert list

Supports:
- Personal Access Token (PAT) authentication
- GitHub App Token (App ID + Private Key) authentication
- Selective checks with --skip-checks and --only-checks options
- Separate CSV and HTML output generators

Usage:
    python xipher_combined_scanner.py -o ORG [options]
    
For help:
    python xipher_combined_scanner.py --help
"""

# -------------------- Standard Library --------------------
import os
import io
import re
import time
import hashlib
import traceback
import zipfile
import argparse
from datetime import datetime, timezone
from typing import Tuple, List, Dict, Optional

# -------------------- Third-Party Libraries --------------------
import requests
import pandas as pd

# -------------------- Cryptography --------------------
from cryptography.hazmat.primitives.asymmetric import ec

# -------------------- Local Modules --------------------
from src.auth import (
    GitHubAuthManager,
    GitHubTokenManager,
    RateLimiter,
    generate_jwt,
    list_installations,
    get_auth_from_user
)
from src.tls_utils import secure_request
from src.generators import CSVGenerator, HTMLGenerator
from src.checkers import load_compliant_issuers
from src.utils import (
    RepoLimit,
    key_extractor,
    safe_parse_pem,
    get_key_size
)
from src.constants import CHECK_TYPES
from src.compliance_results import CombinedComplianceResult
from src.compliance_aggregated_check import check_combined_compliance


# ================================================================================
# COMBINED CERTIFICATE SCANNER
# ================================================================================
class CombinedCertScanner:
    """
    Combined Certificate Scanner with modular compliance checks.
    
    Supports:
    - PAT and GitHub App authentication
    - Selective compliance checks via enabled_checks parameter
    - CSV and HTML output generation
    """
    
    def __init__(
        self, 
        org: str,
        repo: Optional[List[str]] = None,
        pat_token: Optional[str] = None,
        app_id: Optional[str] = None,
        private_key: Optional[str] = None,
        thread_count: int = 1,
        out_dir: str = "./",
        enabled_checks: Optional[set] = None
    ):
        """
        Initialize the scanner.
        
        Args:
            org: GitHub organization name
            repo: List of specific repos to scan (None = all repos)
            pat_token: Personal Access Token for authentication
            app_id: GitHub App ID (alternative to PAT)
            private_key: GitHub App private key (required with app_id)
            thread_count: Number of parallel threads
            out_dir: Output directory for reports
            enabled_checks: Set of enabled checks ('expiry', 'public_key', 'hash', 'issuer')
                           If None, all checks are enabled.
        """
        self.org = org
        self.repo = repo
        self.pat_token = pat_token
        self.app_id = app_id
        self.private_key = private_key
        self.thread_count = thread_count
        cwd_path = os.path.realpath(os.getcwd())
        if out_dir in (".", "./"):
            self.out_dir = cwd_path
        elif os.path.isabs(out_dir):
            self.out_dir = os.path.realpath(out_dir)
        else:
            self.out_dir = os.path.realpath(os.path.join(cwd_path, out_dir))
        if self.out_dir != cwd_path and not self.out_dir.startswith(cwd_path + os.sep):
            raise ValueError("Output directory must resolve within current working directory")
        self.installation_id = None
        
        # Set enabled checks (default: all)
        self.enabled_checks = enabled_checks if enabled_checks else {'expiry', 'public_key', 'hash', 'issuer'}
        
        # Validate and setup output directory
        self._setup_output_dir()
        
        # Load compliant issuers
        self.compliant_issuers = load_compliant_issuers()
        
        # Skip issuer check if no compliant issuers loaded (empty CSV)
        if not self.compliant_issuers and 'issuer' in self.enabled_checks:
            self.enabled_checks = self.enabled_checks - {'issuer'}
            print(f"[INFO] Issuer check disabled (no compliant CAs in CSV)")
        
        # Validate auth
        if not org:
            raise ValueError("Organization (org) must be provided.")
        if not app_id and not pat_token:
            raise ValueError("Either app_id/private_key or pat_token must be provided.")
        
        # Setup authentication
        self.is_pat = pat_token is not None
        self._setup_auth()
    
    def _setup_output_dir(self):
        """Validate and setup output directory with read/write permissions."""
        # Create directory if it doesn't exist
        try:
            os.makedirs(self.out_dir, exist_ok=True)
        except OSError as e:
            raise ValueError(f"Cannot create output directory '{self.out_dir}': {e}")

        # Validate it's a directory
        if not os.path.isdir(self.out_dir):
            raise ValueError(f"Output path '{self.out_dir}' is not a directory")
        
        # Check read permission
        if not os.access(self.out_dir, os.R_OK):
            raise ValueError(f"No read permission for output directory '{self.out_dir}'")
        
        # Check write permission
        if not os.access(self.out_dir, os.W_OK):
            raise ValueError(f"No write permission for output directory '{self.out_dir}'")
        
        print(f"[INFO] Output directory: {os.path.abspath(self.out_dir)} (read/write OK)")
    
    def _setup_auth(self):
        """Configure authentication based on provided credentials."""
        if self.is_pat:
            self.token_manager = None
            self.rate_limiter = RateLimiter(max_calls=5000, period=3600, thread_count=self.thread_count)
            self.auth = GitHubAuthManager(pat_token=self.pat_token)
            self.auth_mode = 'pat'
            print("[INFO] Using PAT authentication (5000 req/hr limit)")
        else:
            self.token_manager = GitHubTokenManager(self.app_id, self.private_key)
            self.rate_limiter = RateLimiter(max_calls=15000, period=3600, thread_count=self.thread_count)
            
            jwt_token = generate_jwt(self.app_id, self.private_key)
            self.installation_id = list_installations(jwt_token, self.org)
            
            self.auth = GitHubAuthManager(
                app_id=self.app_id,
                private_key=self.private_key,
                token_manager=self.token_manager,
                installation_id=self.installation_id
            )
            self.auth_mode = 'app'
            print(f"[INFO] Using GitHub App authentication (15000 req/hr limit)")
    
    def _fetch_repo_zip(self, repo_name: str) -> Optional[zipfile.ZipFile]:
        """Fetch repository as ZIP archive."""
        try:
            self.rate_limiter.wait_for_request()
            headers = self.auth.get_headers()
            
            # Check repo exists and size
            repo_url = f"https://api.github.com/repos/{self.org}/{repo_name}"
            repo_info = secure_request("GET", repo_url, headers=headers, timeout=30)
            
            if repo_info.status_code == 404:
                print(f"[WARN] Repo {repo_name} not found")
                return None
            
            repo_info.raise_for_status()
            size_kb = repo_info.json().get("size", 0)
            
            if size_kb > 1_000_000:
                print(f"[SKIP] Repo {repo_name} too large ({size_kb / 1024:.1f} MB)")
                return None
            
            # Fetch ZIP
            self.rate_limiter.wait_for_request()
            zip_url = f"https://api.github.com/repos/{self.org}/{repo_name}/zipball"
            resp = secure_request("GET", zip_url, headers=headers, stream=True, timeout=(15, 30))
            resp.raise_for_status()
            
            buf = io.BytesIO()
            for chunk in resp.iter_content(chunk_size=1024 * 1024):
                if chunk:
                    buf.write(chunk)
            
            buf.seek(0)
            return zipfile.ZipFile(buf)
        except Exception as e:
            print(f"[ERROR] Failed to fetch {repo_name}: {e}")
            return None
    
    def _extract_files(self, z: zipfile.ZipFile) -> List[Tuple[str, str]]:
        """Extract text files from ZIP archive."""
        files = []
        seen = set()
        virtual_root = os.path.abspath(os.sep)
        
        for file_info in z.infolist():
            if file_info.is_dir():
                continue
            
            # Normalize separators, strip leading traversal, then enforce path bounds.
            raw_name = file_info.filename.replace("\\", "/")
            fname = os.path.normpath(raw_name).replace("\\", "/")
            while fname.startswith("../"):
                fname = fname[3:]
            fname = fname.lstrip("/")

            if not fname or fname in (".", ".."):
                continue

            resolved = os.path.abspath(os.path.join(virtual_root, fname))
            if os.path.commonpath([virtual_root, resolved]) != virtual_root:
                continue

            fname = os.path.relpath(resolved, virtual_root).replace("\\", "/")

            if fname in seen:
                continue
            seen.add(fname)
            
            _, ext = os.path.splitext(fname.lower())
            if ext in RepoLimit.skip_exts or file_info.file_size > RepoLimit.MAX_FILE_SIZE:
                continue
            
            try:
                raw_data = z.read(file_info)
                content = raw_data.decode('utf-8', errors='ignore')
                files.append((fname, content))
            except Exception:
                continue
        
        return files
    
    def _process_certificate(
        self,
        cert_pem: str,
        file_url: str,
        repo_name: str,
        cert_line_start: Optional[int] = None,
        cert_line_end: Optional[int] = None,
    ) -> Optional[Dict]:
        """Process a single certificate and return compliance results."""
        try:
            pem_data = cert_pem.encode("utf-8")
            cert = safe_parse_pem(pem_data, timeout=5)
            if not cert:
                return None
            
            # Extract certificate details
            issuer = str(cert.issuer)
            subject = str(cert.subject)
            public_key = cert.public_key()
            key_type = type(public_key).__name__
            key_size = get_key_size(public_key)
            
            curve = None
            if isinstance(public_key, ec.EllipticCurvePublicKey):
                curve = public_key.curve.name
            
            sig_hash = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else "unknown"
            
            # Calculate expiry using UTC datetime
            try:
                # Use UTC versions (newer cryptography library)
                not_valid_after = cert.not_valid_after_utc
                not_valid_before = cert.not_valid_before_utc
                now_utc = datetime.now(timezone.utc)
            except AttributeError:
                # Fallback for older cryptography library
                not_valid_after = cert.not_valid_after.replace(tzinfo=timezone.utc)
                not_valid_before = cert.not_valid_before.replace(tzinfo=timezone.utc)
                now_utc = datetime.now(timezone.utc)
            
            days_to_expire = (not_valid_after - now_utc).days
            is_expired = days_to_expire <= 0
            
            # Create reference ID
            reference_id = hashlib.sha256(
                (self.org + repo_name + file_url + cert_pem + issuer).encode()
            ).hexdigest()
            
            # Run combined compliance check with enabled checks
            result = check_combined_compliance(
                public_key=public_key,
                key_type=key_type,
                key_size=key_size,
                curve=curve,
                signature_hash=sig_hash,
                issuer=issuer,
                reference_id=reference_id,
                compliant_issuers=self.compliant_issuers,
                days_to_expire=days_to_expire,
                enabled_checks=self.enabled_checks
            )
            
            return {
                "reference_id": reference_id,
                "repo_name": repo_name,
                "file_url": file_url,
                "cert_line_start": cert_line_start,
                "cert_line_end": cert_line_end,
                "issuer": issuer,
                "subject": subject,
                "key_type": key_type,
                "key_size": key_size,
                "curve": curve,
                "signature_hash": sig_hash,
                "issue_date": str(not_valid_before),
                "expiry_date": str(not_valid_after),
                "days_to_expire": days_to_expire,
                "expired": is_expired,
                **result.to_dict()
            }
        except Exception as e:
            print(f"[ERROR] Certificate processing failed: {e}")
            return None
    
    def _fetch_org_repos(self) -> List[str]:
        """Fetch all repositories in the organization."""
        repos = []
        page = 1
        
        while True:
            self.rate_limiter.wait_for_request()
            headers = self.auth.get_headers()
            
            url = f"https://api.github.com/orgs/{self.org}/repos"
            response = secure_request(
                "GET",
                url,
                params={"per_page": 100, "page": page},
                headers=headers,
                timeout=30,
            )
            
            if response.status_code != 200:
                break
            
            data = response.json()
            if not data:
                break
            
            repos.extend([r["name"] for r in data])
            page += 1
        
        return repos
    
    def scan(self) -> pd.DataFrame:
        """Execute the scan and return combined compliance results."""
        start_time = time.time()
        all_results = []
        
        # Get repos to scan
        repos_to_scan = self.repo if self.repo else self._fetch_org_repos()
        print(f"[INFO] Scanning {len(repos_to_scan)} repositories in {self.org}")
        
        for repo_name in repos_to_scan:
            if isinstance(repo_name, dict):
                repo_name = repo_name.get('name', repo_name)
            
            print(f"[INFO] Processing: {repo_name}")
            
            z = self._fetch_repo_zip(repo_name)
            if not z:
                continue
            
            files = self._extract_files(z)
            print(f"[INFO] Found {len(files)} files in {repo_name}")
            
            for fname, content in files:
                certs = key_extractor(content)
                if not certs:
                    continue
                
                parts = fname.split("/")
                repo_path = "/".join(parts[1:]) if len(parts) > 1 else parts[0]
                commit_sha = parts[0].split("-")[-1] if parts else "main"
                file_url = f"https://github.com/{self.org}/{repo_name}/blob/{commit_sha}/{repo_path}"
                search_cursor = 0
                
                for cert_pem in certs:
                    cert_line_start = None
                    cert_line_end = None

                    cert_start_idx = content.find(cert_pem, search_cursor)
                    if cert_start_idx == -1:
                        cert_start_idx = content.find(cert_pem)

                    if cert_start_idx != -1:
                        cert_line_start = content.count("\n", 0, cert_start_idx) + 1
                        cert_line_end = cert_line_start + cert_pem.count("\n")
                        search_cursor = cert_start_idx + len(cert_pem)

                    cert_file_url = file_url
                    if cert_line_start is not None and cert_line_end is not None:
                        cert_file_url = f"{file_url}#L{cert_line_start}-L{cert_line_end}"

                    result = self._process_certificate(
                        cert_pem,
                        cert_file_url,
                        repo_name,
                        cert_line_start=cert_line_start,
                        cert_line_end=cert_line_end,
                    )
                    if result:
                        all_results.append(result)
        
        elapsed = time.time() - start_time
        print(f"\n[INFO] Scan completed in {elapsed:.2f}s")
        
        # Create results DataFrame
        df = pd.DataFrame(all_results)
        
        if df.empty:
            print("[INFO] No certificates found")
            return df
        
        # Print summary
        self._print_summary(df)
        
        # Save outputs
        self._save_outputs(df)
        
        return df
    
    def _print_summary(self, df: pd.DataFrame):
        """Print compliance summary."""
        print("\n" + "="*70)
        print("XIPHER CARAF - COMPLIANCE CHECK SUMMARY")
        print("="*70)
        
        # Show enabled checks
        print(f"Enabled Checks: {', '.join(sorted(self.enabled_checks))}")
        print("-" * 70)
        
        print(f"Total certificates scanned: {len(df)}")
        print(f"Fully compliant: {df['is_compliant'].sum()}")
        print(f"Non-compliant: {(~df['is_compliant']).sum()}")
        
        # Breakdown by check type (only show enabled checks)
        print("\n--- COMPLIANCE BREAKDOWN ---")
        if 'public_key' in self.enabled_checks:
            print(f"PQC Public Key Compliant: {df['public_key_compliant'].sum()}/{len(df)}")
        if 'hash' in self.enabled_checks:
            print(f"PQC Hash Compliant: {df['hash_compliant'].sum()}/{len(df)}")
        if 'issuer' in self.enabled_checks:
            print(f"CA Issuer Compliant: {df['issuer_compliant'].sum()}/{len(df)}")
        if 'expiry' in self.enabled_checks and 'expired' in df.columns:
            print(f"Expired Certificates: {df['expired'].sum()}/{len(df)}")
        print("="*70 + "\n")
    
    def _save_outputs(self, df: pd.DataFrame):
        """Save results to CSV and HTML using generator modules."""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        if df.empty:
            print("[INFO] No certificates to save.")
            return
        
        # Check if all compliant
        if df['is_compliant'].all():
            print("[INFO] All certificates are compliant. No non-compliant certificates to report.")
        
        # Spreadsheet output only: generate XLSX with separate sheets
        spreadsheet_gen = CSVGenerator(
            df=df,
            org=self.org,
            output_dir=self.out_dir,
            filter_mode='non_compliant',
            timestamp=timestamp
        )
        csv_workbook_file = spreadsheet_gen.generate_excel_with_sheets()
        
        # Use HTML Generator
        html_gen = HTMLGenerator(
            df=df,
            org=self.org,
            output_dir=self.out_dir,
            timestamp=timestamp
        )
        html_file = html_gen.generate()
        
        print(f"[OUTPUT] XLSX (Sheets: Non-Compliant, Compliant): {csv_workbook_file}")
        print(f"[OUTPUT] HTML: {html_file}")


# ================================================================================
# USER INPUT & MAIN
# ================================================================================


def main():
    """Main entry point with CLI argument support."""
    parser = argparse.ArgumentParser(
        description="Xipher CARAF Scanner - Certificate Analysis and Risk Assessment Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Available Compliance Checks:
  expiry      - Check if certificates are expired
  public_key  - Check PQC (Post-Quantum Crypto) key compliance
  hash        - Check PQC hash algorithm compliance  
  issuer      - Check if issuer CA is in compliant list

Examples:
  # Interactive mode (prompts for authentication)
  python xipher_combined_scanner.py -o my-org
  
  # With PAT token (set env var, never pass on CLI)
  export GITHUB_TOKEN=YOUR_TOKEN
  python xipher_combined_scanner.py -o my-org
  
  # With GitHub App (point to a key file)
  export XIPHER_APP_PRIVATE_KEY_FILE=/path/to/key.pem
  python xipher_combined_scanner.py -o my-org --app-id 12345

  # Or pass the key file path via CLI flag (path only, not secret content)
  python xipher_combined_scanner.py -o my-org --app-id 12345 --private-key-file /path/to/key.pem
  
  # Scan specific repos
  python xipher_combined_scanner.py -o my-org --repos repo1,repo2
  
  # Run only specific checks
  python xipher_combined_scanner.py -o my-org --only-checks expiry,public_key --pat YOUR_TOKEN
  
  # Skip certain checks
  python xipher_combined_scanner.py -o my-org --skip-checks issuer --pat YOUR_TOKEN
  
  # List available checks
  python xipher_combined_scanner.py --list-checks
  
  # Clean/delete all generated reports (with confirmation)
  python xipher_combined_scanner.py --clean-output
        """
    )
    
    parser.add_argument("-o", "--org", help="GitHub organization name (required unless --list-checks)")
    parser.add_argument("--repos", help="Comma-separated list of repos to scan (default: all)")
    # NOTE: --pat is intentionally absent. Pass the PAT via the GITHUB_TOKEN environment
    # variable to prevent secret exposure in shell history and process listings (ps aux).
    parser.add_argument("--app-id", help="GitHub App ID")
    parser.add_argument(
        "--private-key-file",
        help="Path to GitHub App private key PEM file. "
             "Alternatively, set XIPHER_APP_PRIVATE_KEY_FILE env var. "
             "For inline PEM, set XIPHER_PRIVATE_KEY env var."
    )
    parser.add_argument("--threads", type=int, default=1, help="Number of threads (default: 1)")
    parser.add_argument("--output-dir", default="./", help="Base output directory. Reports saved to <dir>/output/csv/ and <dir>/output/html/ (default: ./)")
    parser.add_argument("--interactive", "-i", action="store_true", help="Force interactive auth input")
    
    # Check selection arguments
    parser.add_argument(
        "--only-checks", 
        help="Comma-separated list of checks to run (others will be skipped). "
             "Options: expiry, public_key, hash, issuer"
    )
    parser.add_argument(
        "--skip-checks",
        help="Comma-separated list of checks to skip. "
             "Options: expiry, public_key, hash, issuer"
    )
    parser.add_argument(
        "--list-checks",
        action="store_true",
        help="List all available compliance checks and exit"
    )
    parser.add_argument(
        "--clean-output",
        action="store_true",
        help="Remove all files and folders in the output directory (with confirmation)"
    )
    
    args = parser.parse_args()
    
    # Handle --list-checks
    if args.list_checks:
        print("\nAvailable Compliance Checks:")
        print("-" * 50)
        for check_name, check_desc in CHECK_TYPES.items():
            print(f"  {check_name:12} - {check_desc}")
        print("\nUsage Examples:")
        print("  --only-checks expiry,hash     # Run only expiry and hash checks")
        print("  --skip-checks issuer          # Run all checks except issuer")
        print()
        return 0
    
    # Handle --clean-output
    if args.clean_output:
        # Security hardening: clean operation is restricted to local ./output only.
        # This prevents user-supplied CLI paths from flowing into filesystem delete/read sinks.
        if args.output_dir not in ("./", "."):
            print("[WARN] --output-dir is ignored with --clean-output for security reasons.")
        resolved_base = os.path.realpath(os.path.abspath('.'))

        # Build the target path from the sanitised base + a hardcoded constant.
        # 'output' is NOT derived from user input, which breaks the taint chain.
        resolved_output = os.path.join(resolved_base, 'output')

        # Stat-based verification: resolve symlinks and verify the directory path
        try:
            resolved_output_real = os.path.realpath(resolved_output)
        except (OSError, ValueError) as e:
            print(f"[ERROR] Failed to resolve output path: {e}")
            return 1

        # Defense-in-depth: confirm the result is still inside the base
        if not resolved_output_real.startswith(resolved_base + os.sep):
            print(f"[ERROR] Resolved output path '{resolved_output_real}' is outside "
                  f"the base directory '{resolved_base}'. Aborting.")
            return 1

        # Additional safeguard: prevent deletion of common system directories
        dangerous_components = {'', 'etc', 'var', 'usr', 'bin', 'sbin', 'dev', 'proc', 'sys', 'root', 'home', 'tmp'}
        path_components = resolved_output_real.split(os.sep)
        if any(comp in dangerous_components for comp in path_components):
            print(f"[ERROR] Output path contains suspicious components: {resolved_output_real}. Aborting.")
            return 1

        if not os.path.exists(resolved_output):
            print(f"[INFO] Output folder does not exist: {resolved_output}")
            return 0

        if not os.path.isdir(resolved_output):
            print(f"[ERROR] Output path exists but is not a directory: {resolved_output}. Aborting.")
            return 1

        def _count_tree(root_rel: str) -> Tuple[int, int]:
            total_files_local = 0
            total_dirs_local = 0
            stack = [root_rel]

            while stack:
                current = stack.pop()
                with os.scandir(current) as entries:
                    for entry in entries:
                        if entry.is_dir(follow_symlinks=False):
                            total_dirs_local += 1
                            stack.append(entry.path)
                        else:
                            total_files_local += 1

            return total_files_local, total_dirs_local

        def _delete_tree(root_rel: str):
            stack = [root_rel]
            dirs_to_remove = []

            while stack:
                current = stack.pop()
                dirs_to_remove.append(current)
                with os.scandir(current) as entries:
                    for entry in entries:
                        if entry.is_dir(follow_symlinks=False):
                            stack.append(entry.path)
                        else:
                            os.unlink(entry.path)

            for directory in reversed(dirs_to_remove):
                os.rmdir(directory)

        # Count items using a constant relative path anchored to validated base.
        total_files = 0
        total_dirs = 0
        base_fd = os.open(resolved_base, os.O_RDONLY)
        try:
            current_dir_fd = os.open('.', os.O_RDONLY)
            try:
                os.fchdir(base_fd)
                total_files, total_dirs = _count_tree('output')
            finally:
                os.fchdir(current_dir_fd)
                os.close(current_dir_fd)
        finally:
            os.close(base_fd)
        
        print(f"\n{'='*60}")
        print("WARNING: This will permanently delete all report files!")
        print(f"{'='*60}")
        print(f"Output folder: {resolved_output}")
        print(f"Files to delete: {total_files}")
        print(f"Folders to delete: {total_dirs}")
        print(f"{'='*60}\n")
        
        confirm = input("Are you sure you want to delete all reports? (yes/Y to confirm): ").strip()
        
        if confirm.lower() in ('yes', 'y'):
            try:
                # Delete using constant relative paths anchored to validated base.
                base_fd = os.open(resolved_base, os.O_RDONLY)
                current_dir_fd = os.open('.', os.O_RDONLY)
                try:
                    os.fchdir(base_fd)
                    _delete_tree('output')
                finally:
                    os.fchdir(current_dir_fd)
                    os.close(current_dir_fd)
                    os.close(base_fd)
                print(f"\n[SUCCESS] Deleted all contents in: {resolved_output}")
                return 0
            except Exception as e:
                print(f"[ERROR] Failed to delete output folder: {e}")
                return 1
        else:
            print("\n[CANCELLED] No files were deleted.")
            return 0
    
    # Require org if not listing checks
    if not args.org:
        parser.error("the following arguments are required: -o/--org")
    
    # Determine enabled checks
    all_checks = set(CHECK_TYPES.keys())
    
    if args.only_checks:
        enabled_checks = set(c.strip().lower() for c in args.only_checks.split(","))
        invalid = enabled_checks - all_checks
        if invalid:
            parser.error(f"Invalid check types: {', '.join(invalid)}. Valid options: {', '.join(all_checks)}")
    elif args.skip_checks:
        skip_checks = set(c.strip().lower() for c in args.skip_checks.split(","))
        invalid = skip_checks - all_checks
        if invalid:
            parser.error(f"Invalid check types: {', '.join(invalid)}. Valid options: {', '.join(all_checks)}")
        enabled_checks = all_checks - skip_checks
    else:
        enabled_checks = all_checks
    
    print(f"[INFO] Enabled checks: {', '.join(sorted(enabled_checks))}")
    
    # Handle authentication
    # PAT is read exclusively from GITHUB_TOKEN to prevent shell-history / ps-aux exposure.
    pat_token = os.environ.get("GITHUB_TOKEN", "").strip() or None
    app_id = args.app_id
    private_key = None

    if app_id:
        # Resolve private key: CLI file path > env file path > env inline PEM.
        key_file_path = getattr(args, "private_key_file", None)
        env_key_file = os.environ.get("XIPHER_APP_PRIVATE_KEY_FILE", "").strip() or None
        chosen_key_file = key_file_path or env_key_file

        if chosen_key_file:
            # Accept a PEM path (relative or absolute) but keep reads constrained to CWD.
            cwd_path = os.path.realpath(os.getcwd())
            raw_key_path = os.path.expanduser(chosen_key_file).strip()
            if not raw_key_path:
                parser.error("Private key file path cannot be empty")

            if os.path.isabs(raw_key_path):
                resolved_key = os.path.realpath(raw_key_path)
            else:
                resolved_key = os.path.realpath(os.path.join(cwd_path, raw_key_path))

            # Keep key reads within CWD for safety.
            if os.path.commonpath([cwd_path, resolved_key]) != cwd_path:
                parser.error("Resolved private key path is outside current working directory")
            if re.fullmatch(r"[A-Za-z0-9._/\-]+\.pem", os.path.relpath(resolved_key, cwd_path).replace("\\", "/")) is None:
                parser.error("Private key path must end with .pem and contain only letters/numbers/._-/")
            if not os.path.isfile(resolved_key):
                parser.error(f"Private key file not found: {resolved_key}")
            with open(resolved_key, "r", encoding="utf-8") as _kf:
                private_key = _kf.read()
            if "BEGIN" not in private_key:
                parser.error("Private key file does not appear to contain a PEM-encoded key")
        else:
            # Fall back to inline PEM from environment (never from --private-key CLI arg).
            env_inline = os.environ.get("XIPHER_PRIVATE_KEY", "").strip() or None
            if env_inline and "BEGIN" in env_inline:
                private_key = env_inline

    # If no auth provided or interactive mode, prompt user
    if args.interactive or (not pat_token and not app_id):
        pat_token, app_id, private_key = get_auth_from_user()
        
        if not pat_token and not app_id:
            print("[ERROR] No valid authentication provided. Exiting.")
            return 1
    
    # Parse repos
    repos = None
    if args.repos:
        repos = [r.strip() for r in args.repos.split(",")]
    
    # Create scanner and run
    try:
        scanner = CombinedCertScanner(
            org=args.org,
            repo=repos,
            pat_token=pat_token,
            app_id=app_id,
            private_key=private_key,
            thread_count=args.threads,
            out_dir=args.output_dir,
            enabled_checks=enabled_checks
        )
        
        results_df = scanner.scan()
        
        # Return non-compliant count for scripting
        if not results_df.empty:
            non_compliant_count = (~results_df['is_compliant']).sum()
            return non_compliant_count
        return 0
        
    except Exception as e:
        print(f"[ERROR] Scanner failed: {e}")
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    result = main()
    exit(result if result is not None else 0)

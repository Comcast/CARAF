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
Security-focused tests for xIPHER Certificate Scanner components.

Covers:
- Zip-slip (path traversal) rejection in archive extraction.
- Output directory validation to prevent writes outside the working directory.
- Token caching and thread-safety guarantees in GitHubTokenManager.
- CSV injection sanitisation across all string columns in CSVGenerator.
- Issuer compliance check resistance to substring-bypass attacks.
- Graceful handling of malformed PEM data in key_extractor.
"""

import io
import zipfile
from datetime import datetime, timedelta, timezone

import pandas as pd
import pytest

from src.auth import GitHubTokenManager
from src.checkers.issuer_checker import check_issuer_compliance
from src.generators.csv_generator import CSVGenerator
from src.utils import key_extractor
from xipher_combined_scanner import CombinedCertScanner


def test_extract_files_rejects_zip_traversal_entries():
    scanner = CombinedCertScanner(org="sample-org", pat_token="token", out_dir=".")

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("repo/certs/valid.pem", "certificate")
        zf.writestr("../../escape.pem", "evil")
        zf.writestr("repo/../../escape2.pem", "evil")

    buf.seek(0)
    with zipfile.ZipFile(buf, mode="r") as zf:
        extracted = scanner._extract_files(zf)

    names = [name for name, _content in extracted]
    assert "repo/certs/valid.pem" in names
    assert "escape.pem" not in names
    assert "escape2.pem" not in names
    assert all(".." not in name for name in names)


def test_combined_scanner_rejects_output_path_outside_cwd():
    with pytest.raises(ValueError):
        CombinedCertScanner(org="sample-org", pat_token="token", out_dir="../outside")


def test_token_manager_uses_cached_token_and_has_lock():
    manager = GitHubTokenManager(app_id="123", private_key="dummy")
    manager.tokens["999"] = "cached-token"
    manager.token_expiries["999"] = datetime.now(timezone.utc) + timedelta(minutes=30)

    def _should_not_generate_jwt():
        raise AssertionError("JWT generation should not be called when cache is valid")

    manager._generate_jwt = _should_not_generate_jwt  # type: ignore[method-assign]

    assert hasattr(manager, "_lock")
    assert manager.get_access_token(999) == "cached-token"


def test_csv_injection_sanitization_applies_to_all_string_columns():
    generator = CSVGenerator(df=pd.DataFrame(), org="sample-org", output_dir=".")
    df = pd.DataFrame(
        {
            "Repo Name": ["=2+5"],
            "File URL": ["@danger"],
            "Key Type": ["-rsa"],
            "Issuer": ["+issuer"],
            "Key Size": [2048],
            "Safe": ["normal"],
        }
    )

    sanitized = generator._sanitize_csv_injection(df)

    assert sanitized.loc[0, "Repo Name"].startswith("'")
    assert sanitized.loc[0, "File URL"].startswith("'")
    assert sanitized.loc[0, "Key Type"].startswith("'")
    assert sanitized.loc[0, "Issuer"].startswith("'")
    assert sanitized.loc[0, "Safe"] == "normal"


def test_issuer_checker_does_not_allow_substring_bypass():
    compliant = ["trusted root ca"]

    is_ok, _msg = check_issuer_compliance("CN=Attacker Trusted Root CA Ltd, O=Evil Corp", compliant)
    assert is_ok is False

    is_ok_exact, _msg2 = check_issuer_compliance("CN=Trusted Root CA, O=Example Corp", compliant)
    assert is_ok_exact is True


def test_key_extractor_handles_malformed_pem_without_crash():
    malformed = "-----BEGIN CERTIFICATE-----\nMALFORMED_DATA_ONLY\n"
    certs = key_extractor(malformed)

    assert isinstance(certs, list)
    assert certs == []

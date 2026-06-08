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
Issuer CA Compliance Checker
============================
Checks if certificate issuers are in the compliant CA list.

The compliant issuers are loaded from a CSV file containing
approved Certificate Authorities (CAs), Intermediate CAs (ICAs),
and Root certificates.

Usage:
    from src.checkers import load_compliant_issuers, check_issuer_compliance
    
    # Load compliant issuers from CSV
    issuers = load_compliant_issuers("path/to/compliant_cas.csv")
    
    # Check if issuer is compliant
    is_compliant, message = check_issuer_compliance(cert_issuer, issuers)
"""

import os
import re
from typing import List, Tuple


# Default CSV file name
DEFAULT_CSV_FILE = "Compliant_Certificates_Combined.csv"


def load_compliant_issuers(csv_path: str = None) -> List[str]:
    """
    Load compliant issuers from the combined CSV file.
    
    The CSV file should have a "Title" column containing CA names.
    Names are normalized to lowercase for case-insensitive matching.
    
    Args:
        csv_path: Path to the CSV file. If None, looks in the project root.
    
    Returns:
        List of issuer names (lowercase) for compliance checking.
        Returns empty list if file not found or on error.
    
    Example CSV format:
        Title
        DigiCert Global Root CA
        GlobalSign Root CA
        Let's Encrypt Authority X3
    """
    if csv_path is None:
        # Look in project root (parent of src/)
        project_root = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
        csv_path = os.path.join(project_root, DEFAULT_CSV_FILE)
    
    try:
        # Read as single column to handle entries with commas (e.g., "XFN Matter OP, 1.3.6...")
        with open(csv_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        
        # Skip header, strip whitespace, lowercase, remove empty lines
        issuers = [line.strip().lower() for line in lines[1:] if line.strip()]
        issuers = list(set(issuers))
        issuers.sort()
        
        if len(issuers) == 0:
            print(f"[WARNING] Compliant CA CSV is empty (header only): {csv_path}")
            print(f"[INFO] Issuer compliance check will be skipped.")
        else:
            print(f"[INFO] Loaded {len(issuers)} compliant issuers from {csv_path}")
        return issuers
        
    except FileNotFoundError:
        print(f"[WARNING] Combined CSV not found at {csv_path}. Using empty issuer list.")
        return []
    except Exception as e:
        print(f"[ERROR] Failed to load issuers: {e}")
        return []


def check_issuer_compliance(issuer: str, compliant_issuers: List[str]) -> Tuple[bool, str]:
    """
    Check if the certificate issuer is in the compliant issuers list.

    Performs strict matching against parsed issuer attributes (CN/O/OU)
    and exact full-DN equality. This prevents substring-bypass issues.
    
    Args:
        issuer: Certificate issuer string (from cert.issuer)
        compliant_issuers: List of compliant issuer names (lowercase)
    
    Returns:
        Tuple of (is_compliant: bool, message: str)
    
    Examples:
        >>> issuers = ["digicert", "globalsign"]
        >>> check_issuer_compliance("CN=DigiCert Global Root CA", issuers)
        (True, "CA is in compliant CA list")
        
        >>> check_issuer_compliance("CN=Unknown CA", issuers)
        (False, "Issuer not in Compliant CA CSV list")
    """
    if not issuer or not isinstance(issuer, str):
        return (False, "Invalid issuer - Issuer not in Compliant CA CSV list")
    
    compliant_set = {_normalize_issuer_text(v) for v in compliant_issuers if v}
    if not compliant_set:
        return (False, "Issuer not in Compliant CA CSV list")

    issuer_values = _extract_issuer_values(issuer)
    issuer_dn_normalized = _normalize_issuer_text(issuer)

    # Exact full-DN match if the CSV contains full DN values.
    if issuer_dn_normalized in compliant_set:
        return (True, "CA is in compliant CA list")

    # Exact attribute-value match (CN/O/OU), no substring acceptance.
    for value in issuer_values:
        if value in compliant_set:
            return (True, "CA is in compliant CA list")
    
    return (False, "Issuer not in Compliant CA CSV list")


def _normalize_issuer_text(value: str) -> str:
    """Normalize issuer text for stable exact matching."""
    text = value.strip().lower()
    text = re.sub(r"\s+", " ", text)
    return text


def _extract_issuer_values(issuer: str) -> List[str]:
    """
    Parse issuer DN string and extract CN/O/OU values for exact comparison.

    Supports common formats such as:
      - "CN=Example CA, O=Example Corp"
      - "<Name(CN=Example CA,O=Example Corp)>"
    """
    cleaned = issuer.strip()
    if cleaned.startswith("<Name(") and cleaned.endswith(")>"):
        cleaned = cleaned[6:-2]

    # Split on commas not escaped by backslash.
    parts = re.split(r"(?<!\\),", cleaned)
    values = []

    for part in parts:
        segment = part.strip()
        if "=" not in segment:
            continue
        key, raw_value = segment.split("=", 1)
        key = key.strip().upper()
        if key not in {"CN", "O", "OU", "COMMONNAME", "ORGANIZATIONNAME", "ORGANIZATIONALUNITNAME"}:
            continue

        normalized = _normalize_issuer_text(raw_value.replace("\\,", ","))
        if normalized:
            values.append(normalized)

    return values


# Export
__all__ = ['load_compliant_issuers', 'check_issuer_compliance', 'DEFAULT_CSV_FILE']

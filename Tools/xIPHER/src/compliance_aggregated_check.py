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
Aggregated Compliance Checker for Xipher CARAF Scanner.

This module provides the check_combined_compliance function that aggregates
results from all individual compliance checkers (public key, hash, issuer, expiry).
"""

from typing import List

from .checkers import (
    check_public_key_compliance,
    check_hash_compliance,
    check_issuer_compliance
)
from .compliance_results import CombinedComplianceResult


def check_combined_compliance(
    public_key,
    key_type: str, 
    key_size: int, 
    curve: str, 
    signature_hash: str, 
    issuer: str, 
    reference_id: str,
    compliant_issuers: List[str],
    days_to_expire: int = None,
    parent_compliant: bool = True,
    enabled_checks: set = None
) -> CombinedComplianceResult:
    """
    Perform compliance checks and combine results.
    
    Args:
        public_key: Parsed cryptography public key object
        key_type: Public key type
        key_size: Key size in bits
        curve: ECC curve name (if applicable)
        signature_hash: Hash algorithm name
        issuer: Certificate issuer
        reference_id: Unique reference ID
        compliant_issuers: List of compliant issuer names
        days_to_expire: Days until certificate expires
        parent_compliant: Whether parent cert is compliant
        enabled_checks: Set of enabled check types. If None, all checks are enabled.
                       Options: 'expiry', 'public_key', 'hash', 'issuer'
    """
    result = CombinedComplianceResult(reference_id)
    
    # Default to all checks if not specified
    if enabled_checks is None:
        enabled_checks = {'expiry', 'public_key', 'hash', 'issuer'}
    
    # Check 1: Expiry Check
    if 'expiry' in enabled_checks:
        if days_to_expire is not None and days_to_expire <= 0:
            result.is_expired = True
            result.expiry_message = f"Certificate is expired (expired {abs(days_to_expire)} days ago)"
            result.add_non_compliance("EXPIRY", result.expiry_message)
        elif days_to_expire is not None and days_to_expire <= 30:
            result.expiry_message = f"Certificate expiring soon ({days_to_expire} days remaining)"
    
    # Check 2: Public Key Compliance
    if 'public_key' in enabled_checks:
        result.public_key_compliant, result.public_key_message = check_public_key_compliance(
            public_key, key_type, key_size, curve
        )
        if not result.public_key_compliant:
            result.add_non_compliance("PUBLIC_KEY", result.public_key_message)
    
    # Check 3: Hash Algorithm Compliance
    if 'hash' in enabled_checks:
        result.hash_compliant, result.hash_message = check_hash_compliance(signature_hash)
        if not result.hash_compliant:
            result.add_non_compliance("HASH", result.hash_message)
    
    # Check 4: Issuer Compliance
    if 'issuer' in enabled_checks:
        result.issuer_compliant, result.issuer_message = check_issuer_compliance(
            issuer, compliant_issuers
        )
        if not result.issuer_compliant:
            result.add_non_compliance("ISSUER", result.issuer_message)
    
    # Check 5: Ancestor Compliance
    result.ancestor_compliant = parent_compliant
    if not parent_compliant:
        result.ancestor_message = "Parent/ancestor certificate is non-compliant"
        result.add_non_compliance("ANCESTOR", result.ancestor_message)
    
    return result

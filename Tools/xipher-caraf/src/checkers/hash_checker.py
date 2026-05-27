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
Hash Algorithm Compliance Checker
=================================
Checks if certificate hash algorithms are compliant with PQC
(Post-Quantum Cryptography) security standards.

Compliant Algorithms:
- SHA-256, SHA-384, SHA-512
- SHA3-256

Non-Compliant:
- SHA-1, MD5, and other weak hash algorithms

Usage:
    from src.checkers import check_hash_compliance
    
    is_compliant, message = check_hash_compliance("sha256")
"""

from typing import Tuple


# PQC-compliant hash algorithms
COMPLIANT_HASH_ALGORITHMS = {
    "sha256",
    "sha384", 
    "sha512",
    "sha3-256",
    "sha3_256"
}

# Known weak/deprecated hash algorithms
WEAK_HASH_ALGORITHMS = {
    "sha1",
    "sha-1",
    "md5",
    "md4",
    "md2"
}


def check_hash_compliance(signature_hash: str) -> Tuple[bool, str]:
    """
    Check if the hash algorithm is compliant with PQC security standards.
    
    Args:
        signature_hash: Hash algorithm name (e.g., "sha256", "sha1")
    
    Returns:
        Tuple of (is_compliant: bool, message: str)
    
    Examples:
        >>> check_hash_compliance("sha256")
        (True, "sha256 is PQC compliant")
        
        >>> check_hash_compliance("sha1")
        (False, "SHA1 is deprecated - weak hash algorithm")
        
        >>> check_hash_compliance("md5")
        (False, "md5 is deprecated")
    """
    if not isinstance(signature_hash, str):
        return (False, "Invalid hash algorithm")
    
    signature_hash_lower = signature_hash.lower()
    
    if signature_hash_lower == "" or signature_hash_lower == "null":
        return (False, "Invalid hash algorithm")
    
    # Check against compliant algorithms
    if signature_hash_lower in COMPLIANT_HASH_ALGORITHMS:
        return (True, f"{signature_hash} is PQC compliant")
    
    # Specific message for SHA1 (common case)
    if signature_hash_lower in ("sha1", "sha-1"):
        return (False, f"{signature_hash.upper()} is deprecated - weak hash algorithm")
    
    # Check other weak algorithms
    if signature_hash_lower in WEAK_HASH_ALGORITHMS:
        return (False, f"{signature_hash.upper()} is deprecated - weak hash algorithm")
    
    return (False, f"{signature_hash} is deprecated")


# Export
__all__ = ['check_hash_compliance', 'COMPLIANT_HASH_ALGORITHMS', 'WEAK_HASH_ALGORITHMS']

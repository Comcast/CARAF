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
Public Key Compliance Checker
=============================
Checks if certificate public keys are compliant with PQC 
(Post-Quantum Cryptography) security standards.

Compliance Requirements:
- RSA: Key size >= 2048 bits
- DSA: Key size >= 2048 bits  
- ECC: NIST curves (secp256r1, secp384r1, secp521r1) or Brainpool curves
- Edwards curves: Ed25519, Ed448 (inherently compliant)
- Montgomery curves: X25519, X448 (inherently compliant)

Usage:
    from src.checkers import check_public_key_compliance
    
    is_compliant, message = check_public_key_compliance(
        key_type="_RSAPublicKey",
        key_size=2048,
        curve=None
    )
"""

from typing import Tuple

from cryptography.hazmat.primitives.asymmetric import (
    rsa, dsa, ec, ed25519, x25519, x448, ed448, dh
)


# Key type constants (matching cryptography library naming)
KEY_TYPE_CONSTANTS = {
    'RSA': "_RSAPublicKey",
    'DSA': "_DSAPublicKey",
    'ECC': "_EllipticCurvePublicKey",
    'ED25519': "_Ed25519PublicKey",
    'ED448': "_Ed448PublicKey",
    'X25519': "_X25519PublicKey",
    'X448': "_X448PublicKey",
    'DH': "_DHPrivateKey"
}

# Compliant ECC curves
COMPLIANT_ECC_CURVES = [
    "secp256r1",
    "secp384r1", 
    "secp521r1",
    "brainpoolP384",
    "brainpoolP512"
]

# Minimum key sizes for RSA/DSA/DH
MIN_KEY_SIZE = 2048


def check_public_key_compliance(public_key, key_type: str, key_size: int, curve: str) -> Tuple[bool, str]:
    """
    Check if a public key is compliant with PQC security standards.
    
    Args:
        public_key: Parsed cryptography public key object
        key_type: Public key type string (used for reporting/fallback)
        key_size: Key size in bits
        curve: ECC curve name (only applicable for ECC keys)
    
    Returns:
        Tuple of (is_compliant: bool, message: str)
    
    Examples:
        >>> check_public_key_compliance("_RSAPublicKey", 2048, None)
        (True, "RSA 2048-bit is PQC compliant")
        
        >>> check_public_key_compliance("_RSAPublicKey", 1024, None)
        (False, "RSA 1024-bit is deprecated (minimum 2048-bit required)")
        
        >>> check_public_key_compliance("_EllipticCurvePublicKey", 256, "secp256r1")
        (True, "ECC curve secp256r1 is PQC compliant")
    """
    if public_key is None:
        return (False, "Invalid public key object - deprecated")

    if key_type is None or key_type == "" or key_type == "null":
        return (False, "Invalid public key type - deprecated")

    try:
        # RSA validation
        if isinstance(public_key, rsa.RSAPublicKey):
            if key_size >= MIN_KEY_SIZE:
                return (True, f"RSA {key_size}-bit is PQC compliant")
            return (False, f"RSA {key_size}-bit is deprecated (minimum {MIN_KEY_SIZE}-bit required)")
            
        # DSA validation
        elif isinstance(public_key, dsa.DSAPublicKey):
            if key_size >= MIN_KEY_SIZE:
                return (True, f"DSA {key_size}-bit is PQC compliant")
            return (False, f"DSA {key_size}-bit is deprecated (minimum {MIN_KEY_SIZE}-bit required)")
        
        # ECDSA validation
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            if curve in COMPLIANT_ECC_CURVES:
                return (True, f"ECC curve {curve} is PQC compliant")
            return (False, f"ECC curve {curve} is deprecated")
        
        # DH validation
        elif isinstance(public_key, dh.DHPublicKey):
            if key_size >= MIN_KEY_SIZE:
                return (True, f"DH {key_size}-bit is PQC compliant")
            return (False, f"DH {key_size}-bit is deprecated (minimum {MIN_KEY_SIZE}-bit required)")
            
        # Edwards and Montgomery curves - inherently compliant
        elif isinstance(public_key, ed25519.Ed25519PublicKey):
            return (True, "Ed25519 public key is PQC compliant")
        elif isinstance(public_key, ed448.Ed448PublicKey):
            return (True, "Ed448 public key is PQC compliant")
        elif isinstance(public_key, x25519.X25519PublicKey):
            return (True, "X25519 public key is PQC compliant")
        elif isinstance(public_key, x448.X448PublicKey):
            return (True, "X448 public key is PQC compliant")
        
        return (False, "Unsupported public key type - deprecated")
            
    except Exception as e:
        return (False, f"Error validating key: {str(e)}")


# Export
__all__ = ['check_public_key_compliance', 'KEY_TYPE_CONSTANTS', 'COMPLIANT_ECC_CURVES', 'MIN_KEY_SIZE']

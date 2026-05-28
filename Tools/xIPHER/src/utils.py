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
Utilities Module
================
Common utility functions for certificate parsing and extraction.

Functions:
    - key_extractor: Extract PEM certificates from text
    - safe_parse_pem: Safely parse PEM certificate data
    - get_key_size: Get key size from public key object
    - serialize_public_key: Serialize public key to PEM string

Classes:
    - RepoLimit: Constants for repository scanning limits
"""

import re
import logging
from typing import List, Optional

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, x25519, x448, ed448


logger = logging.getLogger(__name__)


# ================================================================================
# REPO SCANNING LIMITS
# ================================================================================
class RepoLimit:
    """Constants for repository scanning limits."""
    MAX_FILE_SIZE = 2 * 1024 * 1024  # 2 MB
    MAX_LINES = 70000
    MAX_CHARS = 5_000_000
    MAX_LINE_LENGTH = 100_000
    READ_TIMEOUT = 5
    
    # File extensions to skip during scanning
    skip_exts = {
        ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".class", ".jar",
        ".zip", ".tar", ".gz", ".7z", ".exe", ".bin", ".pdf", ".xlsx",
        ".xls", ".pptx", ".mp4", ".mp3", ".mov", ".woff", ".woff2", ".ttf",
        ".otf", ".dll", ".so", ".obj", ".pdb", ".dat", ".out",
        ".lock", ".bak", ".iso", ".rar", ".bz2", ".war"
    }


# ================================================================================
# CERTIFICATE EXTRACTION
# ================================================================================
def key_extractor(response_text: str) -> List[str]:
    """
    Extract PEM certificates from text.
    
    Args:
        response_text: Text content that may contain PEM certificates
        
    Returns:
        List of unique PEM certificate strings found in the text
    """
    regexes = {
        "PEM CERT": "-----BEGIN CERTIFICATE-----(?:[\nA-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=\n-----END CERTIFICATE-----)",
        "PEM CERT 2": "-----BEGIN CERTIFICATE-----(?:[\nA-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}\n-----END CERTIFICATE-----)",
        "PEM CERT 3": "(?<=-----BEGIN CERTIFICATE-----).*?(?=-----END CERTIFICATE-----)",
        "PEM CERT 4": "-----BEGIN CERTIFICATE-----(?:[\nA-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}==\n-----END CERTIFICATE-----)",
        "PEM CERT 5": r"(-*\s*BEGIN CERTIFICATE+-*\s*[\r\n]*[\s\S]+?[\r\n]*\s*-*\s*END CERTIFICATE+-*)",
    }
    
    output = []
    for key, pattern in regexes.items():
        matches = re.findall(pattern, response_text, flags=re.DOTALL)
        if key == "PEM CERT 3":
            matches = ["-----BEGIN CERTIFICATE-----" + m + "-----END CERTIFICATE-----" for m in matches]
        output.extend(matches)
    
    return list(set([x for x in output if x]))


# ================================================================================
# CERTIFICATE PARSING
# ================================================================================
def safe_parse_pem(pem_data: bytes, timeout: int = 5):
    """
    Safely parse PEM certificate data.
    
    Args:
        pem_data: PEM-encoded certificate bytes
        timeout: Parsing timeout in seconds (currently unused, for future use)
        
    Returns:
        Parsed x509 certificate object, or None if parsing fails
    """
    try:
        cert = x509.load_pem_x509_certificate(pem_data, default_backend())
        return cert
    except Exception:
        # Keep parse failures silent by default; debug details only via logging configuration.
        logger.debug("PEM parse failed")
        return None


def get_key_size(public_key_obj) -> Optional[int]:
    """
    Get key size from public key object.
    
    Args:
        public_key_obj: Public key object from certificate
        
    Returns:
        Key size in bits, or None if not determinable
    """
    if isinstance(public_key_obj, (ed25519.Ed25519PublicKey, x25519.X25519PublicKey)):
        return 256
    if isinstance(public_key_obj, (ed448.Ed448PublicKey, x448.X448PublicKey)):
        return 448
    return getattr(public_key_obj, "key_size", None)


def serialize_public_key(public_key) -> Optional[str]:
    """
    Serialize public key to PEM string.
    
    Args:
        public_key: Public key object to serialize
        
    Returns:
        PEM-encoded public key string, or None if serialization fails
    """
    if public_key is None:
        return None
    try:
        public_key_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return public_key_bytes.decode("utf-8")
    except Exception:
        return None


__all__ = [
    'RepoLimit',
    'key_extractor',
    'safe_parse_pem',
    'get_key_size',
    'serialize_public_key'
]

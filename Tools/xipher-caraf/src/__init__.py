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

# Xipher CARAF Scanner - Source Package
"""
Xipher CARAF (Certificate Analysis and Risk Assessment Framework) Scanner
A modular certificate compliance scanner for GitHub organizations.

Modules:
    auth: GitHub authentication helpers (PAT and GitHub App)
    checkers: Compliance checker functions (public key, hash, issuer)
    generators: Output generators (CSV and HTML reports)
    utils: Utility functions for certificate parsing
"""

from .auth import (
    GitHubAuthManager,
    GitHubTokenManager,
    RateLimiter,
    generate_jwt,
    list_installations,
    get_auth_from_user
)
from .generators import CSVGenerator, HTMLGenerator
from .checkers import (
    check_public_key_compliance,
    check_hash_compliance,
    check_issuer_compliance,
    load_compliant_issuers
)
from .utils import (
    RepoLimit,
    key_extractor,
    safe_parse_pem,
    get_key_size,
    serialize_public_key
)
from .constants import CHECK_TYPES
from .compliance_results import CombinedComplianceResult
from .compliance_aggregated_check import check_combined_compliance

__version__ = "1.0.0"

__all__ = [
    'GitHubAuthManager',
    'GitHubTokenManager', 
    'RateLimiter',
    'generate_jwt',
    'list_installations',
    'get_auth_from_user',
    'CSVGenerator',
    'HTMLGenerator',
    'CHECK_TYPES',
    'CombinedComplianceResult',
    'check_combined_compliance'
]

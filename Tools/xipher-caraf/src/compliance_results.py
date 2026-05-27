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
Combined Compliance Result for Xipher CARAF Scanner.

This module provides the CombinedComplianceResult class for holding
aggregated compliance check results for a certificate.
"""

import html


class CombinedComplianceResult:
    """Holds combined compliance check results for a certificate."""
    
    def __init__(self, reference_id: str):
        self.reference_id = reference_id
        self.is_compliant = True
        self.non_compliant_reasons = []
        
        # Individual check results
        self.public_key_compliant = True
        self.public_key_message = ""
        self.hash_compliant = True
        self.hash_message = ""
        self.issuer_compliant = True
        self.issuer_message = ""
        self.ancestor_compliant = True
        self.ancestor_message = ""
        self.is_expired = False
        self.expiry_message = ""
    
    def add_non_compliance(self, check_type: str, message: str):
        self.is_compliant = False
        self.non_compliant_reasons.append(message)
    
    def get_combined_message(self) -> str:
        if self.is_compliant:
            return "✓ Certificate is fully compliant"
        return "\n".join(
            f"{index}. {reason}" for index, reason in enumerate(self.non_compliant_reasons, start=1)
        )
    
    def get_html_reasons(self) -> str:
        """Get HTML formatted non-compliant reasons."""
        if self.is_compliant:
            return '<span style="color: green;">✓ Certificate is fully compliant</span>'
        reasons_html = '<ul style="margin: 0; padding-left: 20px;">'
        for reason in self.non_compliant_reasons:
            escaped_reason = html.escape(reason)
            reasons_html += f'<li style="color: #d32f2f;">{escaped_reason}</li>'
        reasons_html += '</ul>'
        return reasons_html
    
    def to_dict(self) -> dict:
        return {
            "reference_id": self.reference_id,
            "is_compliant": self.is_compliant,
            "combined_message": self.get_combined_message(),
            "public_key_compliant": self.public_key_compliant,
            "public_key_message": self.public_key_message,
            "hash_compliant": self.hash_compliant,
            "hash_message": self.hash_message,
            "issuer_compliant": self.issuer_compliant,
            "issuer_message": self.issuer_message,
            "ancestor_compliant": self.ancestor_compliant,
            "non_compliant_reasons": self.non_compliant_reasons,
            "html_reasons": self.get_html_reasons()
        }

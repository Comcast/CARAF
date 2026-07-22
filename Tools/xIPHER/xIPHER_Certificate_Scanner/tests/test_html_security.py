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
Tests for HTML output security in HTMLGenerator.

Verifies that user-controlled values (e.g. file URLs, organisation names)
are properly HTML-escaped before being written into the generated report,
and that the generated HTML includes a Content-Security-Policy meta tag.
"""

import os
import shutil
import tempfile

import pandas as pd

from src.generators.html_generator import HTMLGenerator


def test_generate_table_row_escapes_file_link_values():
    generator = HTMLGenerator(df=pd.DataFrame(), org="sample-org", output_dir=".")
    row = pd.Series(
        {
            "expired": False,
            "is_compliant": False,
            "repo_name": "repo",
            "file_url": "https://github.com/org/repo/blob/main/certs/evil\"><script>alert(1)</script>.pem#L10",
            "key_type": "RSA",
            "key_size": 2048,
            "curve": "",
            "signature_hash": "sha256",
            "non_compliant_reasons": ["reason"],
            "cert_line_start": 10,
        }
    )

    row_html = generator._generate_table_row(row, row_id=0, table_id="tab")

    assert '<script>' not in row_html
    assert '&lt;script&gt;' in row_html
    assert 'href="https://github.com' in row_html
    assert '&quot;' in row_html


def test_generate_escapes_org_and_includes_csp_meta():
    local_tmp_dir = tempfile.mkdtemp(prefix="xipher-html-test-", dir=os.getcwd())
    try:
        generator = HTMLGenerator(
            df=pd.DataFrame(),
            org='foo<script>alert(1)</script>',
            output_dir=local_tmp_dir,
            timestamp="20260720_120000",
        )
        html_file = generator.generate()

        with open(html_file, "r", encoding="utf-8") as f:
            html_data = f.read()

        assert "Content-Security-Policy" in html_data
        assert "foo&lt;script&gt;alert(1)&lt;/script&gt;" in html_data
        assert "Organization: foo<script>alert(1)</script>" not in html_data
    finally:
        shutil.rmtree(local_tmp_dir, ignore_errors=True)

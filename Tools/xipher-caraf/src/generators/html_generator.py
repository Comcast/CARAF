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
HTML Generator Module
=====================
Generates styled HTML reports from certificate compliance scan results.

Usage (standalone):
    from src.generators.html_generator import HTMLGenerator
    generator = HTMLGenerator(df, org_name, output_dir)
    html_file = generator.generate()

Command line:
    python -m src.generators.html_generator --input results.json --output ./output
"""

import os
import re
import html
import pandas as pd
from pathlib import Path
from datetime import datetime
from typing import Optional

from .csv_generator import CSVGenerator


class HTMLGenerator:
    """
    Generates styled HTML reports for certificate compliance results.
    
    Uses the same column headers as CSVGenerator for consistency:
        repo_name, file_url, subject, issuer, key_type, key_size, curve,
        signature_hash, issue_date, expiry_date, days_to_expire, expiry_status,
        public_key_compliant, hash_compliant, issuer_compliant, non_compliant,
        non_compliant_reasons
    """
    
    # Use same columns as CSV for consistency
    COLUMNS = CSVGenerator.COLUMNS
    
    # Columns to show by default (visible)
    VISIBLE_COLUMNS = [
        'Repo Name', 'File URL', 'Key Type', 'Key Size', 'Curve', 'Signature Hash', 'Expiry Status',
        'Compliance Status', 'Non-Compliant Reasons'
    ]
    
    # Columns to hide by default (expandable)
    HIDDEN_COLUMNS = [
        'Issuer', 'Subject', 'Expiry Date',
        'Issue Date', 'Days To Expire', 'Public Key Compliant', 
        'Hash Compliant', 'Issuer Compliant'
    ]
    
    def __init__(
        self,
        df: pd.DataFrame,
        org: str,
        output_dir: str = "./",
        timestamp: Optional[str] = None
    ):
        """
        Initialize HTML generator.
        
        Args:
            df: DataFrame with scan results
            org: Organization name
            output_dir: Base output directory
            timestamp: Optional timestamp string (default: auto-generated)
        """
        self.df = df
        self.org = org
        self.org_safe = re.sub(r'[^a-zA-Z0-9_\-]', '', org)
        if not self.org_safe:
            raise ValueError("Invalid organization name for output path")
        cwd_path = os.path.realpath(os.getcwd())
        if output_dir in (".", "./"):
            self.output_dir = cwd_path
        elif os.path.isabs(output_dir):
            self.output_dir = os.path.realpath(output_dir)
        else:
            self.output_dir = os.path.realpath(os.path.join(cwd_path, output_dir))
        if self.output_dir != cwd_path and not self.output_dir.startswith(cwd_path + os.sep):
            raise ValueError("Output directory must resolve within current working directory")
        self.timestamp = timestamp or datetime.now().strftime('%Y%m%d_%H%M%S')
    
    def _get_css_styles(self) -> str:
        """Return CSS styles for the HTML report."""
        return '''
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            min-height: 100vh;
            padding: 20px;
            color: #e0e0e0;
        }
        .container {
            max-width: 1600px;
            margin: 0 auto;
        }
        .header {
            background: linear-gradient(135deg, #0984e3 0%, #6c5ce7 100%);
            padding: 30px;
            border-radius: 15px;
            margin-bottom: 30px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.3);
        }
        .header h1 {
            color: white;
            font-size: 2em;
            margin-bottom: 10px;
        }
        .header .subtitle {
            color: rgba(255,255,255,0.8);
            font-size: 1.1em;
        }
        .summary-cards {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .card {
            background: #2d3436;
            border-radius: 12px;
            padding: 25px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.2);
            border-left: 4px solid;
        }
        .card.total { border-color: #0984e3; }
        .card.compliant { border-color: #00b894; }
        .card.non-compliant { border-color: #d63031; }
        .card.expired { border-color: #fdcb6e; }
        .card h3 {
            font-size: 0.9em;
            color: #b2bec3;
            text-transform: uppercase;
            margin-bottom: 10px;
        }
        .card .value {
            font-size: 2.5em;
            font-weight: bold;
        }
        .card.total .value { color: #0984e3; }
        .card.compliant .value { color: #00b894; }
        .card.non-compliant .value { color: #d63031; }
        .card.expired .value { color: #fdcb6e; }
        .section {
            background: #2d3436;
            border-radius: 12px;
            padding: 25px;
            margin-bottom: 30px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.2);
            overflow: visible;
        }
        .section h2 {
            color: #dfe6e9;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid #636e72;
        }
        .tabs {
            display: flex;
            gap: 10px;
            margin-bottom: 20px;
            flex-wrap: wrap;
        }
        .tab-btn {
            border: 1px solid #636e72;
            background: #1f2933;
            color: #dfe6e9;
            border-radius: 8px;
            padding: 10px 14px;
            font-size: 0.9em;
            cursor: pointer;
            transition: all 0.2s ease;
        }
        .tab-btn:hover {
            border-color: #74b9ff;
            background: #253544;
        }
        .tab-btn.active {
            background: linear-gradient(135deg, #0984e3 0%, #6c5ce7 100%);
            border-color: #0984e3;
            color: #ffffff;
            font-weight: 600;
        }
        .tab-content {
            display: none;
        }
        .tab-content.active {
            display: block;
        }
        .table-container {
            overflow-x: auto;
            overflow-y: auto;
            max-height: 70vh;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
        }
        thead {
            position: sticky;
            top: 0;
            z-index: 20;
        }
        th {
            background: linear-gradient(135deg, #2d3436 0%, #1e272e 100%);
            color: #dfe6e9;
            padding: 15px 12px;
            text-align: left;
            font-weight: 600;
            font-size: 0.85em;
            letter-spacing: 0.5px;
            border-bottom: 2px solid #636e72;
            white-space: nowrap;
            position: sticky;
            top: 0;
            z-index: 20;
        }
        td {
            padding: 12px;
            border-bottom: 1px solid #3d4852;
            vertical-align: top;
            font-size: 0.9em;
        }
        tr:hover {
            background: rgba(255,255,255,0.05);
        }
        .status-badge {
            display: inline-block;
            padding: 5px 12px;
            border-radius: 20px;
            font-size: 0.8em;
            font-weight: 600;
        }
        .status-compliant {
            background: rgba(0, 184, 148, 0.2);
            color: #00b894;
            padding: 6px 14px;
            border-radius: 20px;
            font-weight: 600;
        }
        .status-non-compliant {
            background: rgba(214, 48, 49, 0.3);
            color: #ff4757;
            padding: 6px 14px;
            border-radius: 20px;
            font-weight: 700;
            text-transform: uppercase;
        }
        .status-expired {
            background: rgba(253, 203, 110, 0.2);
            color: #fdcb6e;
        }
        .reasons-list {
            list-style: none;
            padding: 0;
            margin: 0;
        }
        .reasons-list li {
            padding: 5px 0;
            color: #ff7675;
            display: flex;
            align-items: flex-start;
        }
        .reasons-list li::before {
            content: "\\2022";
            color: #d63031;
            font-weight: bold;
            margin-right: 8px;
        }
        .file-link {
            color: #74b9ff;
            text-decoration: none;
            word-break: break-all;
        }
        .file-link:hover {
            text-decoration: underline;
        }
        .footer {
            text-align: center;
            color: #636e72;
            padding: 20px;
            font-size: 0.9em;
        }
        .all-compliant {
            text-align: center;
            padding: 50px;
            color: #00b894;
        }
        .all-compliant .icon {
            font-size: 4em;
            margin-bottom: 20px;
        }
        .all-compliant h3 {
            font-size: 1.5em;
            margin-bottom: 10px;
        }
        .text-success { color: #00b894; }
        .text-danger { color: #ff7675; }
        .text-muted { color: #b2bec3; }
        
        /* Expandable row styles */
        .expand-btn {
            background: linear-gradient(135deg, #0984e3 0%, #6c5ce7 100%);
            border: none;
            color: white;
            padding: 6px 12px;
            border-radius: 5px;
            cursor: pointer;
            font-size: 0.85em;
            font-weight: 500;
            transition: all 0.2s ease;
        }
        .expand-btn:hover {
            transform: scale(1.05);
            box-shadow: 0 2px 8px rgba(9, 132, 227, 0.4);
        }
        .expand-btn.expanded {
            background: linear-gradient(135deg, #636e72 0%, #2d3436 100%);
        }
        .details-row {
            display: none;
            background: rgba(0,0,0,0.2);
        }
        .details-row.show {
            display: table-row;
        }
        .details-content {
            padding: 20px;
        }
        .details-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 15px;
        }
        .detail-item {
            background: rgba(255,255,255,0.05);
            padding: 12px 15px;
            border-radius: 8px;
            border-left: 3px solid #0984e3;
        }
        .detail-item .label {
            font-size: 0.75em;
            color: #b2bec3;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 5px;
        }
        .detail-item .value {
            font-size: 0.95em;
            color: #dfe6e9;
            word-break: break-all;
        }
        .detail-item .value.success { color: #00b894; }
        .detail-item .value.danger { color: #ff7675; }
        '''
    
    def _format_value(self, value, default: str = 'N/A') -> str:
        """Format a value for HTML display with proper escaping."""
        if value is None or value == '' or (isinstance(value, float) and pd.isna(value)):
            return default
        # HTML-escape to prevent < > = from being interpreted as HTML tags
        return html.escape(str(value))
    
    def _format_reasons(self, reasons) -> str:
        """Format non-compliant reasons as HTML list."""
        if not reasons:
            return '<span class="text-muted">N/A</span>'
        
        reasons_html = '<ul class="reasons-list">'
        if isinstance(reasons, list):
            for reason in reasons:
                clean = reason.replace("• ", "") if isinstance(reason, str) else str(reason)
                reasons_html += f'<li>{html.escape(clean)}</li>'
        else:
            # Handle string format
            for line in str(reasons).split('\n'):
                if line.strip():
                    clean = line.replace("• ", "").strip()
                    reasons_html += f'<li>{html.escape(clean)}</li>'
        reasons_html += '</ul>'
        return reasons_html
    
    def _generate_summary_cards(self) -> str:
        """Generate summary cards HTML."""
        total = len(self.df) if not self.df.empty else 0
        compliant = self.df['is_compliant'].sum() if not self.df.empty else 0
        non_compliant = (~self.df['is_compliant']).sum() if not self.df.empty else 0
        expired = self.df['expired'].sum() if not self.df.empty and 'expired' in self.df.columns else 0
        
        return f'''
        <div class="summary-cards">
            <div class="card total">
                <h3>Total Certificates</h3>
                <div class="value">{total}</div>
            </div>
            <div class="card compliant">
                <h3>Compliant</h3>
                <div class="value">{compliant}</div>
            </div>
            <div class="card non-compliant">
                <h3>Non-Compliant</h3>
                <div class="value">{non_compliant}</div>
            </div>
            <div class="card expired">
                <h3>Expired</h3>
                <div class="value">{expired}</div>
            </div>
        </div>
        '''
    
    def _generate_table_headers(self) -> str:
        """Generate table header row with visible columns only."""
        headers = ['', 'Repo Name', 'File URL', 'Key Type', 'Key Size', 'Curve', 
                   'Signature Hash', 'Expiry Status', 'Compliance Status', 'Non-Compliant Reasons']
        headers_html = '<tr>'
        for col in headers:
            headers_html += f'<th>{col}</th>'
        headers_html += '</tr>'
        return headers_html
    
    def _generate_details_row(self, row: pd.Series, row_id: int, table_id: str) -> str:
        """Generate the expandable details row with hidden columns."""
        # Get compliance statuses
        pk_compliant = row.get('public_key_compliant', False)
        hash_compliant = row.get('hash_compliant', False)
        issuer_compliant = row.get('issuer_compliant', False)
        
        # Get issuer and subject - use direct access with fallback
        issuer_value = row['issuer'] if 'issuer' in row.index else ''
        subject_value = row['subject'] if 'subject' in row.index else ''
        
        details_html = f'''
        <tr class="details-row" id="details-{table_id}-{row_id}">
            <td colspan="10">
                <div class="details-content">
                    <div class="details-grid">
                        <div class="detail-item">
                            <div class="label">Issuer</div>
                            <div class="value">{self._format_value(issuer_value)}</div>
                        </div>
                        <div class="detail-item">
                            <div class="label">Subject</div>
                            <div class="value">{self._format_value(subject_value)}</div>
                        </div>
                        <div class="detail-item">
                            <div class="label">Expiry Date</div>
                            <div class="value">{self._format_value(row.get('expiry_date'))}</div>
                        </div>
                        <div class="detail-item">
                            <div class="label">Issue Date</div>
                            <div class="value">{self._format_value(row.get('issue_date'))}</div>
                        </div>
                        <div class="detail-item">
                            <div class="label">Days To Expire</div>
                            <div class="value">{self._format_value(row.get('days_to_expire'))}</div>
                        </div>
                        <div class="detail-item">
                            <div class="label">Public Key Compliant</div>
                            <div class="value {'success' if pk_compliant else 'danger'}">{pk_compliant}</div>
                        </div>
                        <div class="detail-item">
                            <div class="label">Hash Compliant</div>
                            <div class="value {'success' if hash_compliant else 'danger'}">{hash_compliant}</div>
                        </div>
                        <div class="detail-item">
                            <div class="label">Issuer Compliant</div>
                            <div class="value {'success' if issuer_compliant else 'danger'}">{issuer_compliant}</div>
                        </div>
                    </div>
                </div>
            </td>
        </tr>
        '''
        return details_html
    
    def _generate_table_row(self, row: pd.Series, row_id: int, table_id: str) -> str:
        """Generate a single table row with expand button."""
        # Get expiry status
        is_expired = row.get('expired', False)
        expiry_status = 'Expired' if is_expired else 'Valid'
        expiry_class = 'text-danger' if is_expired else 'text-success'
        
        # Get compliance status
        is_compliant = row.get('is_compliant', True)
        compliance_status = 'Compliant' if is_compliant else 'Non-Compliant'
        compliance_class = 'status-compliant' if is_compliant else 'status-non-compliant'
        
        # Format file URL as link
        file_url = row.get('file_url', '')
        file_name = file_url.split('/')[-1].split('#')[0] if file_url else 'N/A'
        cert_line_start = row.get('cert_line_start')
        if file_url:
            if pd.notna(cert_line_start):
                file_link = (
                    f'<a class="file-link" href="{file_url}" target="_blank" '
                    f'title="Open and highlight certificate around line {int(cert_line_start)}">'
                    f'{file_name}:L{int(cert_line_start)}</a>'
                )
            else:
                file_link = f'<a class="file-link" href="{file_url}" target="_blank">{file_name}</a>'
        else:
            file_link = 'N/A'
        
        # Format reasons
        reasons_html = self._format_reasons(row.get('non_compliant_reasons', []))
        
        # Build main row with visible columns
        row_html = '<tr>'
        row_html += f'<td><button class="expand-btn" onclick="toggleDetails(\'{table_id}\', {row_id}, this)">▶ Details</button></td>'
        row_html += f'<td>{self._format_value(row.get("repo_name"))}</td>'
        row_html += f'<td>{file_link}</td>'
        row_html += f'<td>{self._format_value(row.get("key_type", "")).replace("_", "")}</td>'
        row_html += f'<td>{self._format_value(row.get("key_size"))}</td>'
        row_html += f'<td>{self._format_value(row.get("curve"))}</td>'
        row_html += f'<td>{self._format_value(row.get("signature_hash"))}</td>'
        row_html += f'<td><span class="{expiry_class}">{expiry_status}</span></td>'
        row_html += f'<td><span class="{compliance_class}">{compliance_status}</span></td>'
        row_html += f'<td>{reasons_html}</td>'
        row_html += '</tr>'
        
        # Add expandable details row
        row_html += self._generate_details_row(row, row_id, table_id)
        
        return row_html
    
    def _generate_table(
        self,
        df: pd.DataFrame,
        table_id: str,
        empty_title: str,
        empty_message: str,
    ) -> str:
        """Generate the full table HTML."""
        if df.empty:
            return '''
            <div class="all-compliant">
                <div class="icon">✅</div>
                <h3>''' + html.escape(empty_title) + '''</h3>
                <p>''' + html.escape(empty_message) + '''</p>
            </div>
            '''
        
        table_html = '''
        <table>
            <thead>
        '''
        table_html += self._generate_table_headers()
        table_html += '''
            </thead>
            <tbody>
        '''
        
        for row_id, (_, row) in enumerate(df.iterrows()):
            table_html += self._generate_table_row(row, row_id, table_id)
        
        table_html += '''
            </tbody>
        </table>
        '''
        
        return table_html
    
    def _get_javascript(self) -> str:
        """Return JavaScript for expand/collapse and pagination functionality."""
        return '''
        const tableStates = {};

        function initTable(sectionId) {
            const section = document.getElementById(sectionId);
            if (!section) return;

            const tbody = section.querySelector('table tbody');
            const rowsSelect = document.getElementById(`${sectionId}-rowsPerPage`);
            const rowsPerPage = parseInt(rowsSelect ? rowsSelect.value : '10', 10);

            if (!tbody) {
                tableStates[sectionId] = {
                    currentPage: 1,
                    rowsPerPage: rowsPerPage,
                    totalRows: 0,
                    dataRows: []
                };
                updatePaginationInfo(sectionId);
                renderPageButtons(sectionId);
                return;
            }

            const allRows = tbody.querySelectorAll('tr:not(.details-row)');
            tableStates[sectionId] = {
                currentPage: 1,
                rowsPerPage: rowsPerPage,
                totalRows: allRows.length,
                dataRows: Array.from(allRows)
            };

            showPage(sectionId, 1, false);
        }

        function setActionButtons(sectionId, activeAction) {
            const expandBtn = document.getElementById(`${sectionId}-expandAllBtn`);
            const collapseBtn = document.getElementById(`${sectionId}-collapseAllBtn`);
            if (!expandBtn || !collapseBtn) return;

            expandBtn.classList.toggle('active', activeAction === 'expand');
            collapseBtn.classList.toggle('active', activeAction === 'collapse');
        }

        function showPage(sectionId, page, clearActionButtons = true) {
            const state = tableStates[sectionId];
            if (!state) return;

            const totalPages = Math.max(1, Math.ceil(state.totalRows / state.rowsPerPage));
            state.currentPage = Math.min(Math.max(page, 1), totalPages);

            const section = document.getElementById(sectionId);
            if (!section) return;

            section.querySelectorAll('.details-row').forEach(row => row.classList.remove('show'));
            section.querySelectorAll('.expand-btn').forEach(btn => {
                btn.classList.remove('expanded');
                btn.textContent = '▶ Details';
            });

            if (clearActionButtons) {
                setActionButtons(sectionId, null);
            }

            const start = (state.currentPage - 1) * state.rowsPerPage;
            const end = start + state.rowsPerPage;

            state.dataRows.forEach((row, index) => {
                const detailsRow = document.getElementById(`details-${sectionId}-${index}`);
                if (index >= start && index < end) {
                    row.style.display = '';
                } else {
                    row.style.display = 'none';
                    if (detailsRow) detailsRow.classList.remove('show');
                }
            });

            updatePaginationInfo(sectionId);
            renderPageButtons(sectionId);
        }

        function updatePaginationInfo(sectionId) {
            const state = tableStates[sectionId];
            if (!state) return;

            const totalPages = Math.max(1, Math.ceil(state.totalRows / state.rowsPerPage));
            const start = state.totalRows > 0 ? (state.currentPage - 1) * state.rowsPerPage + 1 : 0;
            const end = Math.min(state.currentPage * state.rowsPerPage, state.totalRows);

            const info = document.getElementById(`${sectionId}-pageInfo`);
            const pageNum = document.getElementById(`${sectionId}-pageNumber`);
            if (info) info.textContent = `Showing ${start}-${end} of ${state.totalRows} certificates`;
            if (pageNum) pageNum.textContent = `Page ${state.currentPage} of ${totalPages}`;
        }

        function renderPageButtons(sectionId) {
            const state = tableStates[sectionId];
            if (!state) return;

            const totalPages = Math.max(1, Math.ceil(state.totalRows / state.rowsPerPage));
            const container = document.getElementById(`${sectionId}-pageButtons`);
            if (!container) return;

            container.innerHTML = '';
            if (totalPages <= 1) return;

            if (state.currentPage > 1) {
                container.innerHTML += `<button class="page-btn" onclick="showPage('${sectionId}', 1, true)">« First</button>`;
                container.innerHTML += `<button class="page-btn" onclick="showPage('${sectionId}', ${state.currentPage - 1}, true)">‹ Prev</button>`;
            }

            let startPage = Math.max(1, state.currentPage - 2);
            let endPage = Math.min(totalPages, state.currentPage + 2);

            for (let i = startPage; i <= endPage; i++) {
                const activeClass = i === state.currentPage ? 'active' : '';
                container.innerHTML += `<button class="page-btn ${activeClass}" onclick="showPage('${sectionId}', ${i}, true)">${i}</button>`;
            }

            if (state.currentPage < totalPages) {
                container.innerHTML += `<button class="page-btn" onclick="showPage('${sectionId}', ${state.currentPage + 1}, true)">Next ›</button>`;
                container.innerHTML += `<button class="page-btn" onclick="showPage('${sectionId}', ${totalPages}, true)">Last »</button>`;
            }
        }

        function changeRowsPerPage(sectionId) {
            const state = tableStates[sectionId];
            const rowsSelect = document.getElementById(`${sectionId}-rowsPerPage`);
            if (!state || !rowsSelect) return;

            state.rowsPerPage = parseInt(rowsSelect.value, 10);
            showPage(sectionId, 1, true);
        }

        function toggleDetails(sectionId, rowId, btn) {
            const detailsRow = document.getElementById(`details-${sectionId}-${rowId}`);
            if (!detailsRow || !btn) return;

            if (detailsRow.classList.contains('show')) {
                detailsRow.classList.remove('show');
                btn.classList.remove('expanded');
                btn.textContent = '▶ Details';
            } else {
                detailsRow.classList.add('show');
                btn.classList.add('expanded');
                btn.textContent = '▼ Hide';
            }
        }

        function expandAll(sectionId) {
            const state = tableStates[sectionId];
            const section = document.getElementById(sectionId);
            if (!state || !section) return;

            const start = (state.currentPage - 1) * state.rowsPerPage;
            const end = Math.min(start + state.rowsPerPage, state.totalRows);

            for (let i = start; i < end; i++) {
                const detailsRow = document.getElementById(`details-${sectionId}-${i}`);
                if (detailsRow) detailsRow.classList.add('show');
            }

            section.querySelectorAll('tr:not(.details-row):not([style*="display: none"]) .expand-btn').forEach(btn => {
                btn.classList.add('expanded');
                btn.textContent = '▼ Hide';
            });

            setActionButtons(sectionId, 'expand');
        }

        function collapseAll(sectionId, markActive = true) {
            const section = document.getElementById(sectionId);
            if (!section) return;

            section.querySelectorAll('.details-row').forEach(row => row.classList.remove('show'));
            section.querySelectorAll('.expand-btn').forEach(btn => {
                btn.classList.remove('expanded');
                btn.textContent = '▶ Details';
            });

            if (markActive) {
                setActionButtons(sectionId, 'collapse');
            }
        }

        function switchTab(tabId) {
            document.querySelectorAll('.tab-btn').forEach(btn => {
                btn.classList.toggle('active', btn.dataset.tab === tabId);
            });
            document.querySelectorAll('.tab-content').forEach(content => {
                content.classList.toggle('active', content.id === tabId);
            });

            showPage(tabId, 1, true);
        }

        document.addEventListener('DOMContentLoaded', function() {
            initTable('nonCompliantTab');
            initTable('compliantTab');
            switchTab('nonCompliantTab');
        });
        '''
    
    def generate(self, filename: Optional[str] = None) -> str:
        """
        Generate HTML file.
        
        Args:
            filename: Optional custom filename (without path)
        
        Returns:
            Path to generated HTML file
        """
        if filename is not None:
            raise ValueError("Custom output filename is not supported for security reasons")

        # Create output directory
        html_path = os.path.join(self.output_dir, 'output', 'html', self.org_safe)
        os.makedirs(html_path, exist_ok=True)
        
        # Split data for tabbed sections
        non_compliant_df = self.df[~self.df['is_compliant']].copy() if not self.df.empty else self.df.copy()
        compliant_df = self.df[self.df['is_compliant']].copy() if not self.df.empty else self.df.copy()
        
        # Build HTML
        html_content = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Xipher Certificate Compliance Report - {self.org}</title>
    <style>
        {self._get_css_styles()}
        .action-buttons {{
            margin-bottom: 15px;
            display: flex;
            align-items: center;
            flex-wrap: wrap;
            gap: 10px;
        }}
        .action-buttons button {{
            background: #636e72;
            border: none;
            color: white;
            padding: 8px 16px;
            border-radius: 5px;
            cursor: pointer;
            font-size: 0.85em;
        }}
        .action-buttons button:hover {{
            background: #74b9ff;
        }}
        .action-buttons button.active {{
            background: linear-gradient(135deg, #0984e3 0%, #6c5ce7 100%);
            box-shadow: 0 2px 10px rgba(9, 132, 227, 0.45);
        }}
        .pagination-controls {{
            display: flex;
            align-items: center;
            justify-content: space-between;
            flex-wrap: wrap;
            gap: 15px;
            margin: 20px 0;
            padding: 15px;
            background: rgba(0,0,0,0.2);
            border-radius: 10px;
        }}
        .pagination-left {{
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        .pagination-left label {{
            color: #b2bec3;
            font-size: 0.9em;
        }}
        .pagination-left select {{
            background: #2d3436;
            color: #dfe6e9;
            border: 1px solid #636e72;
            padding: 8px 12px;
            border-radius: 5px;
            font-size: 0.9em;
            cursor: pointer;
        }}
        .pagination-left select:hover {{
            border-color: #74b9ff;
        }}
        .pagination-center {{
            display: flex;
            align-items: center;
            gap: 5px;
        }}
        .page-btn {{
            background: #2d3436;
            border: 1px solid #636e72;
            color: #dfe6e9;
            padding: 8px 12px;
            border-radius: 5px;
            cursor: pointer;
            font-size: 0.85em;
            transition: all 0.2s ease;
        }}
        .page-btn:hover {{
            background: #0984e3;
            border-color: #0984e3;
        }}
        .page-btn.active {{
            background: linear-gradient(135deg, #0984e3 0%, #6c5ce7 100%);
            border-color: #0984e3;
            font-weight: bold;
        }}
        .pagination-right {{
            color: #b2bec3;
            font-size: 0.9em;
        }}
        #pageInfo {{
            color: #74b9ff;
            font-weight: 500;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔐 Xipher Certificate Compliance Report</h1>
            <div class="subtitle">Organization: {self.org} | Generated: {self.timestamp}</div>
        </div>
        
        {self._generate_summary_cards()}
        
        <div class="section">
            <div class="tabs">
                <button class="tab-btn active" data-tab="nonCompliantTab" onclick="switchTab('nonCompliantTab')">🚨 Non-Compliant Certificates</button>
                <button class="tab-btn" data-tab="compliantTab" onclick="switchTab('compliantTab')">✅ Compliant Certificates</button>
            </div>

            <div class="tab-content active" id="nonCompliantTab">
                <div class="action-buttons">
                    <button id="nonCompliantTab-expandAllBtn" onclick="expandAll('nonCompliantTab')">📂 Expand All</button>
                    <button id="nonCompliantTab-collapseAllBtn" onclick="collapseAll('nonCompliantTab')">📁 Collapse All</button>
                </div>

                <div class="table-container">
                    {self._generate_table(non_compliant_df, 'nonCompliantTab', 'All Certificates Are Compliant!', 'No compliance issues were found in the scanned repositories.')}
                </div>

                <div class="pagination-controls">
                    <div class="pagination-left">
                        <label for="nonCompliantTab-rowsPerPage">Show:</label>
                        <select id="nonCompliantTab-rowsPerPage" onchange="changeRowsPerPage('nonCompliantTab')">
                            <option value="5">5</option>
                            <option value="10" selected>10</option>
                            <option value="25">25</option>
                            <option value="50">50</option>
                            <option value="100">100</option>
                        </select>
                        <span>per page</span>
                    </div>
                    <div class="pagination-center" id="nonCompliantTab-pageButtons"></div>
                    <div class="pagination-right">
                        <span id="nonCompliantTab-pageInfo"></span> | <span id="nonCompliantTab-pageNumber"></span>
                    </div>
                </div>
            </div>

            <div class="tab-content" id="compliantTab">
                <div class="action-buttons">
                    <button id="compliantTab-expandAllBtn" onclick="expandAll('compliantTab')">📂 Expand All</button>
                    <button id="compliantTab-collapseAllBtn" onclick="collapseAll('compliantTab')">📁 Collapse All</button>
                </div>

                <div class="table-container">
                    {self._generate_table(compliant_df, 'compliantTab', 'No Compliant Certificates Found', 'No compliant certificates matched this scan.')}
                </div>

                <div class="pagination-controls">
                    <div class="pagination-left">
                        <label for="compliantTab-rowsPerPage">Show:</label>
                        <select id="compliantTab-rowsPerPage" onchange="changeRowsPerPage('compliantTab')">
                            <option value="5">5</option>
                            <option value="10" selected>10</option>
                            <option value="25">25</option>
                            <option value="50">50</option>
                            <option value="100">100</option>
                        </select>
                        <span>per page</span>
                    </div>
                    <div class="pagination-center" id="compliantTab-pageButtons"></div>
                    <div class="pagination-right">
                        <span id="compliantTab-pageInfo"></span> | <span id="compliantTab-pageNumber"></span>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="footer">
            <p>Generated by Xipher CARAF Scanner | {self.timestamp}</p>
        </div>
    </div>
    <script>
        {self._get_javascript()}
    </script>
</body>
</html>
'''
        
        # Generate deterministic filename in target directory.
        html_file = os.path.join(html_path, f"{self.org_safe}_combined_compliance_{self.timestamp}.html")

        resolved_dir = os.path.realpath(html_path)
        resolved_file = os.path.realpath(html_file)
        if not resolved_file.startswith(resolved_dir + os.sep):
            raise ValueError("Resolved HTML output path is outside target directory")
        
        # Write HTML using Path API after path containment validation.
        Path(resolved_file).write_text(html_content, encoding='utf-8')
        
        return resolved_file


import os
def main():
    """Standalone HTML generator from JSON input."""
    import argparse
    import json
    
    parser = argparse.ArgumentParser(
        description="Generate HTML report from scan results",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--input",
        "-i",
        type=argparse.FileType('r', encoding='utf-8'),
        required=True,
        help="Input JSON file with scan results"
    )
    parser.add_argument("--output", "-o", default="./", help="Output directory")
    parser.add_argument("--org", default="scan", help="Organization name for filename")
    
    args = parser.parse_args()
    
    cwd_path = os.path.realpath(os.getcwd())

    output_name = os.path.basename(args.output) if args.output not in (".", "./") else "."
    safe_output_dir = cwd_path if output_name == "." else os.path.realpath(os.path.join(cwd_path, output_name))
    if safe_output_dir != cwd_path and not safe_output_dir.startswith(cwd_path + os.sep):
        raise ValueError("Output directory must be within current working directory")

    if not args.input.name.lower().endswith('.json'):
        raise ValueError("Input file must be a .json file")
    data = json.load(args.input)
    
    df = pd.DataFrame(data)
    
    # Generate HTML
    generator = HTMLGenerator(
        df=df,
        org=args.org,
        output_dir=safe_output_dir
    )
    
    html_file = generator.generate()
    print(f"[OUTPUT] HTML generated: {html_file}")


if __name__ == "__main__":
    main()

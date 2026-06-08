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
CSV Generator Module
====================
Generates CSV reports from certificate compliance scan results.

Usage (standalone):
    from src.generators.csv_generator import CSVGenerator
    generator = CSVGenerator(df, org_name, output_dir)
    csv_file = generator.generate()

Command line:
    python -m src.generators.csv_generator --input results.json --output ./output
"""

import os
import re
import pandas as pd
from datetime import datetime
from typing import Optional


class CSVGenerator:
    """
    Generates CSV reports for certificate compliance results.
    
    Output columns (in order):
        - repo_name: Repository name
        - file_url: Full URL to the certificate file
        - subject: Certificate subject
        - issuer: Certificate issuer
        - key_type: Public key type (RSA, ECC, etc.)
        - key_size: Key size in bits
        - curve: ECC curve name (if applicable)
        - signature_hash: Hash algorithm used for signature
        - issue_date: Certificate issue date
        - expiry_date: Certificate expiry date
        - days_to_expire: Days until expiration (negative if expired)
        - public_key_compliant: Boolean - key compliance status
        - hash_compliant: Boolean - hash algorithm compliance status
        - issuer_compliant: Boolean - issuer CA compliance status
        - expiry_status: "Expired" or "Not Expired"
        - compliance_status: "Non-Compliant" if certificate is non-compliant else "Compliant"
        - non_compliant_reasons: List of compliance failure reasons
    """
    
    # Standard column headers - shared between CSV and HTML
    COLUMNS = [
        'Repo Name',
        'File URL',
        'Open Highlighted Cert',
        'Subject',
        'Issuer',
        'Key Type',
        'Key Size',
        'Curve',
        'Signature Hash',
        'Issue Date',
        'Expiry Date',
        'Days To Expire',
        'Public Key Compliant',
        'Hash Compliant',
        'Issuer Compliant',
        'Expiry Status',
        'Compliance Status',
        'Non Compliant Reasons'
    ]
    
    # Mapping from DataFrame column names to display names
    COLUMN_MAPPING = {
        'repo_name': 'Repo Name',
        'file_url': 'File URL',
        'open_highlighted_cert': 'Open Highlighted Cert',
        'subject': 'Subject',
        'issuer': 'Issuer',
        'key_type': 'Key Type',
        'key_size': 'Key Size',
        'curve': 'Curve',
        'signature_hash': 'Signature Hash',
        'issue_date': 'Issue Date',
        'expiry_date': 'Expiry Date',
        'days_to_expire': 'Days To Expire',
        'public_key_compliant': 'Public Key Compliant',
        'hash_compliant': 'Hash Compliant',
        'issuer_compliant': 'Issuer Compliant',
        'expiry_status': 'Expiry Status',
        'compliance_status': 'Compliance Status',
        'non_compliant_reasons': 'Non Compliant Reasons'
    }
    
    def __init__(
        self,
        df: pd.DataFrame,
        org: str,
        output_dir: str = "./",
        include_compliant: bool = False,
        filter_mode: Optional[str] = None,
        timestamp: Optional[str] = None
    ):
        """
        Initialize CSV generator.
        
        Args:
            df: DataFrame with scan results
            org: Organization name
            output_dir: Base output directory
            include_compliant: If True, include compliant certs (default: False - only non-compliant)
            filter_mode: One of 'non_compliant', 'compliant', or 'all'.
                        If not provided, derived from include_compliant for backward compatibility.
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
        self.include_compliant = include_compliant
        derived_mode = 'all' if include_compliant else 'non_compliant'
        self.filter_mode = filter_mode or derived_mode
        if self.filter_mode not in {'non_compliant', 'compliant', 'all'}:
            raise ValueError("filter_mode must be one of: non_compliant, compliant, all")
        self.timestamp = timestamp or datetime.now().strftime('%Y%m%d_%H%M%S')

    def _filter_dataframe(self, filter_mode: str) -> pd.DataFrame:
        """Filter rows by compliance status using a stable mode contract."""
        if self.df.empty:
            return self.df.copy()

        if filter_mode == 'all':
            return self.df.copy()
        if filter_mode == 'compliant':
            return self.df[self.df['is_compliant']].copy()
        return self.df[~self.df['is_compliant']].copy()
    
    def _sanitize_csv_injection(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Prevent CSV formula injection by prefixing dangerous characters with single quote.
        
        Values starting with =, +, -, or @ can be interpreted as formulas by spreadsheet
        applications. This function prefixes such values with a single quote to force
        them to be treated as plain text.
        
        Args:
            df: DataFrame to sanitize
        
        Returns:
            DataFrame with injection-safe values
        """
        df = df.copy()
        
        # Columns that may contain untrusted data from scanned certificates
        injection_risk_columns = ['Subject', 'Issuer', 'Non Compliant Reasons']
        
        for col in injection_risk_columns:
            if col in df.columns:
                df[col] = df[col].apply(
                    lambda x: f"'{x}" if isinstance(x, str) and x and x[0] in '=+-@' else x
                )
        
        return df
    
    def _prepare_dataframe_for_mode(self, filter_mode: str) -> pd.DataFrame:
        """Prepare DataFrame for CSV/XLSX output for a specific filter mode."""
        output_df = self._filter_dataframe(filter_mode)
        
        if output_df.empty:
            return pd.DataFrame(columns=self.COLUMNS)
        
        # Create derived columns
        if 'is_compliant' in output_df.columns:
            output_df['non_compliant'] = ~output_df['is_compliant']
            output_df['compliance_status'] = output_df['is_compliant'].apply(
                lambda x: 'Compliant' if x else 'Non-Compliant'
            )
        
        # Convert expired to expiry_status text
        if 'expired' in output_df.columns:
            output_df['expiry_status'] = output_df['expired'].apply(
                lambda x: 'Expired' if x else 'Valid'
            )
        
        # Rename combined_message to non_compliant_reasons
        if 'combined_message' in output_df.columns:
            output_df['non_compliant_reasons'] = output_df['combined_message']

        # Build Excel hyperlink formula without exposing start/end line columns.
        if 'file_url' in output_df.columns:
            def _build_excel_link_from_source(row):
                file_url = row.get('file_url')
                if not isinstance(file_url, str) or not file_url.startswith('https://github.com/'):
                    return 'N/A'

                start_line = row.get('cert_line_start')
                if pd.isna(start_line):
                    match = re.search(r'#L(\d+)(?:-L\d+)?$', file_url)
                    if match:
                        start_line = match.group(1)

                label = 'Open Cert'
                if pd.notna(start_line):
                    try:
                        label = f'Open Cert L{int(start_line)}'
                    except (TypeError, ValueError):
                        pass

                safe_url = file_url.replace('"', '""')
                safe_label = label.replace('"', '""')
                return f'=HYPERLINK("{safe_url}","{safe_label}")'

            output_df['open_highlighted_cert'] = output_df.apply(_build_excel_link_from_source, axis=1)
        
        # Select only columns that exist (using original snake_case names)
        original_cols = list(self.COLUMN_MAPPING.keys())
        available_cols = [c for c in original_cols if c in output_df.columns]
        result_df = output_df[available_cols].copy()
        
        # Rename columns to display names
        result_df = result_df.rename(columns=self.COLUMN_MAPPING)

        # Reorder columns to keep key navigation fields near the beginning.
        ordered_cols = [c for c in self.COLUMNS if c in result_df.columns]
        trailing_cols = [c for c in result_df.columns if c not in ordered_cols]
        result_df = result_df[ordered_cols + trailing_cols]
        
        # Fill missing values
        result_df = result_df.fillna('N/A')
        
        # Prevent CSV formula injection
        result_df = self._sanitize_csv_injection(result_df)
        
        return result_df

    def _prepare_dataframe(self) -> pd.DataFrame:
        """Prepare DataFrame for CSV output using instance filter mode."""
        return self._prepare_dataframe_for_mode(self.filter_mode)
    
    def generate(self, filename: Optional[str] = None) -> str:
        """
        Generate CSV file.
        
        Args:
            filename: Optional custom filename (without path)
        
        Returns:
            Path to generated CSV file
        """
        if filename is not None:
            raise ValueError("Custom output filename is not supported for security reasons")

        # Create output directory
        csv_path = os.path.join(self.output_dir, 'output', 'csv', self.org_safe)
        os.makedirs(csv_path, exist_ok=True)
        
        # Prepare data
        csv_df = self._prepare_dataframe()
        
        # Generate deterministic filename in target directory.
        if self.filter_mode == 'compliant':
            csv_name = f"{self.org_safe}_compliant_only_{self.timestamp}.csv"
        elif self.filter_mode == 'all':
            csv_name = f"{self.org_safe}_all_certificates_{self.timestamp}.csv"
        else:
            csv_name = f"{self.org_safe}_combined_compliance_{self.timestamp}.csv"
        csv_file = os.path.join(csv_path, csv_name)

        resolved_dir = os.path.realpath(csv_path)
        resolved_file = os.path.realpath(csv_file)
        if not resolved_file.startswith(resolved_dir + os.sep):
            raise ValueError("Resolved CSV output path is outside target directory")
        
        # Write UTF-8 BOM and an Excel separator hint so locale-specific Excel opens
        # comma-delimited CSVs into multiple columns instead of a single text column.
        with open(resolved_file, 'w', encoding='utf-8-sig', newline='') as csv_handle:
            csv_handle.write('sep=,\n')
            csv_df.to_csv(csv_handle, index=False)
        
        return resolved_file

    def generate_excel_with_sheets(self, filename: Optional[str] = None) -> str:
        """Generate a two-sheet Excel workbook for non-compliant and compliant certificates."""
        if filename is not None:
            raise ValueError("Custom output filename is not supported for security reasons")

        csv_path = os.path.join(self.output_dir, 'output', 'csv', self.org_safe)
        os.makedirs(csv_path, exist_ok=True)

        non_compliant_df = self._prepare_dataframe_for_mode('non_compliant')
        compliant_df = self._prepare_dataframe_for_mode('compliant')

        xlsx_file = os.path.join(
            csv_path,
            f"{self.org_safe}_combined_compliance_{self.timestamp}.xlsx"
        )

        resolved_dir = os.path.realpath(csv_path)
        resolved_file = os.path.realpath(xlsx_file)
        if not resolved_file.startswith(resolved_dir + os.sep):
            raise ValueError("Resolved XLSX output path is outside target directory")

        with pd.ExcelWriter(resolved_file, engine='openpyxl') as writer:
            non_compliant_df.to_excel(writer, sheet_name='Non-Compliant', index=False)
            compliant_df.to_excel(writer, sheet_name='Compliant', index=False)

        return resolved_file
    
    def get_summary(self) -> dict:
        """Get summary statistics from the data."""
        return {
            'total': len(self.df),
            'compliant': self.df['is_compliant'].sum() if not self.df.empty else 0,
            'non_compliant': (~self.df['is_compliant']).sum() if not self.df.empty else 0,
            'expired': self.df['expired'].sum() if not self.df.empty and 'expired' in self.df.columns else 0
        }


import os
def main():
    """Standalone CSV generator from JSON input."""
    import argparse
    import json
    
    parser = argparse.ArgumentParser(
        description="Generate CSV report from scan results",
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
    parser.add_argument("--include-compliant", action="store_true", help="Include compliant certs")
    
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
    
    # Generate CSV
    generator = CSVGenerator(
        df=df,
        org=args.org,
        output_dir=safe_output_dir,
        include_compliant=args.include_compliant
    )
    
    csv_file = generator.generate()
    print(f"[OUTPUT] CSV generated: {csv_file}")
    
    # Print summary
    summary = generator.get_summary()
    print(f"[SUMMARY] Total: {summary['total']}, Compliant: {summary['compliant']}, Non-Compliant: {summary['non_compliant']}")


if __name__ == "__main__":
    main()

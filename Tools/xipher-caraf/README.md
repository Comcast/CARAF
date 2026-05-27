# Xipher CARAF Certificate Scanner

**Cryptographic Discovery and Analysis of Certificates in GitHub Code**

A comprehensive certificate compliance scanner for GitHub organizations that checks certificates against multiple security criteria, including expiry, deprecated/weak public key and hash usage, and issuer CA checks.

## Features

- **Multi-Check Compliance**: Expiry, Public Key (deprecated/weak), Hash Algorithm (deprecated/weak), and Issuer CA compliance checks
- **Flexible Authentication**: Support for Personal Access Token (PAT) and GitHub App authentication
- **Selective Scanning**: Run only specific checks or skip certain checks
- **Multiple Output Formats**: CSV and styled HTML reports with expandable details
- **Interactive HTML Reports**: Pagination, expand/collapse all, color-coded compliance status
- **Modular Architecture**: Separate generators and checkers for extensibility
- **Report Management**: Clean output command to remove all generated reports

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         Xipher CARAF Scanner                                │
│                    (xipher_combined_scanner.py)                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────┐    ┌──────────────────┐    ┌─────────────────────────────┐ │
│  │   GitHub    │───▶│  Authentication  │───▶│     Repository Scanner      │ │
│  │    API      │    │    (src/auth)    │    │   - Fetch ZIP archives      │ │
│  └─────────────┘    │  - PAT (env var) │    │   - Extract files           │ │
│                     │  - GitHub App    │    │   - Parse certificates      │ │
│                     │  - Rate Limiter  │    └───────────┬─────────────────┘ │
│                     └──────────────────┘                │                   │
│                                                         ▼                   │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │                      Compliance Checkers (src/checkers)              │   │
│  ├────────────────┬───────────────┬────────────────┬────────────────────┤   │
│  │  Public Key    │    Hash       │    Issuer      │     Expiry         │   │
│  │  Checker       │   Checker     │   Checker      │     Check          │   │
│  │ (Weak/Legacy)  │ (Weak/Legacy) │  (CA List)     │   (Validity)       │   │
│  └────────────────┴───────────────┴────────────────┴────────────────────┘   │
│                                    │                                        │
│                                    ▼                                        │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │                    Compliance Aggregator                             │   │
│  │              (src/compliance_aggregated_check.py)                    │   │
│  │         Combines results + Ancestor compliance check                 │   │
│  └───────────────────────────────────┬──────────────────────────────────┘   │
│                                      │                                      │
│                                      ▼                                      │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │                     Report Generators (src/generators)               │   │
│  ├─────────────────────────────┬────────────────────────────────────────┤   │
│  │       CSV Generator         │           HTML Generator               │   │
│  │  - Title Case columns       │  - Dark theme responsive design        │   │
│  │  - Compliance status        │  - Expandable row details              │   │
│  │  - Non-compliant reasons    │  - Pagination (5/10/25/50/100)         │   │ 
│  │                             │  - Color-coded compliance badges       │   │
│  └─────────────────────────────┴────────────────────────────────────────┘   │
│                                      │                                      │
│                                      ▼                                      │
│                          ┌─────────────────────┐                            │
│                          │   output/ folder    │                            │
│                          │  ├── csv/{org}/     │                            │
│                          │  └── html/{org}/    │                            │
│                          └─────────────────────┘                            │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Table of Contents

- [Project Setup](#project-setup)
- [Authentication](#authentication)
  - [Creating a Personal Access Token (PAT)](#creating-a-personal-access-token-pat)
  - [Creating a GitHub App Token](#creating-a-github-app-token)
- [Usage](#usage)
  - [Basic Usage](#basic-usage)
  - [Command Line Options](#command-line-options)
  - [Compliance Check Options](#compliance-check-options)
  - [Utility Commands](#utility-commands)
- [Output](#output)
- [Project Structure](#project-structure)

---

## Project Setup

### Prerequisites

- Python 3.8 or higher
- pip (Python package manager)

### Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/your-org/xipher-caraf.git
   cd xipher-caraf
   ```

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Verify installation**:
   ```bash
   python xipher_combined_scanner.py --help
   ```

### Dependencies

The scanner requires the following Python packages (defined in `requirements.txt`):

```
requests==2.33.0
pandas==2.2.2
PyJWT==2.12.1
cryptography==46.0.7
```

Dependencies are pinned to exact versions to prevent accidental installation of releases with breaking changes or security vulnerabilities.

---

## Authentication

The scanner requires GitHub API access. You can authenticate using either a **Personal Access Token (PAT)** or a **GitHub App**.

### Creating a Personal Access Token (PAT)

1. Go to **GitHub Settings** → **Developer settings** → **Personal access tokens** → **Tokens (classic)**
   - URL: https://github.com/settings/tokens

2. Click **"Generate new token (classic)"**

3. Configure the token:
   - **Note**: Give it a descriptive name (e.g., "Xipher CARAF Scanner")
   - **Expiration**: Set appropriate expiration
   - **Scopes**: Select the following:
     - `repo` (Full control of private repositories)
     - Or `public_repo` (for public repositories only)

4. Click **"Generate token"**

5. **Copy the token immediately** (you won't see it again!)

6. Use with the scanner — set the token as an environment variable, never on the command line:
   ```bash
   export GITHUB_TOKEN=YOUR_TOKEN
   python xipher_combined_scanner.py -o YOUR_ORG
   ```

> **Rate Limit**: PAT tokens have a rate limit of 5,000 requests/hour.

### Creating a GitHub App Token

GitHub Apps have higher rate limits (15,000 requests/hour) and are better for organization-wide scanning.

1. Go to **GitHub Settings** → **Developer settings** → **GitHub Apps**
   - URL: https://github.com/settings/apps

2. Click **"New GitHub App"**

3. Configure the app:
   - **GitHub App name**: e.g., "Xipher CARAF Scanner"
   - **Homepage URL**: Your project URL
   - **Webhook**: Uncheck "Active" (not needed)
   - **Permissions**:
     - Repository permissions:
       - **Contents**: Read-only
       - **Metadata**: Read-only

4. Click **"Create GitHub App"**

5. Note the **App ID** (displayed on the app page)

6. Generate a **Private Key**:
   - Scroll to "Private keys" section
   - Click **"Generate a private key"**
   - Save the downloaded `.pem` file securely

7. **Install the app** on your organization:
   - Go to "Install App" in the left sidebar
   - Select your organization
   - Choose repositories (all or selected)

8. Use with the scanner:
   ```bash
   # Recommended: set the key file path as an env var (path stays out of ps aux / shell history)
   export XIPHER_APP_PRIVATE_KEY_FILE=/path/to/private-key.pem
   python xipher_combined_scanner.py -o YOUR_ORG --app-id YOUR_APP_ID
   ```

   > **Security note**: avoid `--private-key-file` on the command line — even a file path is visible
   > in `ps aux` output and shell history, revealing where your key is stored on disk.
   > Use the `XIPHER_APP_PRIVATE_KEY_FILE` environment variable instead.

---

## Usage

### Basic Usage

```bash
# Interactive mode (prompts for authentication)
python xipher_combined_scanner.py -o YOUR_ORG

# With PAT token — pass via env var, never on the command line
export GITHUB_TOKEN=YOUR_TOKEN
python xipher_combined_scanner.py -o YOUR_ORG

# With GitHub App — key file path via env var (recommended; keeps path out of ps aux)
export XIPHER_APP_PRIVATE_KEY_FILE=/path/to/private-key.pem
python xipher_combined_scanner.py -o YOUR_ORG --app-id 12345

# Scan specific repositories (PAT via env var)
export GITHUB_TOKEN=YOUR_TOKEN
python xipher_combined_scanner.py -o YOUR_ORG --repos repo1,repo2
```

### Command Line Options

| Option | Description |
|--------|-------------|
| `-o, --org` | GitHub organization name (required) |
| `--repos` | Comma-separated list of repos to scan (default: all) |
| `--app-id` | GitHub App ID |
| `--private-key-file` | Path to GitHub App private key `.pem` file. **Prefer `XIPHER_APP_PRIVATE_KEY_FILE` env var** — CLI paths appear in `ps aux` and shell history. |
| `--threads` | Number of threads (default: 1) |
| `--output-dir` | Base output directory. Reports saved to `<dir>/output/csv/` and `<dir>/output/html/` (default: ./) |
| `-i, --interactive` | Force interactive authentication input |
| `--only-checks` | Run only specified checks |
| `--skip-checks` | Skip specified checks |
| `--list-checks` | List all available compliance checks |
| `--clean-output` | Remove all files and folders in the output directory (with confirmation) |

### Environment Variables

Secrets are **never** passed as CLI arguments to avoid exposure in shell history and `ps aux` output. Use environment variables instead:

| Variable | Description |
|----------|-------------|
| `GITHUB_TOKEN` | **Required for PAT auth.** Personal Access Token with `repo` or `public_repo` scope. |
| `XIPHER_APP_PRIVATE_KEY_FILE` | Path to the GitHub App private key `.pem` file (alternative to `--private-key-file`). |
| `XIPHER_PRIVATE_KEY` | Inline PEM content of the GitHub App private key (for CI/CD secret injection without a file). |
| `XIPHER_GITHUB_CERT_SHA256_PINS` | Comma-separated SHA-256 fingerprints to pin for `api.github.com` TLS verification. |

### Compliance Check Options

The scanner supports four compliance checks that can be selectively enabled or disabled:

| Check | Description |
|-------|-------------|
| `expiry` | Check if certificates are expired |
| `public_key` | Check deprecated/weak public key configurations |
| `hash` | Check deprecated/weak hash algorithms |
| `issuer` | Check if issuer CA is in compliant list |

#### List Available Checks

```bash
python xipher_combined_scanner.py --list-checks
```

#### Run Only Specific Checks

```bash
# Only check expiry and public key status
export GITHUB_TOKEN=YOUR_TOKEN
python xipher_combined_scanner.py -o YOUR_ORG --only-checks expiry,public_key

# Only check hash algorithm status
python xipher_combined_scanner.py -o YOUR_ORG --only-checks hash
```

#### Skip Certain Checks

```bash
# Run all checks except issuer verification
python xipher_combined_scanner.py -o YOUR_ORG --skip-checks issuer

# Skip expiry and hash checks
python xipher_combined_scanner.py -o YOUR_ORG --skip-checks expiry,hash
```

### Utility Commands

#### List Available Checks
```bash
python xipher_combined_scanner.py --list-checks
```

#### Clean Output (Remove All Reports)
```bash
# Remove all generated reports with confirmation
python xipher_combined_scanner.py --clean-output
```

> **Note**: The `--clean-output` command will prompt for confirmation before deleting files. For security, it always operates on the local `./output` directory regardless of `--output-dir`.

---

## Output

The scanner generates two output files in the `output/` directory:

### XLSX Output

Location: `output/csv/{org}/{org}_combined_compliance_{timestamp}.xlsx`

Sheets:
- Non-Compliant
- Compliant

| Column | Description |
|--------|-------------|
| Repo Name | Repository name |
| File URL | Full URL to the certificate file |
| Open Highlighted Cert | Excel hyperlink to open the exact certificate lines in GitHub |
| Subject | Certificate subject |
| Issuer | Certificate issuer |
| Key Type | Public key type (RSA, ECC, etc.) |
| Key Size | Key size in bits |
| Curve | ECC curve name (if applicable) |
| Signature Hash | Hash algorithm used |
| Issue Date | Certificate issue date |
| Expiry Date | Certificate expiry date |
| Days To Expire | Days until expiration (negative if expired) |
| Public Key Compliant | Boolean - key compliance status |
| Hash Compliant | Boolean - hash algorithm compliance |
| Issuer Compliant | Boolean - issuer CA compliance |
| Expiry Status | "Expired" or "Not Expired" |
| Compliance Status | "Non-Compliant" or "Compliant" |
| Non Compliant Reasons | List of compliance issues |

Tip: in Excel, click **Open Highlighted Cert** to jump directly to the certificate section in a chain file.

### HTML Output

Location: `output/html/{org}/{org}_combined_compliance_{timestamp}.html`

Features:
- **Dark-themed responsive design** with gradient styling
- **Summary cards** showing Total, Compliant, Non-Compliant, and Expired counts
- **Pagination controls** with options for 5, 10, 25, 50, or 100 rows per page
- **Expandable row details** - Click "Details" to see hidden columns
- **Expand All / Collapse All** buttons for bulk operations
- **Color-coded badges**:
  - **Non-Compliant**: Red uppercase badge
  - **Compliant**: Green badge
  - **Expired**: Yellow badge

#### Visible Columns (Main Table)
- Repo Name, File URL, Key Type, Key Size, Curve, Signature Hash, Expiry Status, Compliance Status, Non-Compliant Reasons

#### Hidden Columns (Expandable Details)
- Issuer, Subject, Expiry Date, Issue Date, Days To Expire, Public Key Compliant, Hash Compliant, Issuer Compliant

---

## Project Structure

```
xipher-caraf/
├── xipher_combined_scanner.py          # Main scanner entry point
├── requirements.txt                     # Python dependencies
├── Compliant_Certificates_Combined.csv  # Compliant CA/ICA list for issuer checks
├── README.md                            # This file
├── .gitignore                           # Git ignore rules
│
├── src/                                 # Source modules
│   ├── __init__.py
│   ├── auth.py                          # GitHub authentication (PAT via env + GitHub App)
│   ├── utils.py                         # Utility functions (key extraction, parsing)
│   ├── constants.py                     # Check types and constants
│   ├── compliance_results.py            # CombinedComplianceResult class
│   ├── compliance_aggregated_check.py   # Aggregated compliance checker
│   ├── tls_utils.py                     # TLS verification and secure request helpers
│   │
│   ├── checkers/                        # Individual compliance checkers
│   │   ├── __init__.py
│   │   ├── public_key_checker.py        # Deprecated/weak public key checks
│   │   ├── hash_checker.py              # Deprecated/weak hash checks
│   │   └── issuer_checker.py            # Issuer CA compliance
│   │
│   └── generators/                      # Report generators
│       ├── __init__.py
│       ├── csv_generator.py             # CSV report generator
│       └── html_generator.py            # HTML report generator
│
└── output/                              # Generated reports (created on scan)
    ├── csv/{org}/                       # CSV reports by organization
    └── html/{org}/                      # HTML reports by organization
```

### Module Descriptions

| Module | Description |
|--------|-------------|
| `src/auth.py` | GitHub authentication manager for PAT (`GITHUB_TOKEN`) and GitHub App credentials |
| `src/utils.py` | Certificate parsing, key extraction, PEM handling |
| `src/constants.py` | CHECK_TYPES dictionary defining available compliance checks |
| `src/compliance_results.py` | Data class for combined compliance results |
| `src/compliance_aggregated_check.py` | Main compliance aggregator that runs all checks |
| `src/tls_utils.py` | TLS verification utilities, certificate pinning/TOFU support, and `secure_request()` wrapper |
| `src/checkers/public_key_checker.py` | Detects deprecated/weak key sizes and unsupported curves |
| `src/checkers/hash_checker.py` | Detects deprecated/weak hash algorithms |
| `src/checkers/issuer_checker.py` | Validates issuer against compliant CA list |
| `src/generators/csv_generator.py` | Generates CSV reports with Title Case columns |
| `src/generators/html_generator.py` | Generates interactive HTML reports with pagination |

### Module Usage

The generators can be used independently:

```python
from src.generators import CSVGenerator, HTMLGenerator
import pandas as pd

# Assuming you have scan results in a DataFrame
df = pd.DataFrame(scan_results)

# Generate CSV
csv_gen = CSVGenerator(df, org="my-org", output_dir="./")
csv_file = csv_gen.generate()

# Generate HTML
html_gen = HTMLGenerator(df, org="my-org", output_dir="./")
html_file = html_gen.generate()
```

---

## Compliance Criteria

> **Important**: Hash and public key checks are policy-based deprecated/weak detection checks. They should not be treated as formal PQC certification.

### Public Key Check (Deprecated/Weak Detection)

- **RSA**: Minimum 2048-bit key size
- **DSA**: Minimum 2048-bit key size
- **ECC**: NIST curves (secp256r1, secp384r1, secp521r1) or Brainpool curves
- **Edwards/Montgomery**: Ed25519, Ed448, X25519, X448 (accepted)
- Keys/curves outside these policies are reported as deprecated/weak.

### Hash Check (Deprecated/Weak Detection)

Accepted algorithms:
- SHA-256, SHA-384, SHA-512
- SHA3-256

Deprecated/weak examples: SHA-1, MD5, MD4, MD2.

### Issuer CA Compliance

Certificate issuers are validated against the `Compliant_Certificates_Combined.csv` file, which contains a list of approved Certificate Authorities (CAs).

> **Note**: If the CSV file is empty (header only), the issuer check is automatically skipped.

**Customizing the Compliant CA List:**

You can modify `Compliant_Certificates_Combined.csv` to add or remove CAs based on your organization's requirements. The file format is simple - one CA name per line:

```csv
Title
DigiCert Global Root CA
GlobalSign Root CA
Let's Encrypt Authority X3
```

---

## Troubleshooting

### Common Issues

**Authentication Error**
```
[ERROR] Failed to list installations
```
- Verify `GITHUB_TOKEN` is exported in your shell and has the correct scopes (`repo` or `public_repo`)
- For GitHub Apps, ensure `XIPHER_APP_PRIVATE_KEY_FILE` (or `--private-key-file`) points to a valid `.pem` file and the app is installed on the organization

**Rate Limit Exceeded**
```
[RateLimiter] Sleeping...
```
- The scanner automatically handles rate limiting
- Consider using GitHub App authentication for higher limits

**No Certificates Found**
```
[INFO] No certificates found
```
- Verify the repository contains PEM-encoded certificates
- Check file extensions aren't in the skip list

---

## License

This project is licensed under the Apache License, Version 2.0.

See the full license text at:
http://www.apache.org/licenses/LICENSE-2.0

---

## Contributing

Please read [CONTRIBUTING.md](CONTRIBUTING.md) for contribution guidelines.

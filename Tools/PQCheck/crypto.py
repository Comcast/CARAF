from flask import Blueprint, render_template, request, jsonify, Response
import requests
import os
import base64
import datetime as dt
import re
from openai import AzureOpenAI
import json
import csv
import io
from html import escape
from urllib.parse import urlparse

from dependency import get_dependency_graph, analyze_dependency_crypto

# -----------------------------
# GitHub Config
# -----------------------------

API = "https://api.github.com"

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")

HEADERS = {
    "Accept": "application/vnd.github+json",
    "User-Agent": "crypto-healthscan-ai"
}

if GITHUB_TOKEN:
    HEADERS["Authorization"] = f"Bearer {GITHUB_TOKEN}"


# -----------------------------
# Azure OpenAI Config
# -----------------------------

endpoint = os.getenv("ENDPOINT_URL", "<your_endpoint_here>")
deployment = os.getenv("DEPLOYMENT_NAME", "<your_deployment_here>>")
subscription_key = os.getenv("<your_subscription_key_here>")

client = None
if subscription_key:
    client = yoursubscription(
        azure_endpoint=endpoint,
        api_key=subscription_key,
        api_version="<your_API_version>"
    )


# -----------------------------
# PQC Keywords
# -----------------------------

PQC_KEYWORDS = {
    # NIST PQC algorithms
    "kyber", "ml-kem", "mlkem",
    "dilithium", "ml-dsa", "mldsa",
    "falcon",
    "sphincs", "sphincs+",

    # other PQC candidates
    "ntru", "saber", "frodo", "frodokem",
    "mceliece", "classic-mceliece", "classic mceliece", "cmce",
    "hqc", "bike",
    "sntruprime", "ntrulprime",
    "xmss", "lms",

    # PQC integration libraries
    "liboqs", "oqs", "oqs-provider", "pqclean",

    # general PQC terms
    "post-quantum", "post quantum", "pqc", "quantum-safe",
    "quantum resistant", "quantum secure", "open quantum safe"
}


# -----------------------------
# GitHub Helper
# -----------------------------


def gh_get(url):
    try:
        # Validate URL to prevent SSRF
        parsed = urlparse(url)
        if parsed.netloc != "api.github.com":
            print("Invalid URL: not from api.github.com")
            return None
        
        r = requests.get(url, headers=HEADERS, timeout=20)

        if r.status_code != 200:
            print("GitHub API error:", r.status_code, url)
            return None

        return r.json()

    except Exception as e:
        print("GitHub request failed:", e)
        return None


# -----------------------------
# PyPI Fallback (Latest Release)
# -----------------------------


def get_pypi_latest_release(repo_name):
    """
    Attempt to infer PyPI package name from repo name
    and fetch latest release date from PyPI.
    """
    pkg_candidates = {
        repo_name.lower(),
        repo_name.replace("-", "_").lower(),
        repo_name.replace("_", "-").lower()
    }

    for pkg in pkg_candidates:
        try:
            url = f"https://pypi.org/pypi/{pkg}/json"
            r = requests.get(url, timeout=10)

            if r.status_code != 200:
                continue

            data = r.json()
            releases = data.get("releases", {})

            if not releases:
                continue

            # Get latest version by upload time
            latest_time = None
            for version, files in releases.items():
                for f in files:
                    uploaded = f.get("upload_time_iso_8601")
                    if uploaded:
                        t = dt.datetime.fromisoformat(uploaded.replace("Z", "+00:00"))
                        if not latest_time or t > latest_time:
                            latest_time = t

            if latest_time:
                return latest_time

        except Exception:
            continue

    return None


# -----------------------------
# README
# -----------------------------


def get_readme(owner, repo):
    data = gh_get(f"{API}/repos/{owner}/{repo}/readme")

    if not data:
        return ""

    return base64.b64decode(
        data["content"]
    ).decode("utf-8", "ignore").lower()


# -----------------------------
# Topics
# -----------------------------


def get_topics(owner, repo):
    data = gh_get(f"{API}/repos/{owner}/{repo}/topics")

    if not data:
        return []

    return data.get("names", [])


# -----------------------------
# Contributors
# -----------------------------


def contributors(owner, repo):
    r = requests.get(
        f"{API}/repos/{owner}/{repo}/contributors",
        params={"per_page": 1},
        headers=HEADERS
    )

    if r.status_code != 200:
        return 0

    link = r.headers.get("Link", "")

    m = re.search(r'&page=(\d+)>; rel="last"', link)

    return int(m.group(1)) if m else 1


# -----------------------------
# SECURITY.md
# -----------------------------


def has_security(owner, repo):
    paths = ["SECURITY.md", ".github/SECURITY.md"]

    for p in paths:
        r = requests.get(
            f"{API}/repos/{owner}/{repo}/contents/{p}",
            headers=HEADERS
        )

        if r.status_code == 200:
            return True

    return False


# -----------------------------
# CI Workflows
# -----------------------------


def has_ci(owner, repo):
    r = requests.get(
        f"{API}/repos/{owner}/{repo}/contents/.github/workflows",
        headers=HEADERS
    )

    return r.status_code == 200


# -----------------------------
# Latest Release
# -----------------------------


def get_latest_release(owner, repo):
    """
    Resolve latest release date using:
    1. GitHub Releases
    2. PyPI
    3. GitHub Tags
    """
    # 1️⃣ GitHub Releases
    data = gh_get(f"{API}/repos/{owner}/{repo}/releases/latest")
    if data and "published_at" in data:
        return dt.datetime.fromisoformat(
            data["published_at"].replace("Z", "+00:00")
        )

    # 2️⃣ PyPI Fallback
    pypi_date = get_pypi_latest_release(repo)
    if pypi_date:
        return pypi_date

    # 3️⃣ GitHub Tags Fallback
    tag_date = get_latest_tag_date(owner, repo)
    if tag_date:
        return tag_date

    return None


def get_latest_tag_date(owner, repo):
    tags = gh_get(f"{API}/repos/{owner}/{repo}/tags")

    if not tags:
        return None

    try:
        tag = tags[0]
        sha = tag.get("commit", {}).get("sha")
        if not sha:
            return None

        commit = gh_get(f"{API}/repos/{owner}/{repo}/git/commits/{sha}")
        if not commit:
            return None

        date = commit.get("committer", {}).get("date")
        if date:
            return dt.datetime.fromisoformat(date.replace("Z", "+00:00"))
    except:
        pass

    return None


def resolve_last_push(info, owner, repo):
    raw = info.get("pushed_at")
    if raw:
        try:
            d = dt.datetime.fromisoformat(raw.replace("Z", "+00:00"))
            return {
                "value": d,
                "source": "github.repo.pushed_at",
                "confidence": "high"
            }
        except Exception:
            pass

    raw = info.get("updated_at")
    if raw:
        try:
            d = dt.datetime.fromisoformat(raw.replace("Z", "+00:00"))
            return {
                "value": d,
                "source": "github.repo.updated_at",
                "confidence": "medium"
            }
        except Exception:
            pass

    commits = gh_get(f"{API}/repos/{owner}/{repo}/commits?per_page=1")
    if commits and isinstance(commits, list):
        try:
            date = commits[0]["commit"]["committer"]["date"]
            d = dt.datetime.fromisoformat(date.replace("Z", "+00:00"))
            return {
                "value": d,
                "source": "github.commits.latest",
                "confidence": "medium"
            }
        except Exception:
            pass

    return {
        "value": None,
        "source": "unavailable",
        "confidence": "low"
    }


def resolve_latest_release(owner, repo):
    data = gh_get(f"{API}/repos/{owner}/{repo}/releases/latest")
    if data and "published_at" in data:
        try:
            d = dt.datetime.fromisoformat(data["published_at"].replace("Z", "+00:00"))
            return {
                "value": d,
                "source": "github.releases.latest",
                "confidence": "high"
            }
        except Exception:
            pass

    # fallback: first release from releases API (can include prereleases)
    rels = gh_get(f"{API}/repos/{owner}/{repo}/releases?per_page=1")
    if rels and isinstance(rels, list):
        try:
            published = rels[0].get("published_at")
            if published:
                d = dt.datetime.fromisoformat(published.replace("Z", "+00:00"))
                return {
                    "value": d,
                    "source": "github.releases.list",
                    "confidence": "medium"
                }
        except Exception:
            pass

    pypi_date = get_pypi_latest_release(repo)
    if pypi_date:
        return {
            "value": pypi_date,
            "source": "pypi.releases",
            "confidence": "medium"
        }

    tag_date = get_latest_tag_date(owner, repo)
    if tag_date:
        return {
            "value": tag_date,
            "source": "github.tags.latest",
            "confidence": "low"
        }

    return {
        "value": None,
        "source": "unavailable",
        "confidence": "low"
    }


def resolve_contributors(owner, repo):
    # Sanitize inputs to prevent SSRF
    if not isinstance(owner, str) or not isinstance(repo, str):
        return None
    owner = owner.strip()
    repo = repo.strip()
    if not re.match(r'^[a-zA-Z0-9\-_.]+$', owner) or not re.match(r'^[a-zA-Z0-9\-_.]+$', repo):
        return None
    
    try:
        r = requests.get(
            f"{API}/repos/{owner}/{repo}/contributors",
            params={"per_page": 1, "anon": "true"},
            headers=HEADERS,
            timeout=20
        )
    except Exception:
        r = None

    if r and r.status_code == 200:
        link = r.headers.get("Link", "")
        m = re.search(r'&page=(\d+)>; rel="last"', link)
        if m:
            return {
                "value": int(m.group(1)),
                "source": "github.contributors.link_header",
                "confidence": "high"
            }

        try:
            data = r.json()
            return {
                "value": len(data) if isinstance(data, list) else 0,
                "source": "github.contributors.list",
                "confidence": "medium"
            }
        except Exception:
            pass

    # fallback: contributors stats endpoint
    stats = gh_get(f"{API}/repos/{owner}/{repo}/stats/contributors")
    if stats and isinstance(stats, list):
        return {
            "value": len(stats),
            "source": "github.stats.contributors",
            "confidence": "medium"
        }

    return {
        "value": 0,
        "source": "unavailable",
        "confidence": "low"
    }


def resolve_security_policy(owner, repo, info):
    # Validate owner and repo to prevent SSRF
    if not owner or not repo or not re.match(r'^[a-zA-Z0-9_-]+$', owner) or not re.match(r'^[a-zA-Z0-9_.-]+$', repo):
        return {
            "value": False,
            "source": "invalid_input",
            "confidence": "high"
        }
    
    # common file locations and naming variants
    paths = [
        "SECURITY.md", "SECURITY", "security.md", "security",
        ".github/SECURITY.md", ".github/security.md",
        "docs/SECURITY.md", "docs/security.md",
        "SECURITY_POLICY.md", "security-policy.md"
    ]

    for p in paths:
        try:
            r = requests.get(
                f"{API}/repos/{owner}/{repo}/contents/{p}",
                headers=HEADERS,
                timeout=20
            )
            if r.status_code == 200:
                return {
                    "value": True,
                    "source": f"repo_file:{p}",
                    "confidence": "high"
                }
        except Exception:
            continue

    # fallback: community profile endpoint
    profile = gh_get(f"{API}/repos/{owner}/{repo}/community/profile")
    if profile:
        files = profile.get("files", {})
        if files.get("security", ""):
            return {
                "value": True,
                "source": "github.community.profile.security",
                "confidence": "medium"
            }

    # fallback: security_and_analysis metadata
    sec = info.get("security_and_analysis", {}) if isinstance(info, dict) else {}
    if sec.get("secret_scanning", {}).get("status") == "enabled":
        return {
            "value": True,
            "source": "github.security_and_analysis.secret_scanning",
            "confidence": "low"
        }

    return {
        "value": False,
        "source": "no_security_policy_found",
        "confidence": "medium"
    }


def resolve_ci(owner, repo, readme):
    # Validate owner and repo to prevent SSRF
    if not re.match(r'^[a-zA-Z0-9._-]+$', owner) or not re.match(r'^[a-zA-Z0-9._-]+$', repo):
        return {
            "value": False,
            "source": "invalid_repo_format",
            "confidence": "high"
        }
    
    # 1) GitHub Actions workflows directory
    try:
        r = requests.get(
            f"{API}/repos/{owner}/{repo}/contents/.github/workflows",
            headers=HEADERS,
            timeout=20
        )
        if r.status_code == 200:
            return {
                "value": True,
                "source": "github_actions.workflows_dir",
                "confidence": "high"
            }
    except Exception:
        pass

    # 2) other common CI config files
    ci_files = [
        ".travis.yml",
        ".circleci/config.yml",
        "Jenkinsfile",
        "azure-pipelines.yml",
        ".gitlab-ci.yml",
        "buildkite.yml"
    ]

    for p in ci_files:
        try:
            r = requests.get(
                f"{API}/repos/{owner}/{repo}/contents/{p}",
                headers=HEADERS,
                timeout=20
            )
            if r.status_code == 200:
                return {
                    "value": True,
                    "source": f"ci_config:{p}",
                    "confidence": "medium"
                }
        except Exception:
            continue

    # 3) README badge fallback
    ci_terms = ["github actions", "build status", "ci", "travis", "circleci", "jenkins"]
    if readme and any(t in readme for t in ci_terms):
        return {
            "value": True,
            "source": "readme_ci_badge_or_text",
            "confidence": "low"
        }

    return {
        "value": False,
        "source": "no_ci_signal_found",
        "confidence": "medium"
    }


# -----------------------------
# Search repo code for PQC
# -----------------------------


def search_repo_code(owner, repo):
    found = set()

    crypto_paths = [
        "crypto", "tls", "ssl", "kem", "sign",
        "cipher", "provider", "oqs"
    ]

    for kw in PQC_KEYWORDS:
        url = f"{API}/search/code?q={kw}+in:file+repo:{owner}/{repo}"

        data = gh_get(url)

        if data and "items" in data:
            for item in data["items"]:
                path = item.get("path", "").lower()

                # ensure match is in crypto-related directory
                if any(p in path for p in crypto_paths):
                    found.add(kw)
                    break

    return list(found)


# -----------------------------
# PQC Detection
# -----------------------------


def pqc_detect(owner, repo, readme):
    detected_readme = [k for k in PQC_KEYWORDS if k in readme]
    detected_code = search_repo_code(owner, repo)

    detected = list(set(detected_readme + detected_code))

    native_algorithms = {
        "kyber", "ml-kem", "mlkem",
        "dilithium", "ml-dsa", "mldsa",
        "falcon",
        "sphincs", "sphincs+",
        "ntru", "saber", "frodo", "frodokem",
        "mceliece", "classic-mceliece", "classic mceliece", "cmce",
        "hqc", "bike", "sntruprime", "ntrulprime",
        "xmss", "lms"
    }

    integration_libs = {
        "liboqs", "oqs", "oqs-provider"
    }

    native_found = [a for a in native_algorithms if a in detected]
    integration_found = [a for a in integration_libs if a in detected]

    repo_name = repo.lower()

    # repos that actually implement PQC algorithms
    native_repos = {
        "pqclean",
        "liboqs"
    }

    # frameworks that integrate PQC providers
    integration_frameworks = {
        "openssl",
        "wolfssl",
        "boringssl"
    }

    if repo_name in native_repos:
        category = "Native PQC implementation"

    elif repo_name in integration_frameworks:
        category = "Integration PQC"

    elif integration_found:
        category = "Integration PQC"

    elif "hybrid" in readme:
        category = "Hybrid PQC"

    elif native_found:
        category = "Experimental PQC"

    else:
        category = "No PQC"

    pqc = "Yes" if category != "No PQC" else "No"

    return pqc, category, detected


# -----------------------------
# Maintenance Rating
# -----------------------------


def rate(repo, release, contrib, sec, ci):
    now = dt.datetime.now(dt.timezone.utc)

    pushed_raw = repo.get("pushed_at") or repo.get("updated_at")
    if pushed_raw:
        pushed = dt.datetime.fromisoformat(
            pushed_raw.replace("Z", "+00:00")
        )
    else:
        # Unknown push date is treated as stale to avoid false "well-maintained".
        pushed = now - dt.timedelta(days=3650)

    days_push = (now - pushed).days
    days_rel = (now - release).days if release else 9999

    score = sum([
        days_push <= 90,
        days_rel <= 180,
        contrib >= 3,
        ci,
        sec
    ])

    if score >= 4:
        return "well-maintained"
    elif score >= 2:
        return "maintained"
    else:
        return "at-risk"


def build_evaluation_payload(info, release, contrib, ci, sec, pqc, category, crypto_deps, last_push_dt=None):
    now = dt.datetime.now(dt.timezone.utc)

    if last_push_dt:
        pushed = last_push_dt
    else:
        pushed = dt.datetime.fromisoformat(
            info["pushed_at"].replace("Z", "+00:00")
        )

    days_push = (now - pushed).days
    days_release = (now - release).days if release else None

    return {
        "maintenance_criteria": {
            "recent_commit_days": days_push,
            "recent_release_days": days_release,
            "contributors": contrib,
            "has_ci": ci,
            "has_security_policy": sec
        },
        "pqc_signals": {
            "pqc_declared": pqc,
            "pqc_category": category,
            "crypto_dependencies": crypto_deps
        }
    }


# -----------------------------
# Analyzer
# -----------------------------


def analyze(fullname):
    # -----------------------------
    # Input Validation
    # -----------------------------
    if not fullname:
        return {"error": "Repository name is required"}

    fullname = fullname.strip()

    # remove github url if user pasted full link
    fullname = fullname.replace("https://github.com/", "")
    fullname = fullname.replace("http://github.com/", "")
    fullname = fullname.replace("github.com/", "")

    if "/" not in fullname:
        return {"error": "Invalid format. Use owner/repo"}

    try:
        owner, repo = fullname.split("/")[:2]
    except:
        return {"error": "Invalid format owner/repo"}

    # -----------------------------
    # Fetch Repository Info
    # -----------------------------
    info = gh_get(f"{API}/repos/{owner}/{repo}")

    if not info:
        return {"error": "Repo not found or GitHub API limit reached"}

    # -----------------------------
    # README + PQC Detection
    # -----------------------------
    readme = get_readme(owner, repo)

    pqc, category, detected = pqc_detect(owner, repo, readme)

    # -----------------------------
    # Release Information
    # -----------------------------
    release_info = resolve_latest_release(owner, repo)
    release = release_info["value"]

    # -----------------------------
    # Dependencies
    # -----------------------------
    deps = get_dependency_graph(owner, repo)

    crypto_deps = analyze_dependency_crypto(deps)

    # -----------------------------
    # Repository Metadata
    # -----------------------------
    last_push_info = resolve_last_push(info, owner, repo)
    last_push_dt = last_push_info["value"]
    last_push = last_push_dt.strftime("%Y-%m-%d") if last_push_dt else "Unknown"

    latest_release = (
        release.strftime("%Y-%m-%d") if release else "None"
    )

    contrib_info = resolve_contributors(owner, repo)
    contrib_count = contrib_info["value"]

    security_info = resolve_security_policy(owner, repo, info)
    security_file = security_info["value"]

    ci_info = resolve_ci(owner, repo, readme)
    ci_status = ci_info["value"]

    metric_sources = {
        "last_push": {
            "source": last_push_info["source"],
            "confidence": last_push_info["confidence"]
        },
        "latest_release": {
            "source": release_info["source"],
            "confidence": release_info["confidence"]
        },
        "contributors": {
            "source": contrib_info["source"],
            "confidence": contrib_info["confidence"]
        },
        "ci": {
            "source": ci_info["source"],
            "confidence": ci_info["confidence"]
        },
        "security": {
            "source": security_info["source"],
            "confidence": security_info["confidence"]
        }
    }

    rating_value = rate(
        info,
        release,
        contrib_count,
        security_file,
        ci_status
    )

    evaluation_payload = build_evaluation_payload(
        info=info,
        release=release,
        contrib=contrib_count,
        ci=ci_status,
        sec=security_file,
        pqc=pqc,
        category=category,
        crypto_deps=crypto_deps,
        last_push_dt=last_push_dt
    )

    evaluation_payload["maintenance_criteria_sources"] = metric_sources

    ai_assessment = analyze_repo_with_ai(
        repo=f"{owner}/{repo}",
        evaluation=evaluation_payload
    )

    # -----------------------------
    # Final Result
    # -----------------------------
    return {
        "repo": f"{owner}/{repo}",

        "rating": rating_value,

        "last_push": last_push,
        "latest_release": latest_release,

        "contributors": contrib_count,
        "security": security_file,
        "ci": ci_status,

        "pqc": pqc,
        "category": category,
        "pqc_info": category,

        "detected": ", ".join(detected) if detected else "None",

        "topics": ", ".join(get_topics(owner, repo)[:8]),

        "dependency_count": len(deps),
        "dependencies": deps,
        "crypto_dependencies": crypto_deps,
        "metric_sources": metric_sources,

        # ✅ NEW
        "ai_evaluation_input": evaluation_payload,
        "ai_assessment": ai_assessment
    }


# -----------------------------
# AI Repo Assistant
# -----------------------------


def ask_ai(repo, msg):
    if not client:
        return "Azure OpenAI is not configured. Set AZURE_OPENAI_API_KEY to enable AI responses."

    prompt = f"""
Repository: {repo}

Answer the question about this repository.

Question: {msg}
"""

    res = client.chat.completions.create(
        model=deployment,
        messages=[{"role": "user", "content": prompt}],
        max_tokens=400
    )

    return res.choices[0].message.content


def analyze_repo_with_ai(repo, evaluation):
    if not client:
        return "Azure OpenAI is not configured. Set AZURE_OPENAI_API_KEY to enable AI assessment."

    prompt = f"""
You are a cryptography and open-source risk assessor.

Repository: {repo}

Below is a structured evaluation extracted from GitHub metadata.

Evaluation Data (JSON):
{json.dumps(evaluation, indent=2)}

Your tasks:
1. Decide whether this repository is WELL-MAINTAINED, PARTIALLY MAINTAINED, or AT RISK.
2. Explain your reasoning using the 5 maintenance criteria.
3. Assess the repository's Post-Quantum Cryptography (PQC) readiness:
   - Not Ready
   - Experimental
   - Integration Ready
   - Production Ready
4. Estimate a realistic timeline (in years) for PQC support maturity.
5. Based on maintenance + PQC readiness, decide migration urgency:
    - Keep (no migration needed now)
    - Plan migration (6-18 months)
    - Migrate soon (0-6 months)
6. If PQC support is weak or missing, suggest 2-3 similar libraries/projects that are better aligned for PQC adoption.
7. Provide a concise executive summary (5-7 lines).

Be precise, realistic, and conservative.
"""

    res = client.chat.completions.create(
        model=deployment,
        messages=[{"role": "user", "content": prompt}],
        max_tokens=800
    )

    return res.choices[0].message.content


crypto_bp = Blueprint("crypto_bp", __name__)


def _crypto_csv(result):
        out = io.StringIO()
        writer = csv.writer(out)

        writer.writerow(["section", "field", "value"])

        scalar_fields = [
                "repo", "rating", "last_push", "latest_release", "contributors",
                "security", "ci", "pqc", "category", "pqc_info", "detected", "topics",
                "dependency_count"
        ]

        for key in scalar_fields:
                writer.writerow(["summary", key, result.get(key, "")])

        for dep in result.get("dependencies", []):
                writer.writerow([
                        "dependencies",
                        dep.get("name", ""),
                        dep.get("version", "")
                ])

        for cdep in result.get("crypto_dependencies", []):
                writer.writerow([
                        "crypto_dependencies",
                        cdep.get("name", ""),
                        json.dumps(cdep, ensure_ascii=True)
                ])

        for metric, meta in (result.get("metric_sources", {}) or {}).items():
            writer.writerow([
                "metric_sources",
                metric,
                f"source={meta.get('source', '')}; confidence={meta.get('confidence', '')}"
            ])

        writer.writerow(["ai", "assessment", result.get("ai_assessment", "")])

        return out.getvalue()


def _crypto_html(result):
    criteria = result.get("ai_evaluation_input", {}).get("maintenance_criteria", {})
    sources = result.get("metric_sources", {})

    return """<!DOCTYPE html>
<html>
<head>
    <meta charset=\"utf-8\" />
    <title>Crypto Analysis Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; padding: 24px; }}
        .card {{ border: 1px solid #ddd; border-radius: 8px; padding: 16px; margin-top: 16px; }}
        pre {{ white-space: pre-wrap; background: #f8fafc; padding: 12px; border-radius: 8px; }}
    </style>
</head>
<body>
    <h1>Crypto Repository Analysis</h1>

    <div class=\"card\">
        <p><b>Repository:</b> {repo}</p>
        <p><small>source: {last_push_source} ({last_push_conf})</small></p>
        <p><b>Rating:</b> {rating}</p>
        <p><small>source: {latest_release_source} ({latest_release_conf})</small></p>
        <p><b>PQC Category:</b> {category}</p>
        <p><small>source: {contributors_source} ({contributors_conf})</small></p>
    </div>
        <p><small>source: {ci_source} ({ci_conf})</small></p>

        <p><small>source: {security_source} ({security_conf})</small></p>
    <div class=\"card\">
        <p><b>Last Push:</b> {last_push}</p>
        <p><b>Latest Release:</b> {latest_release}</p>
        <p><b>Contributors:</b> {contributors}</p>
        <p><b>CI:</b> {ci}</p>
        <p><b>Security Policy:</b> {security}</p>
        <p><b>Detected PQC:</b> {detected}</p>
    </div>

    <div class=\"card\">
        <h2>AI Assessment</h2>
        <pre>{ai_assessment}</pre>
    </div>

    <div class=\"card\">
        <h2>Evaluation Criteria</h2>
        <ul>
            <li>Days since commit: {recent_commit_days}</li>
            <li>Days since release: {recent_release_days}</li>
            <li>Contributors: {criteria_contributors}</li>
            <li>CI enabled: {criteria_ci}</li>
            <li>Security policy: {criteria_security}</li>
        </ul>
    </div>
</body>
</html>
""".format(
        repo=escape(str(result.get("repo", ""))),
        rating=escape(str(result.get("rating", ""))),
        category=escape(str(result.get("category", ""))),
        last_push=escape(str(result.get("last_push", ""))),
        latest_release=escape(str(result.get("latest_release", ""))),
        contributors=escape(str(result.get("contributors", ""))),
        ci=escape(str(result.get("ci", ""))),
        security=escape(str(result.get("security", ""))),
        detected=escape(str(result.get("detected", ""))),
        ai_assessment=escape(str(result.get("ai_assessment", ""))),
        recent_commit_days=escape(str(criteria.get("recent_commit_days", ""))),
        recent_release_days=escape(str(criteria.get("recent_release_days", ""))),
        criteria_contributors=escape(str(criteria.get("contributors", ""))),
        criteria_ci=escape(str(criteria.get("has_ci", ""))),
        criteria_security=escape(str(criteria.get("has_security_policy", ""))),
        last_push_source=escape(str(sources.get("last_push", {}).get("source", ""))),
        last_push_conf=escape(str(sources.get("last_push", {}).get("confidence", ""))),
        latest_release_source=escape(str(sources.get("latest_release", {}).get("source", ""))),
        latest_release_conf=escape(str(sources.get("latest_release", {}).get("confidence", ""))),
        contributors_source=escape(str(sources.get("contributors", {}).get("source", ""))),
        contributors_conf=escape(str(sources.get("contributors", {}).get("confidence", ""))),
        ci_source=escape(str(sources.get("ci", {}).get("source", ""))),
        ci_conf=escape(str(sources.get("ci", {}).get("confidence", ""))),
        security_source=escape(str(sources.get("security", {}).get("source", ""))),
        security_conf=escape(str(sources.get("security", {}).get("confidence", "")))
    )

@crypto_bp.route("/crypto", methods=["GET", "POST"])
def crypto():
    result = None

    if request.method == "POST":
        repo = request.form.get("repo", "").strip()

        # convert full GitHub URL if user pasted it
        repo = repo.replace("https://github.com/", "")
        repo = repo.replace("http://github.com/", "")
        repo = repo.replace("github.com/", "")

        if not repo or "/" not in repo:
            result = {"error": "Invalid format. Use owner/repo"}
        else:
            result = analyze(repo)

    return render_template("crypto.html", result=result)


@crypto_bp.route("/repo_crypto", methods=["POST"])
def repo_crypto():
    data = request.get_json()
    repo = data.get("repo")

    result = analyze(repo)

    return jsonify(result)


@crypto_bp.route("/crypto/export/csv", methods=["POST"])
def crypto_export_csv():
    payload = request.get_json() or {}
    result = payload.get("result", {})
    content = _crypto_csv(result)

    return Response(
        content,
        mimetype="text/csv",
        headers={
            "Content-Disposition": "attachment; filename=crypto_analysis.csv"
        }
    )


@crypto_bp.route("/crypto/export/html", methods=["POST"])
def crypto_export_html():
    payload = request.get_json() or {}
    result = payload.get("result", {})
    content = _crypto_html(result)

    return Response(
        content,
        mimetype="text/html",
        headers={
            "Content-Disposition": "attachment; filename=crypto_analysis.html"
        }
    )

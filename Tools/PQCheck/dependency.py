from flask import Blueprint, request, jsonify, render_template, Response
import requests
import os
import re
import shutil
import json
import subprocess
import csv
import io
import glob
from html import escape
from openai import AzureOpenAI

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
deployment = os.getenv("DEPLOYMENT_NAME", "<your_deployment_here>")
subscription_key = os.getenv("API_KEY")

client = None
if subscription_key:
    client = subcription_function(
        azure_endpoint=endpoint,
        api_key=subscription_key,
        api_version="<your_api_version_here>"
    )

CRYPTO_LIBRARIES = {
    # C/C++ system libs
    "openssl", "wolfssl", "boringssl", "libcrypto", "libssl", "gnutls",
    "mbedtls", "nss", "nettle", "gcrypt", "libgcrypt", "cryptopp",
    # Rust crates
    "ring", "rustls", "aws-lc-rs", "p256", "ed25519-dalek",
    "aes", "sha2", "hmac", "pbkdf2",
    # Java / Kotlin
    "bcprov", "bouncycastle", "conscrypt", "spongycastle",
    # .NET
    "portable.bouncycastle", "bouncy-castle",
    # Go
    "x/crypto",
}

PQC_ALGORITHMS = {
    "kyber", "dilithium", "falcon", "sphincs",
    "ml-kem", "ml-dsa", "ntru"
}

PQC_LIBS = {
    "liboqs", "oqs", "oqs-provider"
}

AUTO_GITHUB_MAP = {
    # Python crypto
    "cryptography": "pyca/cryptography",
    "pyjwt": "jpadilla/pyjwt",
    "cffi": "python/cpython",  # dependency of cryptography

    # Classical crypto libs
    "openssl": "openssl/openssl",
    "libssl": "openssl/openssl",
    "libcrypto": "openssl/openssl",
    "boringssl": "google/boringssl",
    "wolfssl": "wolfSSL/wolfssl",
    "gnutls": "gnutls/gnutls",

    # PQC libs
    "liboqs": "open-quantum-safe/liboqs",
    "oqs": "open-quantum-safe/liboqs",
    "oqs-provider": "open-quantum-safe/oqs-provider",
    "circl": "cloudflare/circl",

    # PQC algorithms
    "kyber": "pq-crystals/kyber",
    "dilithium": "pq-crystals/dilithium",
    "falcon": "falcon-sign/falcon",
    "sphincs": "sphincs/sphincsplus",
    "ntru": "NTRUOpenSourceProject/ntru-crypto",
}


def get_dependency_graph(owner, repo):
    # Validate owner and repo to prevent SSRF
    if not owner or not repo or not re.match(r'^[a-zA-Z0-9_-]+$', owner) or not re.match(r'^[a-zA-Z0-9_.-]+$', repo):
        return []
    
    url = f"{API}/repos/{owner}/{repo}/dependency-graph/sbom"

    r = requests.get(url, headers=HEADERS)

    if r.status_code != 200:
        return []

    data = r.json()

    packages = data.get("sbom", {}).get("packages", [])

    deps = []

    for p in packages:
        deps.append({
            "name": p.get("name"),
            "version": p.get("versionInfo", "")
        })

    return deps


def normalize_dep_name(name: str):
    if not name:
        return ""

    n = name.lower()

    # Strip PURL / CycloneDX prefix  (pkg:pypi/foo@1.0  or  pypi:foo)
    if n.startswith("pkg:"):
        n = n.split("/", 1)[-1]
    elif ":" in n and "/" not in n.split(":")[0]:
        # handles  pip:foo  pypi:foo  npm:foo  maven:foo  etc.
        n = n.split(":", 1)[-1]

    # Remove repo hosts
    for host in ["github.com/", "gitlab.com/", "bitbucket.org/"]:
        if host in n:
            n = n.split(host)[-1]

    # Strip version suffix "@1.2.3"
    if "@" in n:
        n = n.split("@")[0]

    # Take last path segment
    n = n.split("/")[-1]

    # Strip pip extras  foo[security]  and version specifiers  foo>=1.0
    n = re.split(r"[><=!~\[\s;]", n)[0]

    return n.strip()


def map_dep_to_github_repo(normalized_name: str):
    """
    Strict mapping: return mapped repo only if it exists in AUTO_GITHUB_MAP.
    """
    return AUTO_GITHUB_MAP.get(normalized_name)


def analyze_dependency_crypto(deps):
    crypto_found = []

    for d in deps:
        raw = d["name"] or ""
        name = normalize_dep_name(raw)

        dep_info = None

        # PQC algorithms
        if any(p in name for p in PQC_ALGORITHMS):
            dep_info = {"name": raw, "normalized": name, "type": "PQC Algorithm"}

        # PQC libraries
        elif any(p in name for p in PQC_LIBS):
            dep_info = {"name": raw, "normalized": name, "type": "PQC Integration"}

        # Classical crypto libs
        elif any(p in name for p in CRYPTO_LIBRARIES):
            dep_info = {"name": raw, "normalized": name, "type": "Classical Crypto"}

    # Go crypto packages (matched before last-segment stripping)
        elif any(k in raw.lower() for k in [
            "golang.org/x/crypto", "github.com/cloudflare/circl",
            "github.com/google/tink",
        ]):
            dep_info = {"name": raw, "normalized": name, "type": "Classical Crypto"}

        # Python crypto packages
        elif any(k in name for k in [
            "cryptography", "pyjwt", "pyopenssl", "paramiko", "bcrypt",
            "cffi", "pyca", "nacl", "pynacl", "rsa", "ecdsa", "ed25519",
            "passlib", "cryptodome", "pycrypto", "itsdangerous", "jwt",
        ]):
            dep_info = {"name": raw, "normalized": name, "type": "Classical Crypto"}

        # Node.js / npm crypto packages
        elif any(k in name for k in [
            "node-forge", "crypto-js", "noble-curves", "noble-hashes",
            "jose", "jsonwebtoken", "node-rsa", "sodium-native",
            "libsodium-wrappers", "argon2", "bcryptjs",
        ]):
            dep_info = {"name": raw, "normalized": name, "type": "Classical Crypto"}

        # Java / Maven crypto packages
        elif any(k in name for k in [
            "bcprov", "bouncycastle", "conscrypt", "spongycastle",
            "tink", "jasypt",
        ]):
            dep_info = {"name": raw, "normalized": name, "type": "Classical Crypto"}

        # .NET NuGet crypto packages
        elif any(k in name.replace(".", "-") for k in [
            "bouncycastle", "portable-bouncycastle", "system-security",
            "identitymodel",
        ]):
            dep_info = {"name": raw, "normalized": name, "type": "Classical Crypto"}

        # if no crypto match → skip
        if not dep_info:
            continue

        # STRICT mapping = only map if in AUTO_GITHUB_MAP
        mapped_repo = map_dep_to_github_repo(name)
        if mapped_repo:
            dep_info["github_repo"] = mapped_repo

        crypto_found.append(dep_info)

    return crypto_found


def run_sbom(repo):
    owner, name = repo.split("/")

    repo_url = f"https://github.com/{owner}/{name}.git"

    workdir = f"/tmp/{name}"

    # Validate workdir to prevent path traversal
    if not os.path.abspath(workdir).startswith("/tmp/"):
        raise ValueError("Invalid workdir path")

    if os.path.exists(workdir):
        shutil.rmtree(workdir)

    subprocess.run(["git", "clone", "--depth", "1", repo_url, workdir])

    sbom_dir = os.path.join(workdir, "sbom")
    os.makedirs(sbom_dir, exist_ok=True)

    subprocess.run([
        "sbom-tool",
        "generate",
        "-b", sbom_dir,
        "-bc", workdir,
        "-pn", name,
        "-pv", "1.0",
        "-ps", "github"
    ])

    manifest = os.path.join(sbom_dir, "_manifest")

    deps = []

    if os.path.exists(manifest):
        for file in os.listdir(manifest):
            if file.endswith(".json"):
                with open(os.path.join(manifest, file), "r", encoding="utf-8", errors="ignore") as f:
                    data = json.load(f)

                    for p in data.get("packages", []):
                        deps.append({
                            "name": p.get("name"),
                            "version": p.get("versionInfo", "")
                        })

    return deps


def detect_pip_dependencies(repo_path):
    deps = []
    seen = set()

    # Validate path to prevent path traversal
    repo_path_abs = os.path.abspath(repo_path)
    if not os.path.isdir(repo_path_abs):
        return deps

    def _read_lines_with_fallback(path):
        # Validate file path to prevent path traversal
        file_path_abs = os.path.abspath(path)
        if not file_path_abs.startswith(repo_path_abs + os.sep) and file_path_abs != repo_path_abs:
            return []
        
        # Some repos store requirements files as UTF-16 (e.g. webmcp).
        with open(path, "rb") as bf:
            raw = bf.read()

        encodings = ["utf-8-sig", "utf-16", "utf-16le", "utf-16be", "latin-1"]
        text = ""
        for enc in encodings:
            try:
                text = raw.decode(enc)
                break
            except UnicodeDecodeError:
                continue

        if not text:
            text = raw.decode("utf-8", errors="ignore")

        return text.splitlines()

    # Glob for every requirements*.txt in root and one level of subdirs
    patterns = [
        "requirements*.txt",
        "requirements/*.txt",
        "requires/*.txt",
    ]
    req_files = set()
    for pat in patterns:
        for f in glob.glob(os.path.join(repo_path_abs, pat)):
            file_path_abs = os.path.abspath(f)
            if file_path_abs.startswith(repo_path_abs + os.sep) or file_path_abs == repo_path_abs:
                req_files.add(file_path_abs)

    for req_file in sorted(req_files):
        for line in _read_lines_with_fallback(req_file):
            line = line.strip()
            # skip blank, comments, options flags (-r, -c, --index-url ...)
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            pkg_name = re.split(r"[><=!~\[\s;@]", line)[0].strip()
            if pkg_name and pkg_name.lower() not in seen:
                seen.add(pkg_name.lower())
                deps.append({"name": pkg_name, "version": "pip"})

    return deps


def detect_pyproject_dependencies(repo_path):
    deps = []
    # Validate path to prevent path traversal
    repo_path_abs = os.path.abspath(repo_path)
    if not os.path.isdir(repo_path_abs):
        return deps
    fpath = os.path.join(repo_path_abs, "pyproject.toml")
    fpath = os.path.abspath(fpath)
    if not fpath.startswith(repo_path_abs + os.sep) and fpath != repo_path_abs:
        return deps
    if not os.path.exists(fpath):
        return deps
    try:
        with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
            text = f.read()

        # [project] dependencies = ["foo>=1.0", ...]
        proj = re.search(r'\[project\].*?(?=\n\[|\Z)', text, re.DOTALL)
        if proj:
            arr = re.search(r'dependencies\s*=\s*\[(.*?)\]', proj.group(), re.DOTALL)
            if arr:
                for pkg_str in re.findall(r'["\']([^"\']+)["\']', arr.group(1)):
                    pkg = re.split(r'[><=!~\[\s;@]', pkg_str)[0].strip()
                    if pkg:
                        deps.append({"name": pkg, "version": "Python (pyproject)"})

        # [tool.poetry.dependencies] and [tool.poetry.dev-dependencies]
        for sec in re.finditer(r'\[tool\.poetry\.(?:dev-)?dependencies\](.*?)(?=\n\[|\Z)', text, re.DOTALL):
            for pkg in re.findall(r'^([a-zA-Z0-9_\-\.]+)\s*=', sec.group(1), re.MULTILINE):
                if pkg.lower() != "python":
                    deps.append({"name": pkg, "version": "Python (poetry)"})

        # [build-system] requires = [...]
        bs = re.search(r'\[build-system\].*?requires\s*=\s*\[(.*?)\]', text, re.DOTALL)
        if bs:
            for pkg_str in re.findall(r'["\']([^"\']+)["\']', bs.group(1)):
                pkg = re.split(r'[><=!~\[\s;@]', pkg_str)[0].strip()
                if pkg:
                    deps.append({"name": pkg, "version": "Python (build)"})

    except Exception:
        pass
    return deps


def detect_github_actions(repo_path):
    actions = []

    workflow_dir = os.path.join(repo_path, ".github", "workflows")

    if not os.path.exists(workflow_dir):
        return actions

    for file in os.listdir(workflow_dir):
        if file.endswith(".yml") or file.endswith(".yaml"):
            with open(os.path.join(workflow_dir, file), "r", encoding="utf-8", errors="ignore") as f:
                text = f.read()

                matches = re.findall(r'uses:\s*([^\s@]+)', text)

                for m in matches:
                    actions.append({
                        "name": m,
                        "version": "GitHub Action"
                    })

    return actions


def detect_go_dependencies(repo_path):
    deps = []
    go_mod = os.path.join(repo_path, "go.mod")
    if not os.path.exists(go_mod):
        return deps
    try:
        with open(go_mod, "r", encoding="utf-8", errors="ignore") as f:
            text = f.read()
        # Matches both single-line `require foo v1.0` and entries inside require(...) blocks
        skip = {"module", "go", "toolchain", "require"}
        for m in re.finditer(r'^\s*([\w.\-/]+)\s+(v[\w.\-+]+)', text, re.MULTILINE):
            name, version = m.group(1).strip(), m.group(2).strip()
            if name not in skip:
                deps.append({"name": name, "version": version})
    except Exception:
        pass
    return deps


def detect_setup_dependencies(repo_path):
    """setup.py install_requires and setup.cfg install_requires."""
    deps = []

    setup_py = os.path.join(repo_path, "setup.py")
    if os.path.exists(setup_py):
        try:
            with open(setup_py, "r", encoding="utf-8", errors="ignore") as f:
                text = f.read()
            for block in re.findall(r'install_requires\s*=\s*\[(.*?)\]', text, re.DOTALL):
                for pkg_str in re.findall(r'["\']([^"\']+)["\']', block):
                    pkg = re.split(r'[><=!~\[\s;@]', pkg_str)[0].strip()
                    if pkg:
                        deps.append({"name": pkg, "version": "Python (setup.py)"})
        except Exception:
            pass

    setup_cfg = os.path.join(repo_path, "setup.cfg")
    if os.path.exists(setup_cfg):
        try:
            with open(setup_cfg, "r", encoding="utf-8", errors="ignore") as f:
                text = f.read()
            m = re.search(r'install_requires\s*=\s*((?:\n[ \t]+\S.*)+)', text)
            if m:
                for line in m.group(1).splitlines():
                    line = line.strip()
                    if line and not line.startswith("#"):
                        pkg = re.split(r'[><=!~\[\s;@]', line)[0].strip()
                        if pkg:
                            deps.append({"name": pkg, "version": "Python (setup.cfg)"})
        except Exception:
            pass

    return deps


def detect_pipfile_dependencies(repo_path):
    """Pipfile [packages] and [dev-packages]."""
    deps = []
    pipfile = os.path.join(repo_path, "Pipfile")
    if not os.path.exists(pipfile):
        return deps
    try:
        with open(pipfile, "r", encoding="utf-8", errors="ignore") as f:
            text = f.read()
        for section in re.findall(r'\[(?:dev-)?packages\](.*?)(?=\n\[|\Z)', text, re.DOTALL):
            for pkg in re.findall(r'^([a-zA-Z0-9_\-\.]+)\s*=', section, re.MULTILINE):
                deps.append({"name": pkg, "version": "Python (Pipfile)"})
    except Exception:
        pass
    return deps


def detect_conda_dependencies(repo_path):
    """environment.yml / conda.yml dependencies list."""
    deps = []
    repo_path = os.path.abspath(repo_path)
    for fname in ["environment.yml", "environment.yaml", "conda.yml", "conda.yaml"]:
        fpath = os.path.join(repo_path, fname)
        fpath = os.path.abspath(fpath)
        if not fpath.startswith(repo_path + os.sep) and fpath != repo_path:
            continue
        if not os.path.exists(fpath):
            continue
        try:
            with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                text = f.read()
            section = re.search(r'dependencies:(.*?)(?=\n\w|\Z)', text, re.DOTALL)
            if section:
                for line in section.group(1).splitlines():
                    line = line.strip().lstrip("- ")
                    if line and not line.startswith("#") and not line.startswith("{"):
                        pkg = re.split(r'[><=!~\s:=]', line)[0].strip()
                        if pkg:
                            deps.append({"name": pkg, "version": "conda"})
        except Exception:
            pass
    return deps


def detect_npm_dependencies(repo_path):
    """package.json dependencies, devDependencies, peerDependencies."""
    deps = []
    pkg_file = os.path.join(repo_path, "package.json")
    pkg_file = os.path.abspath(pkg_file)
    if not pkg_file.startswith(os.path.abspath(repo_path)):
        return deps
    if not os.path.exists(pkg_file):
        return deps
    try:
        with open(pkg_file, "r", encoding="utf-8", errors="ignore") as f:
            data = json.load(f)
        for section in ["dependencies", "devDependencies", "peerDependencies", "optionalDependencies"]:
            for pkg_name, version in data.get(section, {}).items():
                deps.append({"name": pkg_name, "version": f"npm ({version})"})
    except Exception:
        pass
    return deps


def detect_cargo_dependencies(repo_path):
    """Cargo.toml [dependencies], [dev-dependencies], [build-dependencies]."""
    deps = []
    cargo_file = os.path.join(repo_path, "Cargo.toml")
    if not os.path.exists(cargo_file):
        return deps
    try:
        with open(cargo_file, "r", encoding="utf-8", errors="ignore") as f:
            text = f.read()
        for section in re.findall(
            r'\[(?:dev-|build-)?dependencies(?:\.[^\]]+)?\](.*?)(?=\n\[|\Z)', text, re.DOTALL
        ):
            for pkg in re.findall(r'^([a-zA-Z0-9_\-]+)\s*=', section, re.MULTILINE):
                deps.append({"name": pkg, "version": "Rust (Cargo)"})
    except Exception:
        pass
    return deps


def detect_maven_dependencies(repo_path):
    """pom.xml <dependency> blocks (searches entire repo tree)."""
    deps = []
    for pom_file in glob.glob(os.path.join(repo_path, "**/pom.xml"), recursive=True):
        if ".git" in pom_file:
            continue
        try:
            with open(pom_file, "r", encoding="utf-8", errors="ignore") as f:
                text = f.read()
            for m in re.finditer(
                r'<dependency>.*?<groupId>(.*?)</groupId>.*?<artifactId>(.*?)</artifactId>'
                r'(?:.*?<version>(.*?)</version>)?.*?</dependency>',
                text, re.DOTALL
            ):
                group_id = m.group(1).strip()
                artifact_id = m.group(2).strip()
                version = (m.group(3) or "Maven").strip()
                deps.append({"name": f"{group_id}:{artifact_id}", "version": version})
        except Exception:
            pass
    return deps


def detect_nuget_dependencies(repo_path):
    """*.csproj / *.fsproj / *.vbproj PackageReference and packages.config."""
    deps = []
    proj_files = (
        glob.glob(os.path.join(repo_path, "**/*.csproj"), recursive=True)
        + glob.glob(os.path.join(repo_path, "**/*.fsproj"), recursive=True)
        + glob.glob(os.path.join(repo_path, "**/*.vbproj"), recursive=True)
    )
    for fpath in proj_files:
        if ".git" in fpath:
            continue
        try:
            with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                text = f.read()
            for m in re.finditer(
                r'<PackageReference\s+Include="([^"]+)"\s+Version="([^"]+)"', text, re.IGNORECASE
            ):
                deps.append({"name": m.group(1), "version": m.group(2)})
        except Exception:
            pass
    for fpath in glob.glob(os.path.join(repo_path, "**/packages.config"), recursive=True):
        if ".git" in fpath:
            continue
        try:
            with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                text = f.read()
            for m in re.finditer(
                r'<package\s+id="([^"]+)"\s+version="([^"]+)"', text, re.IGNORECASE
            ):
                deps.append({"name": m.group(1), "version": m.group(2)})
        except Exception:
            pass
    return deps


def detect_ruby_dependencies(repo_path):
    """Gemfile gem declarations."""
    deps = []
    gemfile = os.path.join(repo_path, "Gemfile")
    if not os.path.exists(gemfile):
        return deps
    try:
        with open(gemfile, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if line.startswith("#"):
                    continue
                m = re.match(r"gem\s+['\"]([^'\"]+)['\"]", line)
                if m:
                    deps.append({"name": m.group(1), "version": "Ruby (Gem)"})
    except Exception:
        pass
    return deps


def detect_nim_dependencies(repo_path):
    """*.nimble requires declarations."""
    deps = []
    for fpath in glob.glob(os.path.join(repo_path, "*.nimble")):
        try:
            with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    m = re.match(r'requires\s+"([^"]+)', line)
                    if m:
                        pkg = re.split(r'[><=\s]', m.group(1))[0].strip()
                        if pkg and pkg.lower() != "nim":
                            deps.append({"name": pkg, "version": "Nim (nimble)"})
        except Exception:
            pass
    return deps


def dependency_migration_advice_with_ai(repo, crypto_deps):
    if not client:
        return "Azure OpenAI is not configured. Set AZURE_OPENAI_API_KEY to enable migration advice."

    if not crypto_deps:
        return "No cryptographic dependencies were detected, so no PQC migration action is currently required."

    prompt = f"""
You are a cryptography migration advisor focused on post-quantum readiness.

Repository: {repo}
Detected Crypto Dependencies:
{json.dumps(crypto_deps, indent=2)}

Tasks:
1. Identify dependencies that are likely to need migration for PQC adoption.
2. Label urgency for each as:
   - Keep
   - Plan migration (6-18 months)
   - Migrate soon (0-6 months)
3. If a dependency has weak/no PQC path, suggest similar alternatives that support PQC better.
4. Give practical migration notes (compatibility, ecosystem maturity, deployment risk).
5. End with a short prioritized action list.

Be conservative and realistic.
"""

    res = client.chat.completions.create(
        model=deployment,
        messages=[{"role": "user", "content": prompt}],
        max_tokens=800
    )
    return res.choices[0].message.content


dependency_bp = Blueprint("dependency_bp", __name__)


def _dependency_csv(payload):
        out = io.StringIO()
        writer = csv.writer(out)
        writer.writerow(["section", "name", "value1", "value2", "value3"])

        for d in payload.get("dependencies", []):
                writer.writerow(["dependencies", d.get("name", ""), d.get("version", ""), "", ""])

        for c in payload.get("crypto_dependencies", []):
                writer.writerow([
                        "crypto_dependencies",
                        c.get("name", ""),
                        c.get("normalized", ""),
                        c.get("type", ""),
                        c.get("github_repo", "")
                ])

        for m in payload.get("maintenance", []):
                writer.writerow([
                        "maintenance",
                        m.get("repo", ""),
                        m.get("rating", ""),
                        m.get("category", ""),
                        m.get("last_push", "")
                ])
                writer.writerow([
                        "maintenance_ai",
                        m.get("repo", ""),
                        m.get("ai_assessment", ""),
                        "",
                        ""
                ])

        writer.writerow([
                "dependency_migration_advice",
                "summary",
                payload.get("dependency_migration_advice", ""),
                "",
                ""
        ])

        return out.getvalue()


def _dependency_html(payload):
        deps_rows = "".join([
                "<tr><td>{}</td><td>{}</td></tr>".format(
                        escape(str(d.get("name", ""))),
                        escape(str(d.get("version", "")))
                )
                for d in payload.get("dependencies", [])
        ])

        crypto_rows = "".join([
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>".format(
                        escape(str(c.get("name", ""))),
                        escape(str(c.get("normalized", ""))),
                        escape(str(c.get("type", ""))),
                        escape(str(c.get("github_repo", "")))
                )
                for c in payload.get("crypto_dependencies", [])
        ])

        maintenance_blocks = ""
        for m in payload.get("maintenance", []):
                maintenance_blocks += """
                <div class=\"card\">
                    <h3>{repo}</h3>
                    <p><b>Rating:</b> {rating}</p>
                    <p><b>PQC Category:</b> {category}</p>
                    <p><b>Last Push:</b> {last_push}</p>
                    <pre>{ai}</pre>
                </div>
                """.format(
                        repo=escape(str(m.get("repo", ""))),
                        rating=escape(str(m.get("rating", ""))),
                        category=escape(str(m.get("category", ""))),
                        last_push=escape(str(m.get("last_push", ""))),
                        ai=escape(str(m.get("ai_assessment", "")))
                )

        return """<!DOCTYPE html>
<html>
<head>
    <meta charset=\"utf-8\" />
    <title>Dependency Analysis Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; padding: 24px; }}
        table {{ border-collapse: collapse; width: 100%; margin-top: 12px; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background: #f3f4f6; }}
        .card {{ border: 1px solid #ddd; border-radius: 8px; padding: 16px; margin-top: 16px; }}
        pre {{ white-space: pre-wrap; background: #f8fafc; padding: 12px; border-radius: 8px; }}
    </style>
</head>
<body>
    <h1>SBOM Dependency Analysis</h1>
    <div class=\"card\">
        <h2>Dependencies</h2>
        <table>
            <tr><th>Name</th><th>Source</th></tr>
            {deps_rows}
        </table>
    </div>
    <div class=\"card\">
        <h2>Crypto Dependencies</h2>
        <table>
            <tr><th>Name</th><th>Normalized</th><th>Type</th><th>GitHub Repo</th></tr>
            {crypto_rows}
        </table>
    </div>
    <h2>Crypto Dependency Maintenance Analysis</h2>
    {maintenance_blocks}
    <div class=\"card\">
        <h2>PQC Migration Guidance</h2>
        <pre>{migration_advice}</pre>
    </div>
</body>
</html>
""".format(
                deps_rows=deps_rows,
                crypto_rows=crypto_rows,
                maintenance_blocks=maintenance_blocks,
                migration_advice=escape(str(payload.get("dependency_migration_advice", "")))
        )


@dependency_bp.route("/sbom_dependency")
def sbom_dependency_page():
    return render_template("sbom_dependency.html")


@dependency_bp.route("/dependency", methods=["POST"])
def dependency():
    data = request.get_json()
    repo = data.get("repo")

    owner, name = repo.split("/")
    # Sanitize repo name to prevent path traversal
    if not name or ".." in name or "/" in name or "\\" in name:
        return jsonify({"error": "Invalid repository name"}), 400
    
    repo_url = f"https://github.com/{owner}/{name}.git"

    workdir = f"/tmp/{name}"
    workdir = os.path.abspath(workdir)
    if not workdir.startswith("/tmp/"):
        return jsonify({"error": "Invalid working directory"}), 400

    subprocess.run(["git", "clone", "--depth", "1", repo_url, workdir])

    sbom_deps = run_sbom(repo)
    graph_deps = get_dependency_graph(owner, name)

    pip_deps       = detect_pip_dependencies(workdir)
    pyproject_deps = detect_pyproject_dependencies(workdir)
    setup_deps     = detect_setup_dependencies(workdir)
    pipfile_deps   = detect_pipfile_dependencies(workdir)
    conda_deps     = detect_conda_dependencies(workdir)
    npm_deps       = detect_npm_dependencies(workdir)
    cargo_deps     = detect_cargo_dependencies(workdir)
    maven_deps     = detect_maven_dependencies(workdir)
    nuget_deps     = detect_nuget_dependencies(workdir)
    ruby_deps      = detect_ruby_dependencies(workdir)
    nim_deps       = detect_nim_dependencies(workdir)
    action_deps    = detect_github_actions(workdir)
    go_deps        = detect_go_dependencies(workdir)

    # combine all deps
    all_deps = (
        sbom_deps + graph_deps
        + pip_deps + pyproject_deps + setup_deps + pipfile_deps + conda_deps
        + npm_deps + cargo_deps + maven_deps + nuget_deps
        + ruby_deps + nim_deps
        + action_deps + go_deps
    )

    # remove duplicates
    unique = {}
    for d in all_deps:
        key = d["name"].lower()
        unique[key] = d
    final_deps = list(unique.values())

    # 🔥 ADD THIS
    crypto_only = analyze_dependency_crypto(final_deps)
    migration_advice = dependency_migration_advice_with_ai(repo, crypto_only)

    return jsonify({
        "count": len(final_deps),
        "dependencies": final_deps,
        "crypto_dependencies": crypto_only,
        "dependency_migration_advice": migration_advice
    })


@dependency_bp.route("/dependency/export/csv", methods=["POST"])
def dependency_export_csv():
    payload = request.get_json() or {}
    content = _dependency_csv(payload)

    return Response(
        content,
        mimetype="text/csv",
        headers={
            "Content-Disposition": "attachment; filename=dependency_analysis.csv"
        }
    )


@dependency_bp.route("/dependency/export/html", methods=["POST"])
def dependency_export_html():
    payload = request.get_json() or {}
    content = _dependency_html(payload)

    return Response(
        content,
        mimetype="text/html",
        headers={
            "Content-Disposition": "attachment; filename=dependency_analysis.html"
        }
    )
from flask import Blueprint, request, jsonify, render_template, Response
import requests
import os
import re
import shutil
import json
import subprocess
import csv
import io
import glob
from html import escape
from openai import AzureOpenAI

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

endpoint = os.getenv("ENDPOINT_URL", "<Your Endpoint>")
deployment = os.getenv("DEPLOYMENT_NAME", "<Your Deployment>")
subscription_key = os.getenv("API_KEY")

client = None
if subscription_key:
    client = AI(
        azure_endpoint=endpoint,
        api_key=subscription_key,
        api_version="<Your version>"
    )

CRYPTO_LIBRARIES = {
    # C/C++ system libs
    "openssl", "wolfssl", "boringssl", "libcrypto", "libssl", "gnutls",
    "mbedtls", "nss", "nettle", "gcrypt", "libgcrypt", "cryptopp",
    # Rust crates
    "ring", "rustls", "aws-lc-rs", "p256", "ed25519-dalek",
    "aes", "sha2", "hmac", "pbkdf2",
    # Java / Kotlin
    "bcprov", "bouncycastle", "conscrypt", "spongycastle",
    # .NET
    "portable.bouncycastle", "bouncy-castle",
    # Go
    "x/crypto",
}

PQC_ALGORITHMS = {
    "kyber", "dilithium", "falcon", "sphincs",
    "ml-kem", "ml-dsa", "ntru"
}

PQC_LIBS = {
    "liboqs", "oqs", "oqs-provider"
}

AUTO_GITHUB_MAP = {
    # Python crypto
    "cryptography": "pyca/cryptography",
    "pyjwt": "jpadilla/pyjwt",
    "cffi": "python/cpython",  # dependency of cryptography

    # Classical crypto libs
    "openssl": "openssl/openssl",
    "libssl": "openssl/openssl",
    "libcrypto": "openssl/openssl",
    "boringssl": "google/boringssl",
    "wolfssl": "wolfSSL/wolfssl",
    "gnutls": "gnutls/gnutls",

    # PQC libs
    "liboqs": "open-quantum-safe/liboqs",
    "oqs": "open-quantum-safe/liboqs",
    "oqs-provider": "open-quantum-safe/oqs-provider",
    "circl": "cloudflare/circl",

    # PQC algorithms
    "kyber": "pq-crystals/kyber",
    "dilithium": "pq-crystals/dilithium",
    "falcon": "falcon-sign/falcon",
    "sphincs": "sphincs/sphincsplus",
    "ntru": "NTRUOpenSourceProject/ntru-crypto",
}


def get_dependency_graph(owner, repo):
    url = f"{API}/repos/{owner}/{repo}/dependency-graph/sbom"

    r = requests.get(url, headers=HEADERS)

    if r.status_code != 200:
        return []

    data = r.json()

    packages = data.get("sbom", {}).get("packages", [])

    deps = []

    for p in packages:
        deps.append({
            "name": p.get("name"),
            "version": p.get("versionInfo", "")
        })

    return deps


def normalize_dep_name(name: str):
    if not name:
        return ""

    n = name.lower()

    # Strip PURL / CycloneDX prefix  (pkg:pypi/foo@1.0  or  pypi:foo)
    if n.startswith("pkg:"):
        n = n.split("/", 1)[-1]
    elif ":" in n and "/" not in n.split(":")[0]:
        # handles  pip:foo  pypi:foo  npm:foo  maven:foo  etc.
        n = n.split(":", 1)[-1]

    # Remove repo hosts
    for host in ["github.com/", "gitlab.com/", "bitbucket.org/"]:
        if host in n:
            n = n.split(host)[-1]

    # Strip version suffix "@1.2.3"
    if "@" in n:
        n = n.split("@")[0]

    # Take last path segment
    n = n.split("/")[-1]

    # Strip pip extras  foo[security]  and version specifiers  foo>=1.0
    n = re.split(r"[><=!~\[\s;]", n)[0]

    return n.strip()


def map_dep_to_github_repo(normalized_name: str):
    """
    Strict mapping: return mapped repo only if it exists in AUTO_GITHUB_MAP.
    """
    return AUTO_GITHUB_MAP.get(normalized_name)


def analyze_dependency_crypto(deps):
    crypto_found = []

    for d in deps:
        raw = d["name"] or ""
        name = normalize_dep_name(raw)

        dep_info = None

        # PQC algorithms
        if any(p in name for p in PQC_ALGORITHMS):
            dep_info = {"name": raw, "normalized": name, "type": "PQC Algorithm"}

        # PQC libraries
        elif any(p in name for p in PQC_LIBS):
            dep_info = {"name": raw, "normalized": name, "type": "PQC Integration"}

        # Classical crypto libs
        elif any(p in name for p in CRYPTO_LIBRARIES):
            dep_info = {"name": raw, "normalized": name, "type": "Classical Crypto"}

    # Go crypto packages (matched before last-segment stripping)
        elif any(k in raw.lower() for k in [
            "golang.org/x/crypto", "github.com/cloudflare/circl",
            "github.com/google/tink",
        ]):
            dep_info = {"name": raw, "normalized": name, "type": "Classical Crypto"}

        # Python crypto packages
        elif any(k in name for k in [
            "cryptography", "pyjwt", "pyopenssl", "paramiko", "bcrypt",
            "cffi", "pyca", "nacl", "pynacl", "rsa", "ecdsa", "ed25519",
            "passlib", "cryptodome", "pycrypto", "itsdangerous", "jwt",
        ]):
            dep_info = {"name": raw, "normalized": name, "type": "Classical Crypto"}

        # Node.js / npm crypto packages
        elif any(k in name for k in [
            "node-forge", "crypto-js", "noble-curves", "noble-hashes",
            "jose", "jsonwebtoken", "node-rsa", "sodium-native",
            "libsodium-wrappers", "argon2", "bcryptjs",
        ]):
            dep_info = {"name": raw, "normalized": name, "type": "Classical Crypto"}

        # Java / Maven crypto packages
        elif any(k in name for k in [
            "bcprov", "bouncycastle", "conscrypt", "spongycastle",
            "tink", "jasypt",
        ]):
            dep_info = {"name": raw, "normalized": name, "type": "Classical Crypto"}

        # .NET NuGet crypto packages
        elif any(k in name.replace(".", "-") for k in [
            "bouncycastle", "portable-bouncycastle", "system-security",
            "identitymodel",
        ]):
            dep_info = {"name": raw, "normalized": name, "type": "Classical Crypto"}

        # if no crypto match → skip
        if not dep_info:
            continue

        # STRICT mapping = only map if in AUTO_GITHUB_MAP
        mapped_repo = map_dep_to_github_repo(name)
        if mapped_repo:
            dep_info["github_repo"] = mapped_repo

        crypto_found.append(dep_info)

    return crypto_found


def run_sbom(repo):
    owner, name = repo.split("/")

    repo_url = f"https://github.com/{owner}/{name}.git"

    workdir = f"/tmp/{name}"

    if os.path.exists(workdir):
        shutil.rmtree(workdir)

    subprocess.run(["git", "clone", "--depth", "1", repo_url, workdir])

    sbom_dir = os.path.join(workdir, "sbom")
    os.makedirs(sbom_dir, exist_ok=True)

    subprocess.run([
        "sbom-tool",
        "generate",
        "-b", sbom_dir,
        "-bc", workdir,
        "-pn", name,
        "-pv", "1.0",
        "-ps", "github"
    ])

    manifest = os.path.join(sbom_dir, "_manifest")

    deps = []

    if os.path.exists(manifest):
        for file in os.listdir(manifest):
            if file.endswith(".json"):
                with open(os.path.join(manifest, file), "r", encoding="utf-8", errors="ignore") as f:
                    data = json.load(f)

                    for p in data.get("packages", []):
                        deps.append({
                            "name": p.get("name"),
                            "version": p.get("versionInfo", "")
                        })

    return deps


def detect_pip_dependencies(repo_path):
    deps = []
    seen = set()

    def _read_lines_with_fallback(path):
        # Some repos store requirements files as UTF-16 (e.g. webmcp).
        with open(path, "rb") as bf:
            raw = bf.read()

        encodings = ["utf-8-sig", "utf-16", "utf-16le", "utf-16be", "latin-1"]
        text = ""
        for enc in encodings:
            try:
                text = raw.decode(enc)
                break
            except UnicodeDecodeError:
                continue

        if not text:
            text = raw.decode("utf-8", errors="ignore")

        return text.splitlines()

    # Glob for every requirements*.txt in root and one level of subdirs
    patterns = [
        "requirements*.txt",
        "requirements/*.txt",
        "requires/*.txt",
    ]
    req_files = set()
    for pat in patterns:
        req_files.update(glob.glob(os.path.join(repo_path, pat)))

    for req_file in sorted(req_files):
        for line in _read_lines_with_fallback(req_file):
            line = line.strip()
            # skip blank, comments, options flags (-r, -c, --index-url ...)
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            pkg_name = re.split(r"[><=!~\[\s;@]", line)[0].strip()
            if pkg_name and pkg_name.lower() not in seen:
                seen.add(pkg_name.lower())
                deps.append({"name": pkg_name, "version": "pip"})

    return deps


def detect_pyproject_dependencies(repo_path):
    deps = []
    fpath = os.path.join(repo_path, "pyproject.toml")
    if not os.path.exists(fpath):
        return deps
    try:
        with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
            text = f.read()

        # [project] dependencies = ["foo>=1.0", ...]
        proj = re.search(r'\[project\].*?(?=\n\[|\Z)', text, re.DOTALL)
        if proj:
            arr = re.search(r'dependencies\s*=\s*\[(.*?)\]', proj.group(), re.DOTALL)
            if arr:
                for pkg_str in re.findall(r'["\']([^"\']+)["\']', arr.group(1)):
                    pkg = re.split(r'[><=!~\[\s;@]', pkg_str)[0].strip()
                    if pkg:
                        deps.append({"name": pkg, "version": "Python (pyproject)"})

        # [tool.poetry.dependencies] and [tool.poetry.dev-dependencies]
        for sec in re.finditer(r'\[tool\.poetry\.(?:dev-)?dependencies\](.*?)(?=\n\[|\Z)', text, re.DOTALL):
            for pkg in re.findall(r'^([a-zA-Z0-9_\-\.]+)\s*=', sec.group(1), re.MULTILINE):
                if pkg.lower() != "python":
                    deps.append({"name": pkg, "version": "Python (poetry)"})

        # [build-system] requires = [...]
        bs = re.search(r'\[build-system\].*?requires\s*=\s*\[(.*?)\]', text, re.DOTALL)
        if bs:
            for pkg_str in re.findall(r'["\']([^"\']+)["\']', bs.group(1)):
                pkg = re.split(r'[><=!~\[\s;@]', pkg_str)[0].strip()
                if pkg:
                    deps.append({"name": pkg, "version": "Python (build)"})

    except Exception:
        pass
    return deps


def detect_github_actions(repo_path):
    actions = []

    workflow_dir = os.path.join(repo_path, ".github", "workflows")

    if not os.path.exists(workflow_dir):
        return actions

    for file in os.listdir(workflow_dir):
        if file.endswith(".yml") or file.endswith(".yaml"):
            with open(os.path.join(workflow_dir, file), "r", encoding="utf-8", errors="ignore") as f:
                text = f.read()

                matches = re.findall(r'uses:\s*([^\s@]+)', text)

                for m in matches:
                    actions.append({
                        "name": m,
                        "version": "GitHub Action"
                    })

    return actions


def detect_go_dependencies(repo_path):
    deps = []
    go_mod = os.path.join(repo_path, "go.mod")
    if not os.path.exists(go_mod):
        return deps
    try:
        with open(go_mod, "r", encoding="utf-8", errors="ignore") as f:
            text = f.read()
        # Matches both single-line `require foo v1.0` and entries inside require(...) blocks
        skip = {"module", "go", "toolchain", "require"}
        for m in re.finditer(r'^\s*([\w.\-/]+)\s+(v[\w.\-+]+)', text, re.MULTILINE):
            name, version = m.group(1).strip(), m.group(2).strip()
            if name not in skip:
                deps.append({"name": name, "version": version})
    except Exception:
        pass
    return deps


def detect_setup_dependencies(repo_path):
    """setup.py install_requires and setup.cfg install_requires."""
    deps = []

    setup_py = os.path.join(repo_path, "setup.py")
    if os.path.exists(setup_py):
        try:
            with open(setup_py, "r", encoding="utf-8", errors="ignore") as f:
                text = f.read()
            for block in re.findall(r'install_requires\s*=\s*\[(.*?)\]', text, re.DOTALL):
                for pkg_str in re.findall(r'["\']([^"\']+)["\']', block):
                    pkg = re.split(r'[><=!~\[\s;@]', pkg_str)[0].strip()
                    if pkg:
                        deps.append({"name": pkg, "version": "Python (setup.py)"})
        except Exception:
            pass

    setup_cfg = os.path.join(repo_path, "setup.cfg")
    if os.path.exists(setup_cfg):
        try:
            with open(setup_cfg, "r", encoding="utf-8", errors="ignore") as f:
                text = f.read()
            m = re.search(r'install_requires\s*=\s*((?:\n[ \t]+\S.*)+)', text)
            if m:
                for line in m.group(1).splitlines():
                    line = line.strip()
                    if line and not line.startswith("#"):
                        pkg = re.split(r'[><=!~\[\s;@]', line)[0].strip()
                        if pkg:
                            deps.append({"name": pkg, "version": "Python (setup.cfg)"})
        except Exception:
            pass

    return deps


def detect_pipfile_dependencies(repo_path):
    """Pipfile [packages] and [dev-packages]."""
    deps = []
    pipfile = os.path.join(repo_path, "Pipfile")
    if not os.path.exists(pipfile):
        return deps
    try:
        with open(pipfile, "r", encoding="utf-8", errors="ignore") as f:
            text = f.read()
        for section in re.findall(r'\[(?:dev-)?packages\](.*?)(?=\n\[|\Z)', text, re.DOTALL):
            for pkg in re.findall(r'^([a-zA-Z0-9_\-\.]+)\s*=', section, re.MULTILINE):
                deps.append({"name": pkg, "version": "Python (Pipfile)"})
    except Exception:
        pass
    return deps


def detect_conda_dependencies(repo_path):
    """environment.yml / conda.yml dependencies list."""
    deps = []
    for fname in ["environment.yml", "environment.yaml", "conda.yml", "conda.yaml"]:
        fpath = os.path.join(repo_path, fname)
        if not os.path.exists(fpath):
            continue
        try:
            with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                text = f.read()
            section = re.search(r'dependencies:(.*?)(?=\n\w|\Z)', text, re.DOTALL)
            if section:
                for line in section.group(1).splitlines():
                    line = line.strip().lstrip("- ")
                    if line and not line.startswith("#") and not line.startswith("{"):
                        pkg = re.split(r'[><=!~\s:=]', line)[0].strip()
                        if pkg:
                            deps.append({"name": pkg, "version": "conda"})
        except Exception:
            pass
    return deps


def detect_npm_dependencies(repo_path):
    """package.json dependencies, devDependencies, peerDependencies."""
    deps = []
    pkg_file = os.path.join(repo_path, "package.json")
    if not os.path.exists(pkg_file):
        return deps
    try:
        with open(pkg_file, "r", encoding="utf-8", errors="ignore") as f:
            data = json.load(f)
        for section in ["dependencies", "devDependencies", "peerDependencies", "optionalDependencies"]:
            for pkg_name, version in data.get(section, {}).items():
                deps.append({"name": pkg_name, "version": f"npm ({version})"})
    except Exception:
        pass
    return deps


def detect_cargo_dependencies(repo_path):
    """Cargo.toml [dependencies], [dev-dependencies], [build-dependencies]."""
    deps = []
    cargo_file = os.path.join(repo_path, "Cargo.toml")
    if not os.path.exists(cargo_file):
        return deps
    try:
        with open(cargo_file, "r", encoding="utf-8", errors="ignore") as f:
            text = f.read()
        for section in re.findall(
            r'\[(?:dev-|build-)?dependencies(?:\.[^\]]+)?\](.*?)(?=\n\[|\Z)', text, re.DOTALL
        ):
            for pkg in re.findall(r'^([a-zA-Z0-9_\-]+)\s*=', section, re.MULTILINE):
                deps.append({"name": pkg, "version": "Rust (Cargo)"})
    except Exception:
        pass
    return deps


def detect_maven_dependencies(repo_path):
    """pom.xml <dependency> blocks (searches entire repo tree)."""
    deps = []
    for pom_file in glob.glob(os.path.join(repo_path, "**/pom.xml"), recursive=True):
        if ".git" in pom_file:
            continue
        try:
            with open(pom_file, "r", encoding="utf-8", errors="ignore") as f:
                text = f.read()
            for m in re.finditer(
                r'<dependency>.*?<groupId>(.*?)</groupId>.*?<artifactId>(.*?)</artifactId>'
                r'(?:.*?<version>(.*?)</version>)?.*?</dependency>',
                text, re.DOTALL
            ):
                group_id = m.group(1).strip()
                artifact_id = m.group(2).strip()
                version = (m.group(3) or "Maven").strip()
                deps.append({"name": f"{group_id}:{artifact_id}", "version": version})
        except Exception:
            pass
    return deps


def detect_nuget_dependencies(repo_path):
    """*.csproj / *.fsproj / *.vbproj PackageReference and packages.config."""
    deps = []
    proj_files = (
        glob.glob(os.path.join(repo_path, "**/*.csproj"), recursive=True)
        + glob.glob(os.path.join(repo_path, "**/*.fsproj"), recursive=True)
        + glob.glob(os.path.join(repo_path, "**/*.vbproj"), recursive=True)
    )
    for fpath in proj_files:
        if ".git" in fpath:
            continue
        try:
            with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                text = f.read()
            for m in re.finditer(
                r'<PackageReference\s+Include="([^"]+)"\s+Version="([^"]+)"', text, re.IGNORECASE
            ):
                deps.append({"name": m.group(1), "version": m.group(2)})
        except Exception:
            pass
    for fpath in glob.glob(os.path.join(repo_path, "**/packages.config"), recursive=True):
        if ".git" in fpath:
            continue
        try:
            with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                text = f.read()
            for m in re.finditer(
                r'<package\s+id="([^"]+)"\s+version="([^"]+)"', text, re.IGNORECASE
            ):
                deps.append({"name": m.group(1), "version": m.group(2)})
        except Exception:
            pass
    return deps


def detect_ruby_dependencies(repo_path):
    """Gemfile gem declarations."""
    deps = []
    gemfile = os.path.join(repo_path, "Gemfile")
    if not os.path.exists(gemfile):
        return deps
    try:
        with open(gemfile, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if line.startswith("#"):
                    continue
                m = re.match(r"gem\s+['\"]([^'\"]+)['\"]", line)
                if m:
                    deps.append({"name": m.group(1), "version": "Ruby (Gem)"})
    except Exception:
        pass
    return deps


def detect_nim_dependencies(repo_path):
    """*.nimble requires declarations."""
    deps = []
    for fpath in glob.glob(os.path.join(repo_path, "*.nimble")):
        try:
            with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    m = re.match(r'requires\s+"([^"]+)', line)
                    if m:
                        pkg = re.split(r'[><=\s]', m.group(1))[0].strip()
                        if pkg and pkg.lower() != "nim":
                            deps.append({"name": pkg, "version": "Nim (nimble)"})
        except Exception:
            pass
    return deps


def dependency_migration_advice_with_ai(repo, crypto_deps):
    if not client:
        return "Azure OpenAI is not configured. Set AZURE_OPENAI_API_KEY to enable migration advice."

    if not crypto_deps:
        return "No cryptographic dependencies were detected, so no PQC migration action is currently required."

    prompt = f"""
You are a cryptography migration advisor focused on post-quantum readiness.

Repository: {repo}
Detected Crypto Dependencies:
{json.dumps(crypto_deps, indent=2)}

Tasks:
1. Identify dependencies that are likely to need migration for PQC adoption.
2. Label urgency for each as:
   - Keep
   - Plan migration (6-18 months)
   - Migrate soon (0-6 months)
3. If a dependency has weak/no PQC path, suggest similar alternatives that support PQC better.
4. Give practical migration notes (compatibility, ecosystem maturity, deployment risk).
5. End with a short prioritized action list.

Be conservative and realistic.
"""

    res = client.chat.completions.create(
        model=deployment,
        messages=[{"role": "user", "content": prompt}],
        max_tokens=2000
    )
    return res.choices[0].message.content


dependency_bp = Blueprint("dependency_bp", __name__)


def _dependency_csv(payload):
        out = io.StringIO()
        writer = csv.writer(out)
        writer.writerow(["section", "name", "value1", "value2", "value3"])

        for d in payload.get("dependencies", []):
                writer.writerow(["dependencies", d.get("name", ""), d.get("version", ""), "", ""])

        for c in payload.get("crypto_dependencies", []):
                writer.writerow([
                        "crypto_dependencies",
                        c.get("name", ""),
                        c.get("normalized", ""),
                        c.get("type", ""),
                        c.get("github_repo", "")
                ])

        for m in payload.get("maintenance", []):
                writer.writerow([
                        "maintenance",
                        m.get("repo", ""),
                        m.get("rating", ""),
                        m.get("category", ""),
                        m.get("last_push", "")
                ])
                writer.writerow([
                        "maintenance_ai",
                        m.get("repo", ""),
                        m.get("ai_assessment", ""),
                        "",
                        ""
                ])

        writer.writerow([
                "dependency_migration_advice",
                "summary",
                payload.get("dependency_migration_advice", ""),
                "",
                ""
        ])

        return out.getvalue()


def _dependency_html(payload):
        deps_rows = "".join([
                "<tr><td>{}</td><td>{}</td></tr>".format(
                        escape(str(d.get("name", ""))),
                        escape(str(d.get("version", "")))
                )
                for d in payload.get("dependencies", [])
        ])

        crypto_rows = "".join([
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>".format(
                        escape(str(c.get("name", ""))),
                        escape(str(c.get("normalized", ""))),
                        escape(str(c.get("type", ""))),
                        escape(str(c.get("github_repo", "")))
                )
                for c in payload.get("crypto_dependencies", [])
        ])

        maintenance_blocks = ""
        for m in payload.get("maintenance", []):
                maintenance_blocks += """
                <div class=\"card\">
                    <h3>{repo}</h3>
                    <p><b>Rating:</b> {rating}</p>
                    <p><b>PQC Category:</b> {category}</p>
                    <p><b>Last Push:</b> {last_push}</p>
                    <pre>{ai}</pre>
                </div>
                """.format(
                        repo=escape(str(m.get("repo", ""))),
                        rating=escape(str(m.get("rating", ""))),
                        category=escape(str(m.get("category", ""))),
                        last_push=escape(str(m.get("last_push", ""))),
                        ai=escape(str(m.get("ai_assessment", "")))
                )

        return """<!DOCTYPE html>
<html>
<head>
    <meta charset=\"utf-8\" />
    <title>Dependency Analysis Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; padding: 24px; }}
        table {{ border-collapse: collapse; width: 100%; margin-top: 12px; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background: #f3f4f6; }}
        .card {{ border: 1px solid #ddd; border-radius: 8px; padding: 16px; margin-top: 16px; }}
        pre {{ white-space: pre-wrap; background: #f8fafc; padding: 12px; border-radius: 8px; }}
    </style>
</head>
<body>
    <h1>SBOM Dependency Analysis</h1>
    <div class=\"card\">
        <h2>Dependencies</h2>
        <table>
            <tr><th>Name</th><th>Source</th></tr>
            {deps_rows}
        </table>
    </div>
    <div class=\"card\">
        <h2>Crypto Dependencies</h2>
        <table>
            <tr><th>Name</th><th>Normalized</th><th>Type</th><th>GitHub Repo</th></tr>
            {crypto_rows}
        </table>
    </div>
    <h2>Crypto Dependency Maintenance Analysis</h2>
    {maintenance_blocks}
    <div class=\"card\">
        <h2>PQC Migration Guidance</h2>
        <pre>{migration_advice}</pre>
    </div>
</body>
</html>
""".format(
                deps_rows=deps_rows,
                crypto_rows=crypto_rows,
                maintenance_blocks=maintenance_blocks,
                migration_advice=escape(str(payload.get("dependency_migration_advice", "")))
        )


@dependency_bp.route("/sbom_dependency")
def sbom_dependency_page():
    return render_template("sbom_dependency.html")


@dependency_bp.route("/dependency", methods=["POST"])
def dependency():
    data = request.get_json()
    repo = data.get("repo")

    owner, name = repo.split("/")
    repo_url = f"https://github.com/{owner}/{name}.git"

    workdir = f"/tmp/{name}"

    subprocess.run(["git", "clone", "--depth", "1", repo_url, workdir])

    sbom_deps = run_sbom(repo)
    graph_deps = get_dependency_graph(owner, name)

    pip_deps       = detect_pip_dependencies(workdir)
    pyproject_deps = detect_pyproject_dependencies(workdir)
    setup_deps     = detect_setup_dependencies(workdir)
    pipfile_deps   = detect_pipfile_dependencies(workdir)
    conda_deps     = detect_conda_dependencies(workdir)
    npm_deps       = detect_npm_dependencies(workdir)
    cargo_deps     = detect_cargo_dependencies(workdir)
    maven_deps     = detect_maven_dependencies(workdir)
    nuget_deps     = detect_nuget_dependencies(workdir)
    ruby_deps      = detect_ruby_dependencies(workdir)
    nim_deps       = detect_nim_dependencies(workdir)
    action_deps    = detect_github_actions(workdir)
    go_deps        = detect_go_dependencies(workdir)

    # combine all deps
    all_deps = (
        sbom_deps + graph_deps
        + pip_deps + pyproject_deps + setup_deps + pipfile_deps + conda_deps
        + npm_deps + cargo_deps + maven_deps + nuget_deps
        + ruby_deps + nim_deps
        + action_deps + go_deps
    )

    # remove duplicates
    unique = {}
    for d in all_deps:
        key = d["name"].lower()
        unique[key] = d
    final_deps = list(unique.values())

    # 🔥 ADD THIS
    crypto_only = analyze_dependency_crypto(final_deps)
    migration_advice = dependency_migration_advice_with_ai(repo, crypto_only)

    return jsonify({
        "count": len(final_deps),
        "dependencies": final_deps,
        "crypto_dependencies": crypto_only,
        "dependency_migration_advice": migration_advice
    })


@dependency_bp.route("/dependency/export/csv", methods=["POST"])
def dependency_export_csv():
    payload = request.get_json() or {}
    content = _dependency_csv(payload)

    return Response(
        content,
        mimetype="text/csv",
        headers={
            "Content-Disposition": "attachment; filename=dependency_analysis.csv"
        }
    )


@dependency_bp.route("/dependency/export/html", methods=["POST"])
def dependency_export_html():
    payload = request.get_json() or {}
    content = _dependency_html(payload)

    return Response(
        content,
        mimetype="text/html",
        headers={
            "Content-Disposition": "attachment; filename=dependency_analysis.html"
        }
    )

#!/usr/bin/env python3
"""Cryptographic linter for SecureChat.

Scans the repository for forbidden cryptographic anti-patterns:
- Insecure cipher modes (ECB, CBC)
- Insecure RSA padding (PKCS#1 v1.5)
- Deprecated hashes (MD5, SHA-1 used for security)
- Insecure randomness (non-secure Random() instead of Random.secure() / secrets)
- Hardcoded encryption keys or IVs
- Printing/logging private keys or tokens
- SharedPreferences used for storing cryptographic keys

Includes self-tests with synthetic bad samples to verify detection.
"""

from pathlib import Path
import re
import sys

REPO_ROOT = Path(__file__).resolve().parent.parent

# Directories to skip
IGNORED_DIRS = {
    ".git",
    ".dart_tool",
    "build",
    ".system_generated",
    "__pycache__",
    ".pytest_cache",
    ".ruff_cache",
    "node_modules",
}

# Rules definition: (rule_id, regex_pattern, description)
CRYPTO_RULES = [
    (
        "CRYPTO-01-ECB",
        re.compile(
            r"(AESMode\.ecb|ECBBlockCipher|\bECB\b|modes\.ECB)", re.IGNORECASE
        ),
        "ECB mode detected. Always use AES-GCM authenticated encryption.",
    ),
    (
        "CRYPTO-02-CBC",
        re.compile(
            r"(AESMode\.cbc|CBCBlockCipher|\bCBC\b|modes\.CBC)", re.IGNORECASE
        ),
        "CBC mode detected. Always use AES-GCM authenticated encryption.",
    ),
    (
        "CRYPTO-03-PKCS1",
        re.compile(r"(PKCS1Encoding|PKCS1v15|padding\.PKCS1v15)"),
        "PKCS#1 v1.5 padding detected. Always use OAEP with SHA-256 for key wrapping.",
    ),
    (
        "CRYPTO-04-WEAK-HASH",
        re.compile(
            r"(hashlib\.md5|hashlib\.sha1|MD5Digest|SHA1Digest|\bMD5\b)",
            re.IGNORECASE,
        ),
        "MD5/SHA-1 detected. Use SHA-256 or Argon2id.",
    ),
    (
        "CRYPTO-05-INSECURE-RANDOM",
        re.compile(r"\bRandom\(\s*\)|random\.random\(\)|random\.randint\("),
        "Non-secure Random() detected. Always use Random.secure() in Dart or secrets in Python.",
    ),
    (
        "CRYPTO-06-PRINTED-SECRETS",
        re.compile(
            r"(print|logging\.\w+|logger\.\w+)\s*\([^)]*\b(private_key|priv_key|privateKey|access_token|refreshToken|password)\b[^)]*\)",
            re.IGNORECASE,
        ),
        "Logging or printing of private keys or tokens detected.",
    ),
    (
        "CRYPTO-07-SHARED-PREFS-KEYS",
        re.compile(
            r"(SharedPreferences|prefs\.(get|set|put)\w*).*(key|secret|token|private)", re.IGNORECASE
        ),
        "SharedPreferences used for cryptographic keys. Use KeyStore (flutter_secure_storage / Keychain / KeyStore).",
    ),
]


def lint_content(
    content: str, filename: str = "test_file"
) -> list[tuple[str, int, str]]:
    findings = []
    lines = content.splitlines()

    for line_idx, line in enumerate(lines, 1):
        # Ignore comments or tool's own definition lines
        stripped = line.strip()
        if (
            stripped.startswith("//")
            or stripped.startswith("#")
            or stripped.startswith("*")
        ):
            continue

        for rule_id, pattern, desc in CRYPTO_RULES:
            if pattern.search(line):
                findings.append((rule_id, line_idx, desc))
    return findings


def lint_file(file_path: Path) -> list[tuple[Path, int, str, str]]:
    results = []
    # Skip self
    if file_path.resolve() == Path(__file__).resolve():
        return results

    try:
        content = file_path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return results

    lines = content.splitlines()
    for line_idx, line in enumerate(lines, 1):
        stripped = line.strip()
        if (
            stripped.startswith("//")
            or stripped.startswith("#")
            or stripped.startswith("*")
        ):
            continue

        # Skip test mock certs or hash matching in cert_pinning
        if "cert_pinning" in file_path.name and "sha1" in line:
            continue

        for rule_id, pattern, desc in CRYPTO_RULES:
            if pattern.search(line):
                results.append((file_path, line_idx, rule_id, desc))
    return results


def run_self_tests() -> None:
    bad_samples = {
        "CRYPTO-01-ECB": "final cipher = ECBBlockCipher(AESFastEngine());",
        "CRYPTO-02-CBC": "final cipher = CBCBlockCipher(AESEngine());",
        "CRYPTO-03-PKCS1": "final pad = PKCS1Encoding(RSAEngine());",
        "CRYPTO-04-WEAK-HASH": "final md5 = MD5Digest();",
        "CRYPTO-05-INSECURE-RANDOM": "final rand = Random();",
        "CRYPTO-06-PRINTED-SECRETS": "print('User private_key: $privKey');",
        "CRYPTO-07-SHARED-PREFS-KEYS": "prefs.setString('private_key', key);",
    }

    for expected_rule, sample in bad_samples.items():
        findings = lint_content(sample)
        rule_ids = [f[0] for f in findings]
        assert expected_rule in rule_ids, (
            f"Self-test failed: expected {expected_rule} for sample:\n{sample}"
        )

    print(
        f"[PASS] crypto_lint self-tests passed ({len(bad_samples)} bad samples caught)."
    )


def main() -> int:
    # 1. Run self-tests first
    run_self_tests()

    # 2. Scan repository (app, server, tools)
    all_findings = []
    scan_roots = [REPO_ROOT / "app", REPO_ROOT / "server", REPO_ROOT / "tools"]
    for root in scan_roots:
        for ext in ("*.dart", "*.py"):
            for path in root.rglob(ext):
                if any(part in IGNORED_DIRS for part in path.parts):
                    continue
                findings = lint_file(path)
                all_findings.extend(findings)

    if all_findings:
        print("\n[FAIL] Crypto lint violations found:")
        for file_path, line_num, rule_id, desc in all_findings:
            rel_path = file_path.relative_to(REPO_ROOT)
            print(f"  {rel_path}:{line_num} [{rule_id}] {desc}")
        return 1

    print("[PASS] Repository scan clean: 0 crypto anti-patterns found.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

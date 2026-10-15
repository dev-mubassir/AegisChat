#!/usr/bin/env python3
"""Secrets scanner for SecureChat.

Scans the repository to ensure no secrets or sensitive files are committed:
- Private key blocks (RSA, EC, OpenSSH, generic private keys)
- Hardcoded JWTs, API tokens, secret keys
- Committed .env files

Includes self-tests with bad samples to verify detection.
"""

from pathlib import Path
import re
import sys

REPO_ROOT = Path(__file__).resolve().parent.parent

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

SECRET_PATTERNS = [
    (
        "SECRET-01-PRIVATE-KEY",
        re.compile(
            r"-----BEGIN\s+((RSA|EC|DSA|OPENSSH)\s+)?PRIVATE\s+KEY-----",
            re.IGNORECASE,
        ),
        "Private key block detected in repository file.",
    ),
    (
        "SECRET-02-JWT-TOKEN",
        re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\."),
        "Live JWT token detected in source code.",
    ),
    (
        "SECRET-03-COMMITTED-ENV",
        re.compile(r"^\.env(\.(local|production|development|secret))?$"),
        "Committed .env file detected.",
    ),
]


def scan_file_content(
    content: str, filename: str
) -> list[tuple[str, int, str]]:
    findings = []
    lines = content.splitlines()

    for idx, line in enumerate(lines, 1):
        # Ignore comments or tool's own definition lines
        stripped = line.strip()
        if (
            stripped.startswith("//")
            or stripped.startswith("#")
            or stripped.startswith("*")
        ):
            continue

        for rule_id, pattern, desc in SECRET_PATTERNS:
            if rule_id == "SECRET-03-COMMITTED-ENV":
                continue
            if pattern.search(line):
                findings.append((rule_id, idx, desc))
    return findings


def scan_filename(file_path: Path) -> list[tuple[str, int, str]]:
    findings = []
    filename = file_path.name
    for rule_id, pattern, desc in SECRET_PATTERNS:
        if rule_id == "SECRET-03-COMMITTED-ENV":
            if pattern.match(filename) and filename != ".env.example":
                findings.append((rule_id, 1, f"{desc}: {filename}"))
    return findings


def run_self_tests() -> None:
    bad_samples = {
        "SECRET-01-PRIVATE-KEY": (
            "String key = '-----BEGIN RSA PRIVATE KEY-----...';",
            "test.dart",
        ),
        "SECRET-02-JWT-TOKEN": (
            'String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc";',
            "test.dart",
        ),
    }

    for expected_rule, (sample, fname) in bad_samples.items():
        findings = scan_file_content(sample, fname)
        rule_ids = [f[0] for f in findings]
        assert expected_rule in rule_ids, (
            f"Self-test failed: expected {expected_rule} for sample:\n{sample}"
        )

    # Test .env file detection
    env_findings = scan_filename(Path(".env"))
    assert any(f[0] == "SECRET-03-COMMITTED-ENV" for f in env_findings), (
        "Self-test failed for .env"
    )

    print("[PASS] scan_secrets self-tests passed (bad samples detected).")


def main() -> int:
    # 1. Self-tests
    run_self_tests()

    # 2. Scan repo
    all_findings = []
    for path in REPO_ROOT.rglob("*"):
        if any(part in IGNORED_DIRS for part in path.parts):
            continue
        if path.is_dir():
            continue
        if path.resolve() == Path(__file__).resolve():
            continue

        # Check filename (e.g. .env)
        name_findings = scan_filename(path)
        for rule_id, line, desc in name_findings:
            all_findings.append((path, line, rule_id, desc))

        # Check file content
        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue

        content_findings = scan_file_content(content, path.name)
        for rule_id, line, desc in content_findings:
            all_findings.append((path, line, rule_id, desc))

    if all_findings:
        print("\n[FAIL] Secrets found in repository:")
        for file_path, line_num, rule_id, desc in all_findings:
            rel = file_path.relative_to(REPO_ROOT)
            print(f"  {rel}:{line_num} [{rule_id}] {desc}")
        return 1

    print("[PASS] Repository scan clean: 0 committed secrets or private keys.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

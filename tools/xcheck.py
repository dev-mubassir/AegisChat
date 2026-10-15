"""Cross-language crypto verification script.

Verifies bidirectional compatibility between Flutter/Dart and Python reference
implementations of the SecureChat v1 message envelope protocol:
1. Direction 1: Dart seals envelopes -> Python opens and verifies them.
2. Direction 2: Python seals envelopes -> Dart opens and verifies them.

Exits 0 if and only if both directions pass all assertions.
"""

import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa

# Add parent directory to sys.path so we can import tools.ref_envelope
ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

from tools.ref_envelope import open_envelope, rsa_key_from_components, seal  # noqa: E402


def find_dart_binary() -> str:
    """Finds dart executable across PATH and known installation locations."""
    # Check standard PATH
    which_dart = shutil.which("dart")
    if which_dart:
        return which_dart

    candidates = [
        Path("C:/src/flutter/bin/dart.bat"),
        Path("C:/src/flutter/bin/cache/dart-sdk/bin/dart.exe"),
        Path(os.environ.get("LOCALAPPDATA", "")) / "Pub/Cache/bin/dart.bat",
    ]
    for c in candidates:
        if c.exists():
            return str(c)

    raise FileNotFoundError("Could not find dart executable on system")


def run_direction_1_dart_to_python(dart_bin: str) -> None:
    """Runs Dart vector generator and verifies all generated envelopes with Python."""
    print("\n--- Direction 1: Dart -> Python ---")
    app_dir = ROOT_DIR / "app"

    # 1. Run Dart vector generator
    print(f"Running Dart vector generator using {dart_bin}...")
    proc = subprocess.run(
        [dart_bin, "run", "tool/generate_vectors.dart"],
        cwd=str(app_dir),
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        print("Dart generator stdout:", proc.stdout)
        print("Dart generator stderr:", proc.stderr)
        raise RuntimeError(f"Dart generator failed with exit code {proc.returncode}")

    print(proc.stdout.strip())

    vectors_path = ROOT_DIR / "docs" / "vectors.json"
    if not vectors_path.exists():
        raise FileNotFoundError(f"Missing {vectors_path}")

    with open(vectors_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    vectors = data.get("vectors", [])
    if not vectors:
        raise ValueError("No vectors found in docs/vectors.json")

    print(f"Python verifying {len(vectors)} Dart envelopes...")
    for v in vectors:
        name = v["name"]
        recipient_id = v["recipient_id"]
        timestamp = v["timestamp"]
        expected_plaintext = v["plaintext_utf8"]

        rsa_info = v["recipient_rsa"]
        priv_rsa = rsa_key_from_components(
            int(rsa_info["n_hex"], 16),
            int(rsa_info["e"]),
            int(rsa_info["d_hex"], 16),
            int(rsa_info["p_hex"], 16),
            int(rsa_info["q_hex"], 16),
        )

        ed_info = v["sender_ed25519"]
        pub_ed = ed25519.Ed25519PublicKey.from_public_bytes(
            bytes.fromhex(ed_info["public_key_hex"])
        )

        envelope_bytes = bytes.fromhex(v["envelope_hex"])

        seen = set()
        decrypted = open_envelope(
            envelope_bytes=envelope_bytes,
            expected_recipient_id=recipient_id,
            sender_signing_public_key=pub_ed,
            recipient_rsa_private_key=priv_rsa,
            seen_message_ids=seen,
            current_time=timestamp,
            max_clock_skew=300,
        )

        decrypted_text = decrypted.decode("utf-8")
        assert (
            decrypted_text == expected_plaintext
        ), f"Mismatch in {name}: expected {expected_plaintext}, got {decrypted_text}"
        print(f"  [OK] Python opened Dart vector: '{name}'")

    print("Direction 1 (Dart -> Python): ALL PASSED.")


def run_direction_2_python_to_dart(dart_bin: str) -> None:
    """Generates Python test envelopes and verifies them with Dart."""
    print("\n--- Direction 2: Python -> Dart ---")
    test_cases = [
        {
            "name": "Python -> Dart basic ASCII",
            "sender_id": "py_sender_1",
            "recipient_id": "dart_receiver_1",
            "message_id": "msg_py_001",
            "plaintext": "Greetings from Python cryptography reference implementation!",
        },
        {
            "name": "Python -> Dart Unicode and emojis",
            "sender_id": "py_bob_phone",
            "recipient_id": "dart_alice_phone",
            "message_id": "msg_py_002",
            "plaintext": "🐍 Python 🤝 Flutter 💙 E2EE verified! 🔑✨",
        },
        {
            "name": "Python -> Dart 2KB large payload",
            "sender_id": "py_server_agent",
            "recipient_id": "dart_client_app",
            "message_id": "msg_py_003",
            "plaintext": "SecureChat-Payload-" * 128,  # ~2.4 KB
        },
    ]

    python_vectors = []
    timestamp = int(time.time())

    for tc in test_cases:
        rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        ed_key = ed25519.Ed25519PrivateKey.generate()

        ed_pub_bytes = ed_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        ed_priv_bytes = ed_key.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )

        nums = rsa_key.private_numbers()

        envelope_bytes = seal(
            sender_id=tc["sender_id"],
            recipient_id=tc["recipient_id"],
            message_id=tc["message_id"],
            timestamp=timestamp,
            plaintext=tc["plaintext"].encode("utf-8"),
            recipient_rsa_public_key=rsa_key.public_key(),
            sender_signing_key=ed_key,
        )

        python_vectors.append(
            {
                "name": tc["name"],
                "sender_id": tc["sender_id"],
                "recipient_id": tc["recipient_id"],
                "message_id": tc["message_id"],
                "timestamp": timestamp,
                "plaintext_utf8": tc["plaintext"],
                "recipient_rsa": {
                    "n_hex": hex(nums.public_numbers.n)[2:],
                    "e": nums.public_numbers.e,
                    "d_hex": hex(nums.d)[2:],
                    "p_hex": hex(nums.p)[2:],
                    "q_hex": hex(nums.q)[2:],
                },
                "sender_ed25519": {
                    "public_key_hex": ed_pub_bytes.hex(),
                    "private_seed_hex": ed_priv_bytes.hex(),
                },
                "envelope_hex": envelope_bytes.hex(),
            }
        )

    out_file = ROOT_DIR / "docs" / "python_vectors.json"
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump({"vectors": python_vectors}, f, indent=2)

    print(f"Generated {len(python_vectors)} Python vectors in {out_file}")

    # Run Dart verifier
    app_dir = ROOT_DIR / "app"
    print(f"Running Dart verifier using {dart_bin}...")
    proc = subprocess.run(
        [dart_bin, "run", "tool/verify_python_vectors.dart"],
        cwd=str(app_dir),
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        print("Dart verifier stdout:", proc.stdout)
        print("Dart verifier stderr:", proc.stderr)
        raise RuntimeError(f"Dart verifier failed with exit code {proc.returncode}")

    print(proc.stdout.strip())
    print("Direction 2 (Python -> Dart): ALL PASSED.")


def main() -> None:
    print("=== SecureChat Cross-Language Crypto Verification (T12) ===")
    dart_bin = find_dart_binary()
    print(f"Using Dart binary: {dart_bin}")

    run_direction_1_dart_to_python(dart_bin)
    run_direction_2_python_to_dart(dart_bin)

    print("\n[SUCCESS] Bidirectional cross-language crypto checks verified successfully!")
    sys.exit(0)


if __name__ == "__main__":
    main()

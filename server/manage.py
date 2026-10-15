#!/usr/bin/env python3
"""CLI management tool for SecureChat server."""

import argparse
import sys

from app.database import create_invite, init_db


def main() -> int:
    parser = argparse.ArgumentParser(description="SecureChat server management tool")
    subparsers = parser.add_subparsers(dest="command", required=True)

    invite_parser = subparsers.add_parser("create-invite", help="Generate a one-time invite code")
    invite_parser.add_argument(
        "--expires-hours",
        type=int,
        default=24,
        help="Invite expiration in hours (default: 24)",
    )

    args = parser.parse_args()

    if args.command == "create-invite":
        init_db()
        code = create_invite(expires_in_seconds=args.expires_hours * 3600)
        print(code)
        return 0

    return 1


if __name__ == "__main__":
    sys.exit(main())

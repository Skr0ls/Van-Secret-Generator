"""
Secret Generator - Secure generation of critical secrets for production environments
"""

import argparse
import sys

from secret_generator.generators import (
    generate_db_password,
    generate_jwt_hmac,
    generate_random_string,
    generate_rsa_key_pair,
)
from secret_generator.output import format_output, save_to_file


def generate_secrets(args) -> dict[str, dict[str, str]]:
    """Generate secrets based on command-line arguments"""
    secrets_data = {}

    # JWT secrets
    if args.jwt_hmac or args.all:
        secrets_data.setdefault("JWT", {})["HMAC_SECRET"] = generate_jwt_hmac()

    if args.jwt_rsa or args.all:
        private, public = generate_rsa_key_pair()
        secrets_data.setdefault("JWT", {}).update(
            {"RSA_PRIVATE_KEY": private, "RSA_PUBLIC_KEY": public}
        )

    # Database passwords
    if args.db_pass or args.all:
        count = args.db_pass if args.db_pass else 2
        secrets_data["DATABASE"] = {
            f"DB_PASSWORD_{i}": generate_db_password() for i in range(1, count + 1)
        }

    # Application secrets
    if args.app_secrets or args.all:
        secrets_data["APP_SECRETS"] = {
            "SECRET_KEY": generate_random_string(64),
            "API_KEY": generate_random_string(32),
        }

    return secrets_data


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser."""
    parser = argparse.ArgumentParser(
        description="Secure generation of secrets for production environments",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    parser.add_argument("--jwt-hmac", action="store_true", help="Generate a JWT HMAC secret")
    parser.add_argument("--jwt-rsa", action="store_true", help="Generate an RSA key pair for JWT")
    parser.add_argument(
        "--db-pass",
        type=int,
        nargs="?",
        const=2,
        default=None,
        metavar="N",
        help="Generate database passwords (optionally specify the count)",
    )
    parser.add_argument(
        "--app-secrets",
        action="store_true",
        help="Generate application secrets (SECRET_KEY and API_KEY)",
    )
    parser.add_argument("--all", action="store_true", help="Generate all available secrets")
    parser.add_argument("--output", type=str, help="Output file name (BE CAREFUL WITH THIS!)")
    parser.add_argument(
        "--force", action="store_true", help="Allow overwriting an existing output file"
    )

    return parser


def main(argv=None) -> int:
    """Run the CLI and return the process exit code."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.db_pass is not None and args.db_pass < 1:
        parser.error("--db-pass N must be a positive integer (N >= 1)")

    if not any([args.jwt_hmac, args.jwt_rsa, args.db_pass is not None, args.app_secrets, args.all]):
        parser.error("no generation options selected (use --help to list available options)")

    try:
        secrets_data = generate_secrets(args)
        formatted_output = format_output(secrets_data)

        if args.output:
            save_to_file(formatted_output, args.output, force=args.force)
        else:
            print(formatted_output)
    except KeyboardInterrupt:
        print("\nOperation cancelled by user", file=sys.stderr)
        return 130
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())

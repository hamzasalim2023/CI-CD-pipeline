"""Command-line interface for mytool."""

import argparse
import sys

from mytool import __version__
from mytool.commands import secrets as secrets_cmd


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mytool",
        description="CI/CD pipeline security scanner: secrets, vulnerable "
                    "dependencies, and insecure code patterns.",
    )
    parser.add_argument(
        "--version", action="version", version=f"mytool {__version__}"
    )
    subparsers = parser.add_subparsers(dest="command", metavar="COMMAND")
    secrets_cmd.add_parser(subparsers)
    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        parser.print_help()
        return 0
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())

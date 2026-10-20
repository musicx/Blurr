"""Command-line I/O; only authenticated plaintext reaches an output file."""

import argparse
import getpass
import os
from pathlib import Path
import sys
import tempfile

from blurr import BlurrError, __version__, decrypt, encrypt


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="blurr", description="Encrypt text or files into alphanumeric text."
    )
    parser.add_argument("--version", action="version", version=f"Blurr {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)
    for command in ("encrypt", "decrypt"):
        sub = commands.add_parser(command, help=f"{command.capitalize()} text or a file")
        source = sub.add_mutually_exclusive_group(required=True)
        source.add_argument("-t", "--text", help="Literal input text")
        source.add_argument("-i", "--input", type=Path, help="Input file; use - for stdin")
        sub.add_argument("-o", "--output", type=Path, required=True, help="Output file")
        if command == "encrypt":
            sub.add_argument(
                "--encoding", default=None,
                help="Encoding for --text (default: utf-8); file bytes are preserved",
            )
        keys = sub.add_mutually_exclusive_group()
        keys.add_argument("-k", "--key", help="Secret key (may be visible in shell history)")
        keys.add_argument("--key-env", metavar="NAME", help="Read key from an environment variable")
        sub.add_argument("--force", action="store_true", help="Replace an existing output file")
    return parser


def _get_key(args: argparse.Namespace) -> str:
    if args.key is not None:
        key = args.key
    elif args.key_env is not None:
        key = os.environ.get(args.key_env)
        if key is None:
            raise BlurrError("Key environment variable is not set.")
    else:
        if not sys.stdin.isatty():
            raise BlurrError("Non-interactive input requires --key-env or --key.")
        key = getpass.getpass("Key: ")
        if args.command == "encrypt" and key != getpass.getpass("Confirm key: "):
            raise BlurrError("Keys do not match.")
    if not key:
        raise BlurrError("Key must not be empty.")
    return key


def _check_paths(args: argparse.Namespace) -> None:
    output = args.output
    if args.input is not None and args.input != Path("-"):
        source = args.input
        same_path = source.resolve() == output.resolve()
        same_file = output.exists() and source.exists() and source.samefile(output)
        if same_path or same_file:
            raise BlurrError("Input and output must be different files.")
    if os.path.lexists(output) and not args.force:
        raise BlurrError("Output already exists; choose another path or use --force.")
    if output.is_dir():
        raise BlurrError("Output must be a file, not a directory.")


def _read_input(args: argparse.Namespace) -> bytes:
    if args.text is not None:
        encoding = (args.encoding or "utf-8") if args.command == "encrypt" else "ascii"
        return args.text.encode(encoding)
    if args.input == Path("-"):
        return sys.stdin.buffer.read()
    return args.input.read_bytes()


def _write_output(path: Path, data: bytes, force: bool) -> None:
    # Same-directory temporary file: 0600 on POSIX, atomic publication, cleanup on failure.
    descriptor, temporary = tempfile.mkstemp(prefix=".blurr-", dir=path.parent)
    temporary_path = Path(temporary)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        if force:
            os.replace(temporary_path, path)
        else:
            # Linking fails atomically if another process has created the destination.
            os.link(temporary_path, path)
    finally:
        temporary_path.unlink(missing_ok=True)


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    if args.command == "encrypt" and args.encoding is not None and args.text is None:
        parser.error("--encoding applies only to --text; file bytes are preserved")
    try:
        _check_paths(args)
        key = _get_key(args)
        data = _read_input(args)
        if args.command == "encrypt":
            result = encrypt(data, key).encode("ascii")
        else:
            result = decrypt(data.decode("ascii"), key)
        _write_output(args.output, result, args.force)
    except (BlurrError, OSError, UnicodeError, LookupError, OverflowError, EOFError) as exc:
        print(f"blurr: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("blurr: Cancelled.", file=sys.stderr)
        return 130
    return 0

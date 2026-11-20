"""Common command line of the Janus clients (clients/README.md).

    keygen IDENTITY_FILE
    pubkey IDENTITY_FILE
    encrypt OUTPUT INPUT RECIPIENTS [--hidden INPUT RECIPIENTS]...
    decrypt INPUT OUTPUT (--pass PASSWORD | --id IDENTITY_FILE ...)

    RECIPIENTS := --pass PASSWORD | (--to PUBLIC_KEY | --to-file FILE)+
"""

from __future__ import annotations

import os
import secrets
import sys
import tempfile
from pathlib import Path

from . import container, keys
from .container import CannotDecrypt, EncryptionRuleError, Face, Password, SeveralFaces
from .xwing import Identity

USAGE = """\
Janus v1 (Python interoperability client; not audited, not constant-time: not for real secrets)

usage:
  janus.py keygen IDENTITY_FILE        create an identity file; print the public key
  janus.py pubkey IDENTITY_FILE        print the public key of an identity
  janus.py encrypt OUTPUT INPUT RECIPIENTS [--hidden INPUT RECIPIENTS]...
  janus.py decrypt INPUT OUTPUT (--pass PASSWORD | --id IDENTITY_FILE ...)

RECIPIENTS := --pass PASSWORD | (--to PUBLIC_KEY | --to-file FILE)+
"""


class UsageError(Exception):
    pass


def _write_new(path: str, data: bytes) -> None:
    """Write a file that must not exist yet, atomically (temporary file, then rename)."""
    target = Path(path)
    if target.exists():
        raise UsageError(f"{path}: already exists")
    fd, tmp = tempfile.mkstemp(dir=target.parent, prefix=".janus-")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        os.rename(tmp, target)  # fails if target appeared meanwhile, on Windows
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def _keygen(args: list[str]) -> int:
    if len(args) != 1:
        raise UsageError("keygen IDENTITY_FILE")
    identity = Identity(secrets.token_bytes(32))
    _write_new(args[0], keys.identity_file_text(identity).encode("utf-8"))
    print(keys.encode_public_key(identity.public_key))
    return 0


def _pubkey(args: list[str]) -> int:
    if len(args) != 1:
        raise UsageError("pubkey IDENTITY_FILE")
    print(keys.encode_public_key(keys.read_identity_file(args[0]).public_key))
    return 0


def _parse_face(args: list[str], pos: int) -> tuple[Face, int]:
    """Parse INPUT RECIPIENTS starting at args[pos]; return the face and the next position."""
    if pos >= len(args) or args[pos].startswith("--"):
        raise UsageError("missing INPUT")
    plaintext = Path(args[pos]).read_bytes()
    pos += 1
    recipients: list = []
    while pos < len(args) and args[pos] != "--hidden":
        opt = args[pos]
        if pos + 1 >= len(args):
            raise UsageError(f"{opt} needs a value")
        val = args[pos + 1]
        if opt == "--pass":
            recipients.append(Password(val.encode("utf-8")))
        elif opt == "--to":
            recipients.append(keys.decode_public_key(val))
        elif opt == "--to-file":
            recipients.extend(keys.parse_public_keys(Path(val).read_text(encoding="utf-8-sig")))
        else:
            raise UsageError(f"unknown option {opt}")
        pos += 2
    if not recipients:
        raise UsageError("a face needs recipients (--pass, --to or --to-file)")
    return Face(plaintext, recipients), pos


def _encrypt(args: list[str]) -> int:
    if len(args) < 3:
        raise UsageError("encrypt OUTPUT INPUT RECIPIENTS [--hidden INPUT RECIPIENTS]...")
    output = args[0]
    if Path(output).exists():
        raise UsageError(f"{output}: already exists")
    main, pos = _parse_face(args, 1)
    hidden = []
    while pos < len(args):  # args[pos] == "--hidden"
        face, pos = _parse_face(args, pos + 1)
        hidden.append(face)
    _write_new(output, container.encrypt(main, hidden))
    return 0


def _decrypt(args: list[str]) -> int:
    if len(args) < 4:
        raise UsageError("decrypt INPUT OUTPUT (--pass PASSWORD | --id IDENTITY_FILE ...)")
    source, output = args[0], args[1]
    password = None
    identities: list[Identity] = []
    pos = 2
    while pos < len(args):
        opt = args[pos]
        if pos + 1 >= len(args):
            raise UsageError(f"{opt} needs a value")
        if opt == "--pass" and password is None:
            password = args[pos + 1].encode("utf-8")
        elif opt == "--id":
            identities.append(keys.read_identity_file(args[pos + 1]))
        else:
            raise UsageError(f"unexpected option {opt}")
        pos += 2
    if (password is None) == (not identities):
        raise UsageError("give either --pass PASSWORD or one or more --id IDENTITY_FILE")
    if Path(output).exists():
        raise UsageError(f"{output}: already exists")
    plaintext = container.decrypt(Path(source).read_bytes(), password, identities)
    _write_new(output, plaintext)  # decrypted fully in memory: nothing is written on failure
    return 0


COMMANDS = {"keygen": _keygen, "pubkey": _pubkey, "encrypt": _encrypt, "decrypt": _decrypt}


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if not argv or argv[0] in ("-h", "--help", "help") or argv[0] not in COMMANDS:
        sys.stderr.write(USAGE)
        return 0 if argv and argv[0] in ("-h", "--help", "help") else 2
    try:
        return COMMANDS[argv[0]](argv[1:])
    except SeveralFaces as e:
        print(e, file=sys.stderr)
        return 1
    except CannotDecrypt as e:
        print(e, file=sys.stderr)
        return 1
    except UsageError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    except (EncryptionRuleError, keys.KeyFormatError, OSError) as e:
        if argv[0] == "decrypt":
            print(f"cannot decrypt ({e})", file=sys.stderr)
        else:
            print(f"error: {e}", file=sys.stderr)
        return 1 if argv[0] == "decrypt" else 2

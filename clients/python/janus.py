#!/usr/bin/env python3
"""Entry point: python clients/python/janus.py <command> ... (see janus_py/cli.py)."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from janus_py.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())

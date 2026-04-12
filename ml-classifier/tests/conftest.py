"""
conftest.py
===========
Pytest configuration.

When the package is installed in editable mode (`pip install -e '.[dev]'`),
`classifier` is importable via site-packages and the path manipulation below
is a no-op. It is kept as a fallback for editors or CI environments that
invoke pytest without activating the project venv.
"""

import sys
from pathlib import Path

# Fallback: add ml-classifier/src/ to sys.path for uninstalled environments.
_SRC = Path(__file__).parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

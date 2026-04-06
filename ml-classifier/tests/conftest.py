"""
conftest.py
===========
Pytest configuration: ensure src/ is on sys.path so that both sbom_extractor
and the classifier package are importable without installation.
"""

import sys
from pathlib import Path

# Add ml-classifier/src/ to sys.path
_SRC = Path(__file__).parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

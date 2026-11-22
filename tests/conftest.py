import os
import sys
from pathlib import Path

os.environ.setdefault("CYBER_SENTINEL_DB", ":memory:")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

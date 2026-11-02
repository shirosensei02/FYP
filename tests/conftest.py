import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


import pytest


@pytest.fixture(autouse=True)
def isolate_failure_history(tmp_path, monkeypatch):
    # Test fixtures must not create repository history or consume real run history.
    import failure_context
    monkeypatch.setattr(failure_context, 'ROOT', tmp_path / 'failure_context')

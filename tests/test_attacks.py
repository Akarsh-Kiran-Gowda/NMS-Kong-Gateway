"""Every attack must be stopped with the expected response."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "demo"))
import attacks


@pytest.mark.parametrize("name,fn,expected", attacks.ATTACKS, ids=[a[0] for a in attacks.ATTACKS])
def test_attack_blocked(name, fn, expected):
    assert fn() == expected

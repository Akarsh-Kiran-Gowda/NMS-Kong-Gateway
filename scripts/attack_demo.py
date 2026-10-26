"""Run all attack demos and print a table. Usage: .venv/Scripts/python scripts/attack_demo.py"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "demo"))
import attacks

rows = attacks.run_all()
for r in rows:
    print(f"{'BLOCKED' if r['blocked'] else 'NOT BLOCKED':12} {r['name']:52} expected={r['expected']} got={r['got']}")
sys.exit(0 if all(r["blocked"] for r in rows) else 1)

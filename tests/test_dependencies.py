"""The one dependency is declared where tools look for it, with the floor every install instruction names.
Run from the repository root: python3 -B -m unittest discover -s tests -v"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FLOOR = re.compile(r"cryptography>=(\d+(?:\.\d+)*)")
NAMED_IN = ("README.md", ".github/workflows/ci.yml", "agents/model_hive_agent.py")


def requirements() -> list[str]:
    lines = (ROOT / "requirements.txt").read_text(encoding="utf-8").splitlines()
    return [line.split("#", 1)[0].strip() for line in lines if line.split("#", 1)[0].strip()]


class DependencyTests(unittest.TestCase):
    def test_requirements_txt_declares_only_cryptography_with_a_floor(self) -> None:
        declared = requirements()
        self.assertEqual(len(declared), 1, declared)
        self.assertRegex(declared[0], r"^cryptography>=\d+(?:\.\d+)*$")

    def test_every_install_instruction_names_the_same_floor(self) -> None:
        floor = set(FLOOR.findall(requirements()[0]))
        for name in NAMED_IN:
            with self.subTest(file=name):
                self.assertEqual(set(FLOOR.findall((ROOT / name).read_text(encoding="utf-8"))), floor)


if __name__ == "__main__":
    unittest.main()

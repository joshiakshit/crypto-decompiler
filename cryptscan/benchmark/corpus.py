from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path


@dataclass
class Target:
    file: Path
    scope: list[str]
    expected: set[tuple[str, str]]


def load_corpus(corpus_dir: str | Path) -> list[Target]:
    corpus_dir = Path(corpus_dir)
    manifest = json.loads((corpus_dir / "ground_truth.json").read_text())

    targets = []
    for entry in manifest["targets"]:
        scope = entry["scope"]
        expected = {(e["rule_id"], e["class"]) for e in entry["expected"]}
        for rule_id, class_name in expected:
            if not any(class_name.startswith(prefix) for prefix in scope):
                raise ValueError(
                    f"{entry['file']}: expected class {class_name!r} ({rule_id}) "
                    f"does not match any scope prefix {scope}"
                )
        targets.append(
            Target(
                file=(corpus_dir / entry["file"]).resolve(),
                scope=scope,
                expected=expected,
            )
        )
    return targets

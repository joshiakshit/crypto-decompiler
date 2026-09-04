from __future__ import annotations

import csv
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

from ..analyzer import scan
from ..report.json_report import render_json

CSV_FIELDS = ["path", "package", "critical", "high", "medium", "low", "total", "error"]


def _scan_one(args: tuple[str, bool]) -> tuple[dict, str | None]:
    path, want_json = args
    empty = dict.fromkeys(("critical", "high", "medium", "low", "total"), 0)
    try:
        report = scan(path)
    except Exception as exc:
        return {"path": path, "package": "", **empty, "error": str(exc)}, None
    row = {
        "path": path,
        "package": report.target.get("package") or "",
        "critical": report.summary["Critical"],
        "high": report.summary["High"],
        "medium": report.summary["Medium"],
        "low": report.summary["Low"],
        "total": len(report.findings),
        "error": "",
    }
    return row, (render_json(report) if want_json else None)


def scan_dir(
    directory: str | Path,
    csv_path: str | Path | None = None,
    json_dir: str | Path | None = None,
    jobs: int | None = None,
) -> list[dict]:
    apks = sorted(Path(directory).glob("*.apk"))
    if json_dir:
        Path(json_dir).mkdir(parents=True, exist_ok=True)
    args = [(str(p), json_dir is not None) for p in apks]

    rows: list[dict] = []
    with ProcessPoolExecutor(max_workers=jobs) as pool:
        for (path, _), (row, json_text) in zip(args, pool.map(_scan_one, args)):
            rows.append(row)
            if json_dir and json_text:
                (Path(json_dir) / f"{Path(path).stem}.json").write_text(json_text)

    if csv_path:
        with open(csv_path, "w", newline="") as fh:
            writer = csv.DictWriter(fh, fieldnames=CSV_FIELDS)
            writer.writeheader()
            writer.writerows(rows)
    return rows

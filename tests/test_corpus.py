import csv
import shutil
from pathlib import Path

from cryptscan.corpus.batch import scan_dir

FIX = Path(__file__).parent / "fixtures"


def test_scan_dir_writes_csv_and_json(tmp_path):
    for name in ("app_a.apk", "app_b.apk"):
        shutil.copy(FIX / "samples.apk", tmp_path / name)
    csv_path = tmp_path / "summary.csv"
    json_dir = tmp_path / "reports"

    rows = scan_dir(tmp_path, csv_path=csv_path, json_dir=json_dir, jobs=1)

    assert len(rows) == 2
    assert all(r["total"] > 0 and r["error"] == "" for r in rows)
    assert (json_dir / "app_a.json").exists()

    with open(csv_path) as fh:
        parsed = list(csv.DictReader(fh))
    assert len(parsed) == 2
    assert parsed[0]["package"] == "com.cryptscan.samples"

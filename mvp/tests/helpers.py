import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def load_sample(name):
    with (ROOT / "samples" / name).open("r", encoding="utf-8") as handle:
        return json.load(handle)


import os
import json


_base_dir = os.environ["JSON_AD_DIR"]


def write(R, name):
    with open(f"{_base_dir}/{name}.json", "w") as f:
        f.write(json.dumps(R, indent=2, ensure_ascii=False))

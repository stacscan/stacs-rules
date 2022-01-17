"""Generate a new rule pack from enumerated rules."""

import os
import json
import glob

if __name__ == "__main__":
    rules = []

    # Enumerate all rules.
    cwd = os.path.abspath(os.path.expanduser(os.path.dirname(__file__)))

    for rule in glob.glob(f"{cwd}/rules/**/*.yar", recursive=True):
        rules.append({"module": "rules", "path": rule.replace(f"{cwd}/", "")})

    # Generate the rule pack.
    pack = {
        "include": [],
        "pack": rules,
    }

    # Write out the rule pack.
    with open(os.path.join(cwd, "credential.json"), "w") as fout:
        fout.write(json.dumps(pack, sort_keys=True, indent=4))

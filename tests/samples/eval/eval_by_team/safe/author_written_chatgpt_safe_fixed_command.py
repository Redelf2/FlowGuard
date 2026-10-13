# LABEL: SAFE
# PROVENANCE: Author-written; created without opening evaluate.py, rules.py, or existing samples.
# Reason: The configured command sink receives a fixed argument list and no value from input().
import subprocess

subprocess.run(["echo", "ready"], shell=False)

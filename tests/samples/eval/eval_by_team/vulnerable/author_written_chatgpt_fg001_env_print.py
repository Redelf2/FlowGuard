# LABEL: VULNERABLE — FG001
# PROVENANCE: Author-written; created without opening evaluate.py, rules.py, or existing samples.
# Reason: A value from os.getenv is passed through an alias to print.
import os

private_value = os.getenv("PRIVATE_VALUE")
value_alias = private_value
print(value_alias)

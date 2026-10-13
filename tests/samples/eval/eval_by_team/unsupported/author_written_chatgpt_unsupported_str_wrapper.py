# LABEL: UNSUPPORTED
# PROVENANCE: Author-written; created without opening evaluate.py, rules.py, or existing samples.
# Reason: The sensitive value passes through str(), a function-call transformation not supported by the current tracking scope.
import os

secret_value = os.getenv("SECRET_VALUE")
print(str(secret_value))

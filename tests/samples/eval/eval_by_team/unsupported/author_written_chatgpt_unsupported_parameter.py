# LABEL: UNSUPPORTED
# PROVENANCE: Author-written; created without opening evaluate.py, rules.py, or existing samples.
# Reason: The value is passed through a function parameter before reaching print(), and parameter tracking is outside the current scope.
import os

def display_value(value):
    print(value)

secret_value = os.getenv("SECRET_VALUE")
display_value(secret_value)

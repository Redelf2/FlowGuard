# Static analysis sample. Do not run this file.
# Unsupported: the or-expression is not a direct copy of os.getenv. Not scored.
import os

secret = os.getenv("API_KEY") or "missing"
print(secret)

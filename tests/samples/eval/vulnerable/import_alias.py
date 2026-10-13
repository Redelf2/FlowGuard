# Static analysis sample. Do not run this file.
# Expected FG001: from os import getenv makes getenv() the configured source.
from os import getenv

print(getenv("API_KEY"))

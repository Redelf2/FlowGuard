# Static analysis sample. Do not run this file.
# Expected FG001: secret is copied twice before it is printed.
import os

secret = os.getenv("API_KEY")
backup = secret
copy = backup
print(copy)

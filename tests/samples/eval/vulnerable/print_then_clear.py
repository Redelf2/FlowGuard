# Static analysis sample. Do not run this file.
# Expected FG001: print uses the secret before the later literal replaces it.
import os

secret = os.getenv("API_KEY")
print(secret)
secret = "public"

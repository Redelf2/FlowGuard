# Sample for static analysis only. Do not run this file.
# Intended flow for a later rule: os.getenv -> secret -> backup -> print
import os

secret = os.getenv("API_KEY")
backup = secret
print(backup)

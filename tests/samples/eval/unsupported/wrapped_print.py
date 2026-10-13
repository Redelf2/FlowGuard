# Static analysis sample. Do not run this file.
# Unsupported: str(secret) hides the tainted name from print. Not scored.
import os

secret = os.getenv("API_KEY")
print(str(secret))

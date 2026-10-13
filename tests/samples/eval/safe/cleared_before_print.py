# Static analysis sample. Do not run this file.
# No finding: the tainted value is replaced before print.
import os

secret = os.getenv("API_KEY")
secret = "public"
print(secret)

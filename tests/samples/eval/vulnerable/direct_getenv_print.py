# Static analysis sample. Do not run this file.
# Expected FG001: os.getenv is passed straight to print.
import os

print(os.getenv("API_KEY"))

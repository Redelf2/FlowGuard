"""Sensitive value copied into another variable and printed.

This sample is for static analysis only. Do not run it with a real API key.
FG001 should report a potential exposure from os.getenv through backup to print.
"""

import os

secret = os.getenv("API_KEY")
backup = secret
print(backup)

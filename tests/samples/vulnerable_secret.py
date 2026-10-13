"""Sensitive value copied into another variable and printed.

This sample is for static analysis only. Do not run it with a real API key.
A later milestone should report a potential exposure from os.getenv to print.
"""

import os

secret = os.getenv("API_KEY")
backup = secret
print(backup)

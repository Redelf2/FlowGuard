"""A secret is loaded, but the printed value is a different variable.

This file is not labeled safe because it "looks fine". For the planned
rules, print() receives message, and message is the literal "hello".
The getenv result is stored in secret and does not reach print in this file.
Milestone 1 only parses these facts. It does not judge the file.
"""

import os

secret = os.getenv("API_KEY")
message = "hello"
print(message)

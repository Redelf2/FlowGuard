# Static analysis sample. Do not run this file.
# Expected FG001 and FG002 in the same file.
import os
import subprocess

secret = os.getenv("API_KEY")
print(secret)
user_input = input()
subprocess.run(user_input, shell=True)

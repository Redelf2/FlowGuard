# Sample for static analysis only. Do not run this file.
# Intended flow for a later rule: input -> user_input -> subprocess.run
import subprocess

user_input = input("Enter a command: ")
subprocess.run(user_input, shell=True)

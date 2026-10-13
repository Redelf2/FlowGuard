"""Untrusted input passed to a shell command.

This sample is for static analysis only. Do not execute it: if someone
entered a shell command, subprocess.run would run that command.
"""

import subprocess

user_input = input("Enter a command: ")
subprocess.run(user_input, shell=True)

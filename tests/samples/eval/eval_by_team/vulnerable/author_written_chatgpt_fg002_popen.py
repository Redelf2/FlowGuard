# LABEL: VULNERABLE — FG002
# PROVENANCE: Author-written; created without opening evaluate.py, rules.py, or existing samples.
# Reason: input() is assigned to a variable that reaches subprocess.Popen with shell=True.
import subprocess

requested_action = input("Enter a command: ")
action_text = requested_action
subprocess.Popen(action_text, shell=True)

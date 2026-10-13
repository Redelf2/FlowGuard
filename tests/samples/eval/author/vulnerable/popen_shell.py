# Author-written validation sample, not teammate-blind. Do not run this file.
# Label chosen before running FlowGuard: vulnerable FG002.
# input() reaches subprocess.Popen with shell=True.
import subprocess

typed = input("cmd: ")
subprocess.Popen(typed, shell=True)

# Author-written validation sample, not teammate-blind. Do not run this file.
# Label chosen before running FlowGuard: vulnerable FG002.
# input() reaches subprocess.check_output. shell=True is absent.
import subprocess

command = input()
subprocess.check_output(command)

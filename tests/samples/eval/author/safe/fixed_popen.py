# Author-written validation sample, not teammate-blind. Do not run this file.
# Label chosen before running FlowGuard: safe.
# Popen receives a fixed argument list and no input() value.
import subprocess

subprocess.Popen(["python", "--version"], shell=False)

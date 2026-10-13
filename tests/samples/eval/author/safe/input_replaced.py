# Author-written validation sample, not teammate-blind. Do not run this file.
# Label chosen before running FlowGuard: safe.
# input() is replaced by a literal before os.system.
import os

command = input()
command = "hostname"
os.system(command)

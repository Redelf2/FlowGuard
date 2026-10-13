# Static analysis sample. Do not run this file.
# Expected FG002: input() reaches os.system, which passes the string to a shell.
import os

command = input("cmd: ")
os.system(command)

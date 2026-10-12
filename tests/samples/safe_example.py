# Sample for static analysis only. Do not run this file.
# Labeled safe for the planned rules:
# print receives an ordinary string, not a configured secret source.
# subprocess.run receives a fixed argument list and shell=False.
# The parser does not decide safety. Later rule tests will use this file.
import subprocess

status = "ok"
print(status)
subprocess.run(["echo", "hello"], shell=False)

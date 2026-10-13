# Static analysis sample. Do not run this file.
# Expected FG002: input() reaches subprocess.run. shell=True is absent, so
# confidence stays limited. The flow is still a finding.
import subprocess

user_input = input()
subprocess.run(user_input)

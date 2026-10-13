# Static analysis sample. Do not run this file.
# No finding under the current rules: os.getenv is not an FG002 source,
# and subprocess.run is not an FG001 destination.
import os
import subprocess

subprocess.run(os.getenv("API_KEY"), shell=True)

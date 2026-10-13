# Static analysis sample. Do not run this file.
# Unsupported: a star import does not say that getenv means os.getenv. Not scored.
from os import *

print(getenv("API_KEY"))

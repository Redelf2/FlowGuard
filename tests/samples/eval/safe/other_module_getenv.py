# Static analysis sample. Do not run this file.
# No finding: helpers.getenv is not the standard-library os.getenv.
from helpers import getenv

secret = getenv("API_KEY")
print(secret)

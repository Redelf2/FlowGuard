# Static analysis sample. Do not run this file.
# No finding: this getenv is a function in the file, and the import is hidden by it.
from os import getenv


def getenv(name):
    return name


secret = getenv("API_KEY")
print(secret)

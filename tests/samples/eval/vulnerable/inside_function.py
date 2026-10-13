# Static analysis sample. Do not run this file.
# Expected FG001: the source and the print are in one function.
import os


def load():
    secret = os.getenv("API_KEY")
    print(secret)

# Static analysis sample. Do not run this file.
# Unsupported: the argument is not tracked into the parameter secret. Not scored.
import os


def show(secret):
    print(secret)


show(os.getenv("API_KEY"))

# Static analysis sample. Do not run this file.
# No finding: the parameter hides the imported name inside show.
from os import getenv


def show(getenv):
    print(getenv())

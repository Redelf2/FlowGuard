# Author-written validation sample, not teammate-blind. Do not run this file.
# Label chosen before running FlowGuard: unsupported.
# The import is in the outer function and is not applied to the nested function.
def outer():
    from os import getenv

    def inner():
        print(getenv("API_KEY"))

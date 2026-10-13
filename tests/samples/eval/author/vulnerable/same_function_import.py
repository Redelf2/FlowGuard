# Author-written validation sample, not teammate-blind. Do not run this file.
# Label chosen before running FlowGuard: vulnerable FG001.
# from os import getenv is in the same function that prints the value.
def load():
    from os import getenv

    secret = getenv("API_KEY")
    print(secret)

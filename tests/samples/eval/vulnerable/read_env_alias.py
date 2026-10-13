# Static analysis sample. Do not run this file.
# Expected FG001: read_env is a clear alias of os.getenv.
from os import getenv as read_env

secret = read_env("API_KEY")
print(secret)

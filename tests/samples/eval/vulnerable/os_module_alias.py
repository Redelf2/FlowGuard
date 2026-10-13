# Static analysis sample. Do not run this file.
# Expected FG001: os_module.getenv means os.getenv. Other attributes are not rewritten.
import os as os_module

secret = os_module.getenv("API_KEY")
print(secret)

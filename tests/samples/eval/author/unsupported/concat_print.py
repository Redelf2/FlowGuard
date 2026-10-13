# Author-written validation sample, not teammate-blind. Do not run this file.
# Label chosen before running FlowGuard: unsupported.
# print receives secret joined with text, not the bare name.
import os

secret = os.getenv("API_KEY")
print("key=" + secret)

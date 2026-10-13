# Author-written validation sample, not teammate-blind. Do not run this file.
# Label chosen before running FlowGuard: safe.
# logging.info receives a literal. The getenv result is not passed to the log.
import logging
import os

secret = os.getenv("API_KEY")
logging.info("configuration loaded")
print(secret is not None)

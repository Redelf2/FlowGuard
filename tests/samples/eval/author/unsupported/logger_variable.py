# Author-written validation sample, not teammate-blind. Do not run this file.
# Label chosen before running FlowGuard: unsupported.
# logger.warning is not the configured sink name logging.warning.
import logging
import os

secret = os.getenv("API_KEY")
logger = logging.getLogger("app")
logger.warning(secret)

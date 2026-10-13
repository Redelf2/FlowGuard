# Static analysis sample. Do not run this file.
# Unsupported: logger.info is not the configured sink logging.info. Not scored.
import os

secret = os.getenv("API_KEY")
logger.info(secret)

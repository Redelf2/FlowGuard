# Static analysis sample. Do not run this file.
# Expected FG001: os.environ.get reaches logging.info.
import logging
import os

token = os.environ.get("API_KEY")
logging.info(token)

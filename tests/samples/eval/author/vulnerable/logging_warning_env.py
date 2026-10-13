# Author-written validation sample, not teammate-blind. Do not run this file.
# Label chosen before running FlowGuard: vulnerable FG001.
# os.environ.get reaches logging.warning in the same function.
import logging
import os


def report():
    token = os.environ.get("TOKEN")
    logging.warning(token)

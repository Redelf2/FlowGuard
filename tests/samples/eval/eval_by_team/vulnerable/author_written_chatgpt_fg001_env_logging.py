# LABEL: VULNERABLE — FG001
# PROVENANCE: Author-written; created without opening evaluate.py, rules.py, or existing samples.
# Reason: os.environ.get supplies a value that is copied to a variable and passed to logging.warning.
import logging
import os

service_token = os.environ.get("SERVICE_TOKEN")
token_copy = service_token
logging.warning("Service token: %s", token_copy)

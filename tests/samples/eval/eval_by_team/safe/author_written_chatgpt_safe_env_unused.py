# LABEL: SAFE
# PROVENANCE: Author-written; created without opening evaluate.py, rules.py, or existing samples.
# Reason: The environment value is not passed to any configured FG001 sink.
import os

service_token = os.getenv("SERVICE_TOKEN")
print("Service started")

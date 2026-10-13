# Static analysis sample. Do not run this file.
# No finding: print receives a literal. Running this file would create a marker.
from pathlib import Path

Path("flowguard_eval_marker.txt").write_text("executed")
print("ok")

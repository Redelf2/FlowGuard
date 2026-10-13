# Static analysis sample. Do not run this file.
# Unsupported: self.secret is not a simple variable. Not scored.
import os

self.secret = os.getenv("API_KEY")
print(self.secret)

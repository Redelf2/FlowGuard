# Static analysis sample. Do not run this file.
# No finding: load's secret is not show's secret.
import os


def load():
    secret = os.getenv("API_KEY")


def show():
    secret = "public"
    print(secret)

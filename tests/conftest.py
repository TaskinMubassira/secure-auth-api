import os

# Cheap bcrypt cost for fast tests; must be set before the app modules are imported.
os.environ.setdefault("BCRYPT_ROUNDS", "4")

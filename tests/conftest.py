import os

# Disable color/styling for all CLI tests so substring assertions on
# `result.stdout` work regardless of CI terminal capabilities.
os.environ["NO_COLOR"] = "1"
os.environ["TERM"] = "dumb"

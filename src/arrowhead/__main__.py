"""Make python -m arrowhead equivalent to the arrowhead console script."""

import sys

from arrowhead.cli import main

if __name__ == "__main__":
    sys.exit(main())

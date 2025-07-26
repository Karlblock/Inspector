#!/bin/bash
# Wrapper script for cyba-inspector to handle path issues

# Get the directory where the actual script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Change to script directory and execute
cd "$SCRIPT_DIR"
exec python3 cyba-inspector.py "$@"
#!/bin/sh
# Synthetic-only launcher. Never used by the production Dockerfile.
set -eu
exec python3 -B /opt/wrapper/tests/mock_worker.py "$@"

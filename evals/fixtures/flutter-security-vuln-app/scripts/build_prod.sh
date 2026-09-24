#!/usr/bin/env bash
# Prod release build script (fixture — fake values only).
set -euo pipefail

flutter build apk --release \
  --dart-define=API_KEY=AKIAIOSFODNN7EXAMPLE \
  --dart-define=AMPLITUDE_KEY=amplitude-fake-000111 \
  --split-per-abi

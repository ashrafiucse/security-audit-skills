#!/usr/bin/env bash
# Production deploy — FAKE fixture data only.
set -euo pipefail

php artisan migrate --force
php artisan config:cache
php artisan queue:restart
# stored feature values are never cleared (absence is the finding)

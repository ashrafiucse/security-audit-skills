#!/usr/bin/env bash
# Production deploy (safe shape) — FAKE fixture data only.
set -euo pipefail

php artisan migrate --force
php artisan config:cache
php artisan queue:restart
php artisan pennant:purge

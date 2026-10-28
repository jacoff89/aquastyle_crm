#!/usr/bin/env bash
# Деплой прода: ./deploy.sh [ветка]  (по умолчанию main)
set -euo pipefail

cd "$(dirname "$0")"
BRANCH="${1:-main}"
DC="docker compose -f docker-compose.prod.yml"
ARTISAN="$DC exec -T php-fpm php artisan"

echo "→ Maintenance mode"
$ARTISAN down --retry=15 || true
trap '$ARTISAN up || true' EXIT   # поднимем сайт даже если что-то упало

echo "→ git pull ($BRANCH)"
git fetch origin "$BRANCH"
git checkout "$BRANCH"
git pull --ff-only origin "$BRANCH"

echo "→ composer install"
$DC exec -T php-fpm composer install --no-dev --optimize-autoloader --no-interaction

echo "→ build frontend"
$DC run --rm nodejs

echo "→ remove node_modules"
rm -rf node_modules

echo "→ migrate"
$ARTISAN migrate --force

echo "→ caches"
$ARTISAN optimize

echo "→ restart php-fpm (сброс OPcache)"
$DC restart php-fpm

echo "✓ Deployed: $(git log -1 --oneline)"
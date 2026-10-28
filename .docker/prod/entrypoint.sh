#!/bin/sh
set -e
[ -f .env ] || { echo ".env не смонтирован в /var/www/html/.env" >&2; exit 1; }

mkdir -p storage/app/public storage/app/private storage/framework/cache/data \
         storage/framework/sessions storage/framework/views storage/logs

# storage смонтирован с хоста: приводим владельца к ubuntu (только то, что отличается — быстро)
find storage bootstrap/cache \! -user ubuntu -exec chown ubuntu:ubuntu {} +

runuser -u ubuntu -- php artisan optimize --no-interaction

# основной процесс (supervisord) работает от root, всё остальное (artisan migrate и т.п.) — от ubuntu
if [ "$1" = "supervisord" ]; then
    exec "$@"
fi
exec runuser -u ubuntu -- "$@"

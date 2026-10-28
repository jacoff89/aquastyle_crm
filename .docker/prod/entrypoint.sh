#!/bin/sh
set -e
[ -f .env ] || { echo ".env не смонтирован в /var/www/html/.env" >&2; exit 1; }

# Подгоняем UID/GID пользователя ubuntu в контейнере под владельца на хосте.
# Берём из PUID/PGID (их передаёт deploy.sh), иначе — 1000 по умолчанию
PUID="${PUID:-1000}"
PGID="${PGID:-1000}"
[ "$PUID" != 0 ] || { echo "PUID=0 (root) не поддерживается" >&2; exit 1; }
if [ "$(id -u ubuntu)" != "$PUID" ] || [ "$(id -g ubuntu)" != "$PGID" ]; then
    groupmod -o -g "$PGID" ubuntu
    usermod -o -u "$PUID" -g "$PGID" ubuntu
    chown ubuntu:ubuntu /run/php /run/php-fpm.pid
fi

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

# syntax=docker/dockerfile:1

# ---------- база: PHP-FPM + nginx + supervisor ----------
FROM phpdockerio/php:8.5-fpm AS php-base
WORKDIR /var/www/html
ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get -y --no-install-recommends install php-zip unzip php8.5-mysql php8.5-sqlite3 php8.5-bcmath php8.5-intl php8.5-xml php8.5-gd \
        nginx supervisor \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* /usr/share/doc/* \
    && rm -f /etc/nginx/sites-enabled/default /etc/nginx/conf.d/default.conf \
    && ln -sf /dev/stdout /var/log/nginx/access.log \
    && ln -sf /dev/stderr /var/log/nginx/error.log

COPY --from=composer:2 /usr/bin/composer /usr/local/bin/composer

RUN mkdir -p /run/php \
    && touch /run/php-fpm.pid \
    && chown -R ubuntu:ubuntu /run/php /run/php-fpm.pid

# ---------- composer + код ----------
FROM php-base AS vendor
COPY composer.json composer.lock ./
RUN composer install --no-dev --no-scripts --no-autoloader --prefer-dist --no-interaction
COPY . .
RUN composer dump-autoload --no-dev --optimize --no-interaction

# ---------- сборка фронтенда ----------
FROM node:24 AS assets
# чтобы node (fetch) тоже ходил через прокси, если он задан
ENV NODE_USE_ENV_PROXY=1
WORKDIR /app
COPY package.json package-lock.json .npmrc ./
RUN npm ci
COPY . .
RUN npm run build

# ---------- итоговый образ: nginx + php-fpm ----------
FROM vendor AS app
COPY --from=assets /app/public ./public
RUN chmod -R a+rX public

COPY .docker/php-fpm/php-prod.ini /etc/php/8.5/fpm/conf.d/99-prod.ini
COPY .docker/prod/php-fpm-pool.conf /etc/php/8.5/fpm/pool.d/zz-prod-user.conf
COPY .docker/prod/nginx-site.conf /etc/nginx/conf.d/default.conf
COPY .docker/prod/supervisord.conf /etc/supervisord.conf
COPY --chmod=755 .docker/prod/entrypoint.sh /usr/local/bin/entrypoint.sh

RUN mkdir -p storage/app/public storage/app/private storage/framework/cache/data \
        storage/framework/sessions storage/framework/views storage/logs bootstrap/cache \
    && chown -R ubuntu:ubuntu storage bootstrap/cache

EXPOSE 80
# запускается от root: supervisord держит nginx (root, воркеры www-data)
# и php-fpm (от ubuntu). Artisan-команды entrypoint выполняет от ubuntu.
ENTRYPOINT ["entrypoint.sh"]
CMD ["supervisord", "-c", "/etc/supervisord.conf"]

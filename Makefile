.PHONY: pull up build down dev composer-install npm-install npm-build migrate create-admin test pint setup deploy-dev deploy-prod

compose-env = env UID=$$(id -u) GID=$$(id -g) docker compose

pull:
	$(compose-env) pull

up:
	$(compose-env) up -d --wait
	@if test -f vendor/autoload.php && ! grep -q '^APP_KEY=[^[:space:]]' .env 2>/dev/null; then \
		$(compose-env) exec -T php-fpm php artisan key:generate --force; \
	fi

composer-install:
	$(compose-env) exec -T php-fpm composer install --no-interaction

npm-install:
	$(compose-env) exec -T nodejs npm install

npm-build:
	$(compose-env) exec -T nodejs npm run build

migrate:
	$(compose-env) exec -T php-fpm php artisan migrate --force

create-admin:
	$(compose-env) exec php-fpm php artisan app:create-admin

test:
	$(compose-env) exec -T php-fpm php artisan test --compact

pint:
	$(compose-env) exec -T php-fpm vendor/bin/pint

setup: pull build up composer-install npm-install
	@if ! grep -q '^APP_KEY=[^[:space:]]' .env 2>/dev/null; then \
		$(compose-env) exec -T php-fpm php artisan key:generate --force; \
	fi
	$(compose-env) exec -T php-fpm php artisan migrate --force

build:
	$(compose-env) build

down:
	$(compose-env) down

dev: up
	$(compose-env) exec nodejs npm run dev

# Деплой: сборка образа и push в registry, затем pull и перезапуск на сервере по SSH.
# Откат на уже собранный образ: make deploy-prod TAG=<тег>
deploy-dev:
	./deploy.sh dev $(TAG)

deploy-prod:
	./deploy.sh prod $(TAG)

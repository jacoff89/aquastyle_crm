.PHONY: pull up build down dev composer-install npm-install npm-build migrate create-admin test pint boost-update setup deploy-dev deploy-prod queue-logs queue-failed queue-retry

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

# Обновить гайдлайны (CLAUDE.md, AGENTS.md) и скиллы (.claude/skills, .agents/skills) Laravel Boost. Переменные BOOST_*_EXECUTABLE_PATH
# заставляют Boost писать в инструкциях для ИИ команды через Docker, а не для хоста.
# В .env их класть нельзя: MCP-инструменты Boost внутри контейнера тоже берут
# путь к php из BOOST_PHP_EXECUTABLE_PATH и перестанут работать.
boost-update:
	$(compose-env) exec -T \
		-e BOOST_PHP_EXECUTABLE_PATH="docker compose exec -T php-fpm php" \
		-e BOOST_COMPOSER_EXECUTABLE_PATH="docker compose exec -T php-fpm composer" \
		-e BOOST_VENDOR_BIN_EXECUTABLE_PATH="docker compose exec -T php-fpm vendor/bin/" \
		-e BOOST_NPM_EXECUTABLE_PATH="docker compose exec -T nodejs npm" \
		php-fpm php artisan boost:update --no-interaction

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
# Ветка для dev: make deploy-dev BRANCH=<ветка> (по умолчанию dev)
# Откат на уже собранный образ: make deploy-prod TAG=<тег>
deploy-dev:
	./deploy.sh dev $(if $(TAG),--tag $(TAG),$(BRANCH))

deploy-prod:
	./deploy.sh prod $(if $(TAG),--tag $(TAG))

queue-logs:
	$(compose-env) logs -f queue

queue-failed:
	$(compose-env) exec -T php-fpm php artisan queue:failed

queue-retry:
	$(compose-env) exec -T php-fpm php artisan queue:retry all
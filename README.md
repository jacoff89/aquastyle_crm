# Аквастиль CRM

Laravel 13 + Inertia 3 + Vue 3 + Tailwind CSS 4 в Docker. CRM дайвинг-центра: календарь, клиенты, инструкторы.

## Требования

- Docker
- Docker Compose
- GNU Make

## Настройка окружения

Создайте файл `.env` на основе `.env.example`:

```bash
cp .env.example .env
```

Что стоит проверить в `.env`:

- `NGINX_PORT` — порт, на котором приложение будет доступно на хосте;
- `MYSQL_PORT` — порт MySQL на хосте;
- `VITE_PORT` — порт Vite dev-сервера (HMR);
- `DB_DATABASE`, `DB_USERNAME`, `DB_PASSWORD` — параметры базы данных;
- `HTTP_PROXY` — прокси для Composer и npm. В `.env.example` указан пример-заглушка: укажите свой прокси или оставьте значение пустым.

`UID` и `GID` в `.env` задавать не нужно: Makefile сам передаёт в Docker значения текущего пользователя. При запуске `docker compose` напрямую без `make` используются значения по умолчанию `1000:1000`.

## Быстрый запуск

Полная первоначальная настройка проекта:

```bash
make setup
```

Команда:

1. загружает свежие Docker-образы;
2. собирает Docker-контейнеры;
3. запускает контейнеры;
4. устанавливает Composer-зависимости;
5. устанавливает npm-зависимости;
6. генерирует `APP_KEY`, если он отсутствует;
7. выполняет миграции базы данных.

После запуска приложение доступно по адресу из `NGINX_PORT` в `.env`, например:

```text
http://localhost:3336
```

Создайте администратора:

```bash
make create-admin
```

Пароль вводится интерактивно.

## Команды Make

```bash
make pull
```

Загрузить свежие версии Docker-образов.

```bash
make build
```

Собрать Docker-образы с UID и GID текущего пользователя.

```bash
make up
```

Запустить контейнеры и сгенерировать `APP_KEY`, если он пустой.

```bash
make down
```

Остановить контейнеры.

```bash
make composer-install
```

Установить PHP-зависимости через Composer.

```bash
make npm-install
```

Установить JavaScript-зависимости через npm.

```bash
make npm-build
```

Собрать фронтенд для production (`npm run build`).

```bash
make migrate
```

Запустить миграции базы данных.

```bash
make create-admin
```

Создать администратора (`php artisan app:create-admin`).

```bash
make test
```

Запустить тесты. Они используют SQLite в памяти и не затрагивают основную базу.

```bash
make pint
```

Привести PHP-код к стилю проекта через Laravel Pint.

```bash
make dev
```

Запустить Vite в dev-режиме с HMR.

## Разработка

Для работы с фронтендом запустите:

```bash
make dev
```

Vite слушает порт `VITE_PORT` (по умолчанию `5173`), изменения во Vue-компонентах и стилях подхватываются без перезагрузки страницы. Приложение при этом открывается по адресу `NGINX_PORT`.

Если страница не показывает фронтенд-изменения или возникает ошибка `Unable to locate file in Vite manifest`, запустите `make dev` или `make npm-build`.

Artisan и Composer можно запускать напрямую внутри контейнера:

```bash
docker compose exec php-fpm php artisan route:list
docker compose exec php-fpm composer require <пакет>
```

## Деплой

Деплой выполняется скриптом `deploy.sh`. Он собирает production-образ (`.docker/prod/Dockerfile`: nginx + php-fpm в одном образе), отправляет его в Container Registry, затем по SSH скачивает образ на сервере, применяет миграции и перезапускает контейнер. После перезапуска проверяется эндпоинт `/up`; если он не отвечает, происходит автоматический откат на предыдущий тег.

```bash
make deploy-dev
```

Собрать и выкатить текущий коммит на dev-сервер. Требуется ветка `dev`.

```bash
make deploy-prod
```

Собрать и выкатить текущий коммит на prod-сервер. Требуется ветка `main` и чистое рабочее дерево.

Откат или повторная выкатка уже собранного образа без сборки:

```bash
make deploy-prod TAG=<тег>
```

Тег образа — короткий хеш коммита (10 символов).

Параметры серверов (адрес, SSH-порт, каталог, репозиторий образов, ветка) задаются в `deploy.sh` и могут быть переопределены переменными окружения: `PROD_HOST`, `PROD_SSH_PORT`, `PROD_DIR`, `PROD_REPO`, `DEPLOY_BRANCH` и аналогичными `DEV_*`.

На сервере рядом с `docker-compose.prod.yml` должен лежать `.env` с production-настройками (включая `NGINX_PORT`). Каталог `storage` монтируется с хоста, туда же пишутся логи и загруженные файлы.

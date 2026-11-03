# Аквастиль CRM

Laravel Boost is already installed in this project. The full guidelines for AI agents are in `CLAUDE.md`: read it before working on the user's request.

## Docker

PHP, Composer, Node and the database run only inside Docker containers. Do not install PHP on the host and do not run `php`, `composer`, `npm` or `vendor/bin/*` there.

- PHP commands: `docker compose exec -T php-fpm php artisan route:list`, `docker compose exec -T php-fpm vendor/bin/pint --dirty --format agent`.
- Node commands: `docker compose exec -T nodejs npm run build`.
- Prefer `Makefile` targets when one fits (`make migrate`, `make test`). `make pint` formats the whole project: run it only when the user asks, and after your own changes use `pint --dirty` as above.
- If a container is not running, ask the user to run `make up`.

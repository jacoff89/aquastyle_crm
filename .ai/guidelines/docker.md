# Docker

- PHP, Composer, Node and the database run only inside Docker containers. Do not run `php`, `composer`, `npm` or `vendor/bin/*` on the host: the host is not expected to have them, and the `db` host from `.env` only resolves inside the Docker network.
- Run every PHP command in the `php-fpm` container with `docker compose exec -T php-fpm ...`. This applies to every command in these guidelines and in the skills, even where it is written bare:
  - `php artisan route:list` → `docker compose exec -T php-fpm php artisan route:list`
  - `php artisan make:model Foo --no-interaction` → `docker compose exec -T php-fpm php artisan make:model Foo --no-interaction`
  - `php artisan test --compact --filter=testName` → `docker compose exec -T php-fpm php artisan test --compact --filter=testName`
  - `vendor/bin/pint --dirty --format agent` → `docker compose exec -T php-fpm vendor/bin/pint --dirty --format agent`
  - `php artisan tinker --execute '...'` → `docker compose exec -T php-fpm php artisan tinker --execute '...'`
  - `composer show --direct` → `docker compose exec -T php-fpm composer show --direct`
- Run Node commands in the `nodejs` container: `docker compose exec -T nodejs npm run build`. For the Vite dev server ask the user to run `make dev`.
- Prefer a `Makefile` target when one does exactly what is needed (`make migrate`, `make test`, `make pint`, `make npm-build`).
- If a command fails because a container is not running, ask the user to run `make up` instead of falling back to the host.

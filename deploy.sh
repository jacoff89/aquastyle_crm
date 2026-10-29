#!/usr/bin/env bash
# Деплой: сборка образа здесь → push в Container Registry → pull и перезапуск на сервере по SSH.
#   ./deploy.sh dev [ветка]         собрать и выкатить указанную ветку (по умолчанию dev)
#   ./deploy.sh prod                собрать и выкатить ветку main
#   ./deploy.sh <prod|dev> --tag <тег>   выкатить уже собранный тег без сборки (откат)
# Собирается коммит ветки (git archive), рабочая копия и текущая ветка не важны.
set -euo pipefail
cd "$(dirname "$0")"

ENV_NAME="${1:-}"
case "$ENV_NAME" in
  prod)
    REPO="${PROD_REPO:-registry.yakov89.ru/aquastyle/crm-images/prod}"
    SSH_HOST="${PROD_HOST:-aquastyle@89.169.0.212}"
    SSH_PORT="${PROD_SSH_PORT:-22}"
    REMOTE_DIR="${PROD_DIR:-/home/aquastyle/aquastyle_crm}"
    DEFAULT_BRANCH="main"
    ALLOW_ANY_BRANCH=0
    ;;
  dev)
    REPO="${DEV_REPO:-registry.yakov89.ru/aquastyle/crm-images/dev}"
    SSH_HOST="${DEV_HOST:-aquastyle@83.142.160.165}"
    SSH_PORT="${DEV_SSH_PORT:-2622}"
    REMOTE_DIR="${DEV_DIR:-/home/aquastyle/aquastyle_crm}"
    DEFAULT_BRANCH="dev"
    ALLOW_ANY_BRANCH=1
    ;;
  *)
    echo "Использование: ./deploy.sh <prod|dev> [ветка] | ./deploy.sh <prod|dev> --tag <тег>" >&2
    exit 1
    ;;
esac

TAG=""
BRANCH=""
if [ "${2:-}" = "--tag" ]; then
  TAG="${3:-}"
  [ -n "$TAG" ] || { echo "✗ Не указан тег" >&2; exit 1; }
else
  BRANCH="${2:-$DEFAULT_BRANCH}"
  if [ "$ALLOW_ANY_BRANCH" = 0 ] && [ "$BRANCH" != "$DEFAULT_BRANCH" ]; then
    echo "✗ На $ENV_NAME выкатывается только ветка $DEFAULT_BRANCH" >&2
    exit 1
  fi
fi

if [ -z "$TAG" ]; then
  if git rev-parse -q --verify "refs/heads/$BRANCH" >/dev/null; then
    REF="$BRANCH"
  else
    git fetch -q origin "$BRANCH" 2>/dev/null || true
    if git rev-parse -q --verify "refs/remotes/origin/$BRANCH" >/dev/null; then
      REF="origin/$BRANCH"
    else
      echo "✗ Ветка $BRANCH не найдена" >&2
      exit 1
    fi
  fi
  TAG="$(git rev-parse --short=10 "$REF")"

  BUILD_ARGS=()
  PROXY="${HTTP_PROXY:-$(grep -E '^HTTP_PROXY=' .env 2>/dev/null | cut -d= -f2- | tr -d "'\"" || true)}"
  if [ -n "$PROXY" ]; then
    BUILD_ARGS+=(--build-arg "HTTP_PROXY=$PROXY" --build-arg "HTTPS_PROXY=$PROXY")
  fi

  echo "→ build ($BRANCH @ $TAG)"
  git archive "$REF" | docker build --provenance=false --sbom=false -f .docker/prod/Dockerfile "${BUILD_ARGS[@]}" -t "$REPO:$TAG" -

  echo "→ push"
  docker push "$REPO:$TAG"
fi

echo "→ деплой $TAG на $ENV_NAME ($SSH_HOST, порт $SSH_PORT)"
ssh -p "$SSH_PORT" "$SSH_HOST" "mkdir -p '$REMOTE_DIR/storage'"
scp -q -P "$SSH_PORT" docker-compose.prod.yml "$SSH_HOST:$REMOTE_DIR/docker-compose.prod.yml"

ssh -p "$SSH_PORT" "$SSH_HOST" bash -s -- "$REMOTE_DIR" "$REPO" "$TAG" <<'REMOTE'
set -euo pipefail
cd "$1"
export DOCKER_REPO="$2" IMAGE_TAG="$3"

# пользователь в контейнере = пользователь хоста, под которым идёт деплой
export HOST_UID="$(id -u)" HOST_GID="$(id -g)"

DC="docker compose -f docker-compose.prod.yml"
PREV="$(cat .current_tag 2>/dev/null || true)"

$DC pull
# миграции новым образом, пока старый контейнер ещё обслуживает сайт
$DC run --rm --no-deps -T app php artisan migrate --force </dev/null
$DC up -d --remove-orphans

PORT="$(grep -E '^NGINX_PORT=' .env | cut -d= -f2)"
for _ in $(seq 1 30); do
  if curl -fsS -o /dev/null "http://127.0.0.1:${PORT}/up"; then
    echo "$IMAGE_TAG" > .current_tag
    # оставляем 3 свежих образа, остальные удаляем
    docker image ls "$DOCKER_REPO" -q | awk '!s[$0]++' | tail -n +4 | xargs -r docker rmi >/dev/null 2>&1 || true
    echo "✓ Выкачено: $IMAGE_TAG"
    exit 0
  fi
  sleep 2
done

echo "✗ /up не отвечает" >&2
$DC logs --tail=50 app >&2 || true
if [ -n "$PREV" ]; then
  echo "→ откат на $PREV" >&2
  IMAGE_TAG="$PREV" $DC up -d
fi
exit 1
REMOTE

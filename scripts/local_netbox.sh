#!/usr/bin/env bash
# Локальный NetBox в Docker для проверки RSM (только localhost, тестовые учётки).
#   scripts/local_netbox.sh up       клонировать netbox-docker, сгенерировать учётки, запустить и дождаться healthy
#   scripts/local_netbox.sh down     остановить (данные остаются в docker volumes)
#   scripts/local_netbox.sh destroy  остановить и удалить данные
#   source local/netbox.env          NETBOX_URL / NETBOX_TOKEN для rsm; там же логин/пароль UI
set -euo pipefail
cd "$(dirname "$0")/.."
DIR=local/netbox-docker
PROJECT=rsm-netbox

case "${1:-up}" in
  up)
    [ -d "$DIR" ] || git clone -q -b release --depth 1 https://github.com/netbox-community/netbox-docker.git "$DIR"
    if [ ! -f "$DIR/docker-compose.override.yml" ]; then
      python3 - <<'EOF'
import secrets, string
alnum = string.ascii_letters + string.digits
key = "".join(secrets.choice(alnum) for _ in range(12))   # NetBox ≥ 4.5: токен v2 = nbt_<key>.<token>
tok = "".join(secrets.choice(alnum) for _ in range(40))
pw = secrets.token_urlsafe(18)
open("local/netbox-docker/docker-compose.override.yml", "w").write(f"""# Локальный NetBox для проверки RSM (тестовые учётные данные — только для localhost)
services:
  netbox:
    ports:
      - "8000:8080"
    healthcheck:
      start_period: 300s
    environment:
      SKIP_SUPERUSER: "false"
      SUPERUSER_NAME: "admin"
      SUPERUSER_EMAIL: "admin@example.com"
      SUPERUSER_PASSWORD: "{pw}"
      SUPERUSER_API_KEY: "{key}"
      SUPERUSER_API_TOKEN: "{tok}"
""")
open("local/netbox.env", "w").write(f"""# Тестовый локальный NetBox (docker, localhost:8000). Не использовать вне локальной проверки.
# source local/netbox.env
export NETBOX_URL=http://localhost:8000
export NETBOX_TOKEN=nbt_{key}.{tok}
# UI: http://localhost:8000  логин admin, пароль: {pw}
""")
EOF
      chmod 600 local/netbox.env "$DIR/docker-compose.override.yml"
    fi
    (cd "$DIR" && docker compose -p "$PROJECT" up -d --wait)
    echo "NetBox: http://localhost:8000 — учётки в local/netbox.env (source local/netbox.env)"
    ;;
  down)
    (cd "$DIR" && docker compose -p "$PROJECT" down)
    ;;
  destroy)
    (cd "$DIR" && docker compose -p "$PROJECT" down -v)
    ;;
  *)
    echo "usage: $0 up|down|destroy" >&2
    exit 2
    ;;
esac

#!/usr/bin/env bash
# Local review demo: MySQL in Docker, the app on http://localhost:5210/this_platform
# with the developer sign-in page instead of Entra ID. Never use these settings on a server.
#
#   demo/run.sh            start (first run: migrate, init keys, seed demo data)
#   demo/run.sh --fresh    first run without demo data: you claim admin with the setup token
#   demo/run.sh code       current authenticator code for the demo users (add --watch)
#   demo/run.sh qr         QR code to add the demo key to your phone's authenticator
#   demo/run.sh stop       stop MySQL (data is kept)
#   demo/run.sh reset      delete the demo database and keys
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
STATE="$ROOT/.demo"
APP="$ROOT/src/SatuVault"
DEMO="$ROOT/demo/SatuVault.Demo"
PORT="${SATU_DEMO_PORT:-5210}"
export SATU_DEMO_DB_PORT="${SATU_DEMO_DB_PORT:-53307}"

export ASPNETCORE_ENVIRONMENT=Development
export ConnectionStrings__App="Server=127.0.0.1;Port=$SATU_DEMO_DB_PORT;Database=satuvault_demo;User ID=satuvault_app;Password=demo-app-pass;SslMode=Preferred"
export ConnectionStrings__Admin="Server=127.0.0.1;Port=$SATU_DEMO_DB_PORT;Database=satuvault_demo;User ID=root;Password=demo-root;SslMode=Preferred"
export SatuVault__KeyDirectory="$STATE/keys"
export SatuVault__PathBase=/this_platform
export SatuVault__DevLogin=true
export SATU_BACKUP_PASSPHRASE=demo-backup-passphrase

compose() { docker compose -f "$ROOT/demo/docker-compose.yml" -p satuvault-demo "$@"; }
demo_tool() { dotnet run --project "$DEMO" --no-launch-profile -v q -- "$@"; }
# The app reads appsettings*.json from its content root, so run it from its folder.
app() { (cd "$APP" && dotnet run --no-build --no-launch-profile -- "$@"); }

case "${1:-up}" in
  code) demo_tool code "${@:2}"; exit ;;
  qr) demo_tool qr; exit ;;
  stop) compose stop; exit ;;
  reset)
    compose down -v
    rm -rf "$STATE"
    echo "Demo database and keys deleted."
    exit ;;
  up|--fresh) ;;
  *) sed -n '2,10p' "$0"; exit 2 ;;
esac

command -v docker >/dev/null || { echo "Docker is required"; exit 1; }
command -v dotnet >/dev/null || { echo "The .NET 10 SDK is required"; exit 1; }

echo "==> Starting MySQL (127.0.0.1:$SATU_DEMO_DB_PORT)"
compose up -d --wait

echo "==> Building"
dotnet build "$ROOT/SatuVault.slnx" -v q -nologo -clp:ErrorsOnly

mkdir -p "$STATE"
if [[ ! -f "$STATE/keys/master.key" ]]; then
  echo "==> First run: schema, keys"
  app migrate --app-user satuvault_app
  app init --protection none --backup "$STATE/keys/master-key-backup.json" > "$STATE/init.txt"
  if [[ "${1:-}" == "--fresh" ]]; then
    TOKEN="$(awk 'f && NF {print $1; exit} /One-time setup token/ {f=1}' "$STATE/init.txt")"
    echo "$TOKEN" > "$STATE/setup-token.txt"
  else
    echo "==> Seeding demo data"
    demo_tool seed
  fi
fi

cat <<EOF

  SatuVault demo   http://localhost:$PORT/this_platform

  Sign in on the developer page with any email. Seeded accounts (already enrolled):
    alice@demo.local   admin, manager of Finance
    bob@demo.local     manager of Infrastructure
    citra@demo.local   manager of Marketing
    dewi@demo.local    member of Marketing
    eko@demo.local     no team, not enrolled yet (try the authenticator setup)

  Authenticator codes for the seeded accounts:  demo/run.sh code --watch
  (or scan demo/run.sh qr into your phone). Each code works once per user,
  so a second reveal needs the next code.
EOF
if [[ -f "$STATE/setup-token.txt" ]]; then
  echo "  Fresh install: sign in, enroll, then open /this_platform/Setup with token $(cat "$STATE/setup-token.txt")"
fi
echo "  Ctrl+C stops the app; demo/run.sh reset deletes everything."
echo

export ASPNETCORE_URLS="http://localhost:$PORT"
app

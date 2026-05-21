#!/usr/bin/env bash
#
# Back up the rproxy rules database. The DB is a single SQLite file; this uses
# the SQLite online-backup API so it is safe to run while rproxy-ui is live.
#
#   sudo ./scripts/backup-db.sh [destination-dir]
#
# Default destination: /var/lib/rproxy/backups
#
set -euo pipefail

DB_PATH="${DB_PATH:-/var/lib/rproxy/rules.db}"
DEST="${1:-/var/lib/rproxy/backups}"

if [[ ! -f "$DB_PATH" ]]; then
  echo "No database at $DB_PATH — nothing to back up." >&2
  exit 1
fi

mkdir -p "$DEST"
STAMP="$(date +%Y%m%d-%H%M%S)"
OUT="$DEST/rules-$STAMP.db"

# .backup is atomic and consistent even with concurrent writers.
sqlite3 "$DB_PATH" ".backup '$OUT'"
echo "Backup written: $OUT ($(du -h "$OUT" | cut -f1))"

# Keep the 14 most recent backups.
ls -1t "$DEST"/rules-*.db 2>/dev/null | tail -n +15 | xargs -r rm --
echo "Retained backups: $(ls -1 "$DEST"/rules-*.db 2>/dev/null | wc -l)"
